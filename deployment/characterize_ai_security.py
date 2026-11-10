"""Plan or explicitly run AI-path production-profile characterization.

Default execution is plan-only and performs no Docker work. ``--run`` is
required to create the uniquely named disposable Compose project.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time


os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deployment"))
sys.path.insert(0, str(ROOT / "tools"))

from enkstein_guard.productconfig import validate  # noqa: E402
from production_harness import (  # noqa: E402
    AgentRun, Deployment as ProductionDeployment, IMAGE, NETWORKS,
    capacity_config, percentile, write_report,
)


REPORT_NAME = "ai-security-characterization.json"
PROJECT_PREFIX = "egai"
_REPORT = re.compile(r"[A-Za-z0-9_.-]{1,128}")
UPSTREAM_STATS = "/capture/ai-security-characterization-stats.json"
UPSTREAM_SCHEMA = "enkstein-ai-security-characterization-upstream-v1"
UPSTREAM_KINDS = ("inspection", "business", "unknown")
UPSTREAM_MODELS = ("synthetic-security", "synthetic-model", "unknown")
_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class CharacterizationParameters:
    actors: int = 2
    per_actor_history: int = 16
    duration_seconds: float = 10
    rate_per_actor: float = 2
    max_inflight: int = 4

    def __post_init__(self):
        if (type(self.actors) is not int or not 2 <= self.actors <= 64 or self.actors % 2
                or type(self.per_actor_history) is not int
                or not 16 <= self.per_actor_history <= 256
                or type(self.duration_seconds) not in (int, float)
                or not math.isfinite(self.duration_seconds)
                or not 1 <= self.duration_seconds <= 600
                or type(self.rate_per_actor) not in (int, float)
                or not math.isfinite(self.rate_per_actor)
                or not 0.1 <= self.rate_per_actor <= 3
                or math.floor(self.duration_seconds * self.rate_per_actor) < 1
                or type(self.max_inflight) is not int
                or not 1 <= self.max_inflight <= 16
                or self.history_capacity > 100_000):
            raise ValueError("invalid_ai_characterization_parameters")

    @property
    def history_capacity(self):
        return self.actors * self.per_actor_history

    @property
    def offered_per_actor(self):
        return int(math.floor(self.duration_seconds * self.rate_per_actor))


def characterization_config(parameters):
    total_rate = math.ceil(parameters.actors * parameters.rate_per_actor)
    horizon = 3600 + 60 + 300
    outcome_capacity = max(100_000, math.ceil(1.1 * total_rate * horizon))
    if outcome_capacity > 1_000_000:
        raise ValueError("outcome_capacity_exceeds_product_bound")
    config = capacity_config(
        rate=total_rate, capacity=outcome_capacity, archive_age=3600,
        archive_interval=60, max_request_age=1800, agents_per_tenant=1)
    connectors, routes, engines, agents = [], [], [], []
    uid = 11_001
    for tenant in ("a", "b"):
        connectors.extend([
            {"name": "business-" + tenant, "type": "chat_completions",
             "endpoint": "https://upstream.acceptance.test/v1/chat/completions",
             "model": "synthetic-model", "credential": "business-key-" + tenant,
             "authentication": "x-api-key", "ca_file": "/bootstrap/ca.pem",
             "timeout_seconds": 20, "max_concurrent_calls": 64,
             "data_domain": "acceptance-upstream"},
            {"name": "security-" + tenant, "type": "chat_completions",
             "endpoint": "https://upstream.acceptance.test/v1/chat/completions",
             "model": "synthetic-security", "credential": "security-key-" + tenant,
             "authentication": "x-api-key", "ca_file": "/bootstrap/ca.pem",
             "timeout_seconds": 20, "max_concurrent_calls": 64,
             "data_domain": "acceptance-upstream"},
        ])
        routes.extend([
            {"name": tenant + ".security.inspect", "tenant": tenant,
             "operation": "security.assess", "connector": "security-" + tenant,
             "clearance": "internal", "produces": "internal", "privacy": "tokenize"},
            {"name": tenant + ".business", "tenant": tenant,
             "operation": "model.call", "connector": "business-" + tenant,
             "clearance": "internal", "produces": "internal", "privacy": "tokenize",
             "security_engine": "engine-" + tenant},
        ])
        engines.append({"name": "engine-" + tenant, "tenant": tenant,
                        "model_route": tenant + ".security.inspect",
                        "timeout_seconds": 5, "confidence_threshold": 0.7,
                        "failure_action": "deny"})
        for number in range(1, parameters.actors // 2 + 1):
            agents.append({
                "id": "agent-%s-%02d" % (tenant, number), "tenant": tenant,
                "principal": "%s-bot-%02d" % (tenant, number), "uid": uid,
                "clearance": "internal", "groups": ["support"],
                "routes": [tenant + ".business"],
            })
            uid += 1
    config.update({
        "connectors": connectors,
        "routes": routes,
        "security_engines": engines,
        "security_history": {
            "capacity": parameters.history_capacity,
            "ttl_seconds": 3600,
            "per_actor_capacity": parameters.per_actor_history,
        },
        "agents": agents,
        "approvers": [],
        "backend_inventory": {"schema_version": 1, "backends": [{
            "backend_id": "acceptance-upstream", "account_id": "synthetic-shared",
            "data_domain": "acceptance-upstream", "tenants": ["a", "b"],
            "hosts": ["https://upstream.acceptance.test"],
        }]},
        "egress": {"mode": "proxy", "socket": "/run/guard-egress/egress.sock",
                   "client_uids": [10001], "socket_group": 10003,
                   "max_connections": 128,
                   "allow": [{"host": "upstream.acceptance.test", "port": 443,
                              "addresses": NETWORKS}]},
    })
    config["service"].update({
        "control_timeout_seconds": 10,
        "max_connections": max(32, parameters.actors * 4),
        "per_peer_connections": 4,
    })
    # Validate before deployment, but serialize the public configuration.
    # The normalized runtime representation includes internal/default fields
    # that are deliberately not accepted as operator-supplied configuration.
    validate(config)
    return config


def build_plan(parameters, config=None):
    config = config or characterization_config(parameters)
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":"), allow_nan=False)
    tenants = Counter(agent["tenant"] for agent in config["agents"])
    return {
        "schema": "enkstein-ai-security-characterization-plan-v1",
        "mode": "plan",
        "docker_executed": False,
        "project_prefix": PROJECT_PREFIX,
        "parameters": {
            "actor_count": parameters.actors,
            "actors_per_tenant": dict(sorted(tenants.items())),
            "per_actor_history": parameters.per_actor_history,
            "history_capacity": parameters.history_capacity,
            "warmup_calls_per_actor": parameters.per_actor_history,
            "warmup_offered_calls": parameters.history_capacity,
            "measurement_duration_seconds": parameters.duration_seconds,
            "measurement_rate_per_actor": parameters.rate_per_actor,
            "measurement_offered_per_actor": parameters.offered_per_actor,
            "measurement_offered_calls": parameters.offered_per_actor * parameters.actors,
            "max_inflight_per_actor": parameters.max_inflight,
        },
        "configuration_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
        "profile": config["profile"],
        "agent_uids": [agent["uid"] for agent in config["agents"]],
        "fixed_models": sorted({connector["model"] for connector in config["connectors"]
                                if connector["type"] == "chat_completions"}),
        "separate_credentials": sorted(connector["credential"] for connector in config["connectors"]
                                       if connector["type"] == "chat_completions"),
        "production_accepted": False,
        "live_model_robustness": False,
        "limitations": [
            "Synthetic local TLS upstream only",
            "Characterization results are not production SLOs or acceptance",
            "Single-host production profile; no HA or multi-host claim",
        ],
    }


def aggregate_agent_results(results, expected, phase):
    statuses, actors = Counter(), {}
    latencies = {name: [] for name in ("total", "queue", "rpc")}
    elapsed_values, offered_windows, drains = [], [], []
    for actor in expected:
        result = results.get(actor) or {}
        item = result.get("summary") or {}
        reported_statuses = item.get("statuses") or {}
        reported_latencies = {
            name: item.get(name + "_latencies_ms") or [] for name in latencies
        }
        valid_statuses = (type(reported_statuses) is dict
                          and all(type(status) is str and status
                                  and type(count) is int and count >= 0
                                  for status, count in reported_statuses.items()))
        valid_latencies = all(
            type(values) is list
            and all(type(value) in (int, float) and math.isfinite(value) and value >= 0
                    for value in values)
            for values in reported_latencies.values())
        strict_counts = all(
            type(item.get(name)) is int and item[name] >= 0
            for name in ("offered_calls", "actual_calls", "successful_calls", "error_calls"))
        elapsed = item.get("elapsed_seconds")
        offered_window = item.get("offered_window_seconds")
        drain = item.get("drain_seconds")
        valid_timing = (type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0)
        if phase == "measurement":
            valid_timing = bool(
                valid_timing
                and type(offered_window) in (int, float) and math.isfinite(offered_window)
                and offered_window >= 0
                and type(drain) in (int, float) and math.isfinite(drain) and drain >= 0
                and elapsed + 0.002 >= offered_window
                and drain <= elapsed + 0.002)
        else:
            valid_timing = bool(valid_timing and offered_window is None and drain is None)
        status_total = sum(reported_statuses.values()) if valid_statuses else None
        internally_consistent = bool(
            valid_statuses and valid_latencies and strict_counts and valid_timing
            and item.get("actor") == actor
            and item.get("phase") == phase
            and item.get("actual_calls") == status_total
            and all(len(values) == status_total for values in reported_latencies.values())
            and item.get("successful_calls") == reported_statuses.get("ok", 0)
            and item.get("error_calls") == status_total - reported_statuses.get("ok", 0))
        if valid_statuses:
            statuses.update(reported_statuses)
        if valid_latencies:
            for name, values in reported_latencies.items():
                latencies[name].extend(values)
        if valid_timing:
            elapsed_values.append(elapsed)
            if phase == "measurement":
                offered_windows.append(offered_window)
                drains.append(drain)
        actors[actor] = {
            "returncode": result.get("returncode"),
            "summary_present": bool(result.get("summary")),
            "internally_consistent": internally_consistent,
            "reported_actor": item.get("actor"),
            "reported_phase": item.get("phase"),
            "offered_calls": item.get("offered_calls"),
            "actual_calls": item.get("actual_calls"),
            "successful_calls": item.get("successful_calls"),
            "error_calls": item.get("error_calls"),
            "statuses": item.get("statuses"),
            "elapsed_seconds": elapsed,
            "offered_window_seconds": offered_window,
            "drain_seconds": drain,
            "stderr": result.get("stderr", ""),
        }
    complete = bool(actors) and all(
        item["returncode"] == 0 and item["summary_present"]
        and item["offered_calls"] == expected[actor]
        and item["actual_calls"] == expected[actor]
        and item["internally_consistent"] is True
        for actor, item in actors.items())
    aggregated = {
        "phase": phase,
        "complete": complete,
        "actors": actors,
        "offered_calls": sum(expected.values()),
        "actual_calls": sum(statuses.values()),
        "successful_calls": statuses.get("ok", 0),
        "error_calls": sum(count for status, count in statuses.items() if status != "ok"),
        "statuses": dict(sorted(statuses.items())),
        "max_agent_elapsed_seconds": max(elapsed_values) if elapsed_values else None,
        "offered_window_seconds": max(offered_windows) if offered_windows else None,
        "max_drain_seconds": max(drains) if drains else None,
    }
    for name, values in latencies.items():
        aggregated.update({
            name + "_p50_ms": percentile(values, 0.50),
            name + "_p95_ms": percentile(values, 0.95),
            name + "_p99_ms": percentile(values, 0.99),
            name + "_max_ms": round(max(values), 2) if values else None,
        })
    return aggregated


def parse_upstream_counters(value):
    """Strictly validate one bounded cumulative upstream snapshot."""
    expected_keys = {
        "schema", "sequence", "requests", "inspection", "business", "unknown",
        "models", "header_hashes",
    }
    if type(value) is not dict or set(value) != expected_keys or value.get("schema") != UPSTREAM_SCHEMA:
        raise ValueError("invalid_upstream_counter_schema")
    numeric = ("sequence", "requests", *UPSTREAM_KINDS)
    if any(type(value.get(name)) is not int or value[name] < 0 for name in numeric):
        raise ValueError("invalid_upstream_counter_value")
    if value["sequence"] != value["requests"] or value["requests"] != sum(
            value[name] for name in UPSTREAM_KINDS):
        raise ValueError("inconsistent_upstream_counters")
    models = value.get("models")
    if (type(models) is not dict or set(models) != set(UPSTREAM_MODELS)
            or any(type(models[name]) is not int or models[name] < 0 for name in UPSTREAM_MODELS)
            or models["synthetic-security"] != value["inspection"]
            or models["synthetic-model"] != value["business"]
            or models["unknown"] != value["unknown"]):
        raise ValueError("invalid_upstream_model_counters")
    hashes = value.get("header_hashes")
    if type(hashes) is not dict or set(hashes) != set(UPSTREAM_KINDS):
        raise ValueError("invalid_upstream_header_counters")
    for kind in UPSTREAM_KINDS:
        buckets = hashes[kind]
        if (type(buckets) is not dict or len(buckets) > 17
                or any((key not in ("missing", "other") and not _DIGEST.fullmatch(key))
                       or type(count) is not int or count < 0
                       for key, count in buckets.items())
                or sum(buckets.values()) != value[kind]):
            raise ValueError("invalid_upstream_header_counters")
    return value


def upstream_counter_delta(before, after):
    before = parse_upstream_counters(before)
    after = parse_upstream_counters(after)

    def difference(old, new):
        result = {}
        for key in set(old) | set(new):
            prior, current = old.get(key, 0), new.get(key, 0)
            if current < prior:
                raise ValueError("upstream_counter_regression")
            if current - prior:
                result[key] = current - prior
        return dict(sorted(result.items()))

    delta = {}
    for name in ("sequence", "requests", *UPSTREAM_KINDS):
        if after[name] < before[name]:
            raise ValueError("upstream_counter_regression")
        delta[name] = after[name] - before[name]
    delta["models"] = difference(before["models"], after["models"])
    delta["header_hashes"] = {
        kind: difference(before["header_hashes"][kind], after["header_hashes"][kind])
        for kind in UPSTREAM_KINDS
    }
    return delta


class AISecurityCharacterization(ProductionDeployment):
    def __init__(self, parameters, config):
        overlay = ROOT / "deployment/acceptance/ai_security_characterization_compose.yaml"
        super().__init__(config, label="ai-characterization", overlays=(overlay,),
                         upstream_mode="capture", project_prefix=PROJECT_PREFIX)
        self.parameters = parameters
        self.load_script = ROOT / "deployment/acceptance/ai_security_load.py"

    def _agent_command(self, agent, phase):
        token = self.run / "credentials" / (agent["id"] + ".token")
        args = [
            "--phase", phase, "--actor", agent["id"],
            "--route", agent["tenant"] + ".business",
            "--warmup-count", str(self.parameters.per_actor_history),
            "--duration", str(self.parameters.duration_seconds),
            "--rate", str(self.parameters.rate_per_actor),
            "--max-inflight", str(self.parameters.max_inflight),
        ]
        return [
            *self.base, "run", "--rm", "--no-deps", "-T",
            "--user", "%d:10001" % agent["uid"],
            "-v", str(self.load_script) + ":/ai_security_load.py:ro",
            "-v", str(token) + ":/run/agent-token:ro",
            "--entrypoint", "python", "agent", "/ai_security_load.py", *args,
        ]

    @staticmethod
    def _parse_agent(result):
        lines = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        summary = next((line for line in reversed(lines) if line.get("type") == "summary"), None)
        return {"summary": summary, "returncode": result.returncode,
                "stderr": result.stderr[-1500:] if result.returncode else ""}

    def warmup(self):
        runs = {}
        for agent in self.config["agents"]:
            process = subprocess.Popen(
                self._agent_command(agent, "warmup"), env=self.env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            runs[agent["id"]] = AgentRun(process)
        deadline = (time.monotonic()
                    + self.parameters.per_actor_history / self.parameters.rate_per_actor + 180)
        return {actor: run.result(max(0, deadline - time.monotonic()))
                for actor, run in runs.items()}

    def measurement(self):
        runs = {}
        for agent in self.config["agents"]:
            process = subprocess.Popen(
                self._agent_command(agent, "measurement"), env=self.env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            runs[agent["id"]] = AgentRun(process)
        samples = [self.sample()]
        time.sleep(min(5, max(0.25, self.parameters.duration_seconds / 2)))
        samples.append(self.sample())
        deadline = time.monotonic() + self.parameters.duration_seconds + 180
        results = {actor: run.result(max(0, deadline - time.monotonic()))
                   for actor, run in runs.items()}
        samples.append(self.sample())
        return results, samples

    def upstream_counters(self):
        result = self.compose(
            "exec", "-T", "upstream", "cat", UPSTREAM_STATS,
            check=False, timeout=60)
        if result.returncode:
            raise RuntimeError("upstream_counters_unavailable")
        try:
            value = json.loads(result.stdout)
        except (TypeError, ValueError):
            raise RuntimeError("upstream_counters_malformed") from None
        return parse_upstream_counters(value)


def execute_characterization(parameters, config, report_name=REPORT_NAME):
    plan = build_plan(parameters, config)
    deployment = None
    report = {
        "schema": "enkstein-ai-security-characterization-v1",
        "complete": False,
        "production_accepted": False,
        "live_model_robustness": False,
        "plan": plan,
        "image": IMAGE,
        "evidence": None,
        "warmup": None,
        "measurement": None,
        "observed_errors": False,
        "observed_error_counts": {},
        "metrics": {"samples": [], "status_after_warmup": None,
                    "status_after_measurement": None},
        "upstream_counters": {"initial": None, "after_warmup": None,
                              "warmup_delta": None, "after_measurement": None,
                              "measurement_delta": None},
        "limitations": plan["limitations"],
    }
    try:
        deployment = AISecurityCharacterization(parameters, config)
        ready = deployment.up()
        if ready.get("ready") is not True:
            raise RuntimeError("guard_not_ready")
        report["evidence"] = deployment.header("ai-security-characterization")
        initial_counters = deployment.upstream_counters()
        report["upstream_counters"]["initial"] = initial_counters
        warm_results = deployment.warmup()
        warm_expected = {agent["id"]: parameters.per_actor_history
                         for agent in config["agents"]}
        warm = aggregate_agent_results(warm_results, warm_expected, "warmup")
        warm_status = deployment.status()
        after_warmup = deployment.upstream_counters()
        warm_delta = upstream_counter_delta(initial_counters, after_warmup)
        occupancy = ((warm_status or {}).get("security_history") or {}).get("records")
        warm["confirmed_history_occupancy"] = occupancy
        warm["required_history_occupancy"] = parameters.history_capacity
        warm["every_actor_filled"] = all(
            type(item.get("successful_calls")) is int
            and item["successful_calls"] >= parameters.per_actor_history
            for item in warm["actors"].values())
        warm["counter_checks"] = {
            "inspection_matches_actual": warm_delta["inspection"] == warm["actual_calls"],
            "business_matches_actual": warm_delta["business"] == warm["actual_calls"],
            "successful_matches_actual": warm["successful_calls"] == warm["actual_calls"],
            "unknown_is_zero": warm_delta["unknown"] == 0,
        }
        warm["counters_complete"] = all(warm["counter_checks"].values())
        report["warmup"] = warm
        report["metrics"]["status_after_warmup"] = warm_status
        report["upstream_counters"]["after_warmup"] = after_warmup
        report["upstream_counters"]["warmup_delta"] = warm_delta
        if (not warm["complete"] or not warm["every_actor_filled"]
                or not warm["counters_complete"]
                or occupancy != parameters.history_capacity):
            raise RuntimeError("warmup_incomplete")

        measurement_results, samples = deployment.measurement()
        after_measurement = deployment.upstream_counters()
        measured_delta = upstream_counter_delta(after_warmup, after_measurement)
        measured_expected = {agent["id"]: parameters.offered_per_actor
                             for agent in config["agents"]}
        measurement = aggregate_agent_results(
            measurement_results, measured_expected, "measurement")
        measurement["counter_checks"] = {
            "business_matches_successful": (
                measured_delta["business"] == measurement["successful_calls"]),
            "inspection_covers_successful": (
                measured_delta["inspection"] >= measurement["successful_calls"]),
            "inspection_not_above_actual": (
                measured_delta["inspection"] <= measurement["actual_calls"]),
            "unknown_is_zero": measured_delta["unknown"] == 0,
            "ai_path_observed": measured_delta["inspection"] > 0,
        }
        measurement["counters_complete"] = all(measurement["counter_checks"].values())
        report["measurement"] = measurement
        report["metrics"]["samples"] = samples
        report["metrics"]["status_after_measurement"] = deployment.status()
        report["upstream_counters"]["after_measurement"] = after_measurement
        report["upstream_counters"]["measurement_delta"] = measured_delta
        report["observed_error_counts"] = {
            status: count for status, count in measurement["statuses"].items()
            if status != "ok"
        }
        report["observed_errors"] = bool(report["observed_error_counts"])
        report["complete"] = measurement["complete"] and measurement["counters_complete"]
        if not report["complete"]:
            report["error"] = "measurement_incomplete"
    except Exception as error:
        detail = str(error)
        report["error"] = type(error).__name__ + ":" + (
            deployment.redact(detail) if deployment is not None else detail)[-1000:]
        if deployment is not None:
            try:
                report["diagnostic_logs"] = deployment.logs()
            except Exception:
                report["diagnostic_logs"] = "unavailable"
    finally:
        if deployment is not None:
            try:
                deployment.down()
            except Exception as error:
                report["complete"] = False
                report["cleanup_error"] = type(error).__name__ + ":" + deployment.redact(str(error))[-1000:]
    output = write_report(report_name, report)
    print(json.dumps({"complete": report["complete"], "report": str(output),
                      "production_accepted": False, "live_model_robustness": False},
                     sort_keys=True))
    return 0 if report["complete"] else 1


def argument_parser():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="validate and print plan (default)")
    mode.add_argument("--run", action="store_true", help="explicitly execute Docker characterization")
    parser.add_argument("--actors", type=int, default=2)
    parser.add_argument("--per-actor-history", type=int, default=16)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--rate-per-actor", type=float, default=2)
    parser.add_argument("--max-inflight", type=int, default=4)
    parser.add_argument("--report", default=REPORT_NAME)
    return parser


def main(argv=None):
    args = argument_parser().parse_args(argv)
    if not _REPORT.fullmatch(args.report):
        raise ValueError("invalid_report_name")
    parameters = CharacterizationParameters(
        actors=args.actors, per_actor_history=args.per_actor_history,
        duration_seconds=args.duration, rate_per_actor=args.rate_per_actor,
        max_inflight=args.max_inflight)
    config = characterization_config(parameters)
    if not args.run:
        print(json.dumps(build_plan(parameters, config), indent=2, sort_keys=True))
        return 0
    return execute_characterization(parameters, config, args.report)


if __name__ == "__main__":
    raise SystemExit(main())
