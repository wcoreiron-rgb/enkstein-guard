"""Plan or explicitly run the fixed synthetic AI-security endurance profile.

The default is side-effect-free plan output.  ``--run`` is the only mode that
constructs a disposable Compose deployment.  An explicit shorter duration is
a smoke/harness check and can never produce a full endurance pass.
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
import subprocess
import sys
import time


os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deployment"))

from characterize_ai_security import (  # noqa: E402
    UPSTREAM_STATS, parse_upstream_counters, upstream_counter_delta,
)
from enkstein_guard.productconfig import validate  # noqa: E402
from production_harness import (  # noqa: E402
    AgentRun, Deployment as ProductionDeployment, IMAGE, NETWORKS,
    capacity_config, write_report,
)


TARGETS_PATH = ROOT / "deployment/ai-security-endurance-targets.json"
LOAD_SCRIPT = ROOT / "deployment/acceptance/ai_security_endurance_load.py"
OVERLAY = ROOT / "deployment/acceptance/ai_security_characterization_compose.yaml"
FULL_REPORT = "production-ai-security-endurance.json"
SMOKE_REPORT = "production-ai-security-endurance-smoke.json"
PROJECT_PREFIX = "egaie"
ACTORS = 4
TENANTS = 2
PER_ACTOR_HISTORY = 64
HISTORY_CAPACITY = 256
RATE_PER_ACTOR = 2
FULL_DURATION_SECONDS = 10_800
MIN_SMOKE_DURATION_SECONDS = 30
MAX_INFLIGHT = 4
WINDOW_SECONDS = 60
ACTOR_DRAIN_SECONDS = 75
PHASE_STARTUP_GRACE_SECONDS = 120
MEASURED_CALLS = 86_400
WARMUP_CALLS = 256


EXPECTED_REQUIREMENTS = {
    "AE-01": {"warmup_calls_exact": 256, "measured_calls_exact": 86400,
              "successful_calls_exact": 86400, "error_calls_max": 0,
              "actors_complete_exact": 4, "duration_seconds_exact": 10800},
    "AE-02": {"p95_ms_max": 1000, "p99_ms_max": 2000,
              "window_p99_ms_max": 5000},
    "AE-03": {"guard_rss_mib_max": 256, "egress_rss_mib_max": 96,
              "last_hour_max_over_first_hour_max_mib": 32},
    "AE-04": {"guard_fds_max": 256, "guard_threads_max": 64},
    "AE-05": {"security_history_records_max": 256,
              "security_history_records_after_warmup_exact": 256,
              "security_history_records_at_end_exact": 256,
              "active_state_bytes_max": 268435456},
    "AE-06": {"retention_failures_max": 0, "audit_with_archives_verified": True,
              "outcome_archives_verified": True},
    "AE-07": {"phase_inspection_business_successful_equal": True,
              "unknown_calls_max": 0, "inspection_credential_hashes_exact": 2,
              "business_credential_hashes_exact": 2,
              "credential_hash_sets_distinct": True,
              "configured_security_engines_exact": 2},
    "AE-08": {"image_identity_required": True, "wheel_identity_required": True,
              "dependency_lock_match_required": True,
              "raw_saved_configuration_required": True,
              "configuration_hash_required": True,
              "revision_digests_required": True, "target_sha256_required": True,
              "target_deployment_revision_binding_required": True,
              "missing_measurements_max": 0},
}


@dataclass(frozen=True)
class EnduranceParameters:
    duration_seconds: int = FULL_DURATION_SECONDS
    explicit_duration: bool = False

    def __post_init__(self):
        if type(self.duration_seconds) is not int:
            raise ValueError("invalid_endurance_duration")
        if type(self.explicit_duration) is not bool:
            raise ValueError("invalid_endurance_mode")
        if self.explicit_duration:
            if not MIN_SMOKE_DURATION_SECONDS <= self.duration_seconds < FULL_DURATION_SECONDS:
                raise ValueError("smoke_duration_must_be_30_through_10799")
        elif self.duration_seconds != FULL_DURATION_SECONDS:
            raise ValueError("full_duration_must_be_10800")

    @property
    def full_endurance(self):
        return not self.explicit_duration

    @property
    def measured_calls_per_actor(self):
        return self.duration_seconds * RATE_PER_ACTOR

    @property
    def measured_calls(self):
        return ACTORS * self.measured_calls_per_actor


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_targets(path=TARGETS_PATH):
    value = json.loads(Path(path).read_text())
    if (type(value) is not dict
            or value.get("schema") != "enkstein-guard.ai-security-endurance-targets/v1"
            or value.get("defined_before_measurement") is not True
            or value.get("load") != {
                "actors": 4, "tenants": 2, "retained_votes_per_actor": 64,
                "warmup_calls": 256, "duration_seconds": 10800,
                "requests_per_second_per_actor": 2, "measured_calls": 86400,
                "max_inflight_per_actor": 4, "progress_window_seconds": 60,
            }):
        raise ValueError("invalid_endurance_targets_header")
    items = value.get("targets")
    if (type(items) is not list or len(items) != len(EXPECTED_REQUIREMENTS)
            or [item.get("id") for item in items] != list(EXPECTED_REQUIREMENTS)
            or any(item.get("requirements") != EXPECTED_REQUIREMENTS[item.get("id")]
                   for item in items if item.get("id") in EXPECTED_REQUIREMENTS)):
        raise ValueError("endurance_targets_changed")
    return value


def endurance_config():
    config = capacity_config(
        rate=40, capacity=200_000, archive_age=3600, archive_interval=300,
        max_request_age=1800, audit_threshold=20_000, audit_keep=5000,
        audit_interval=300, vault_interval=60, token_ttl=300,
        agents_per_tenant=2)
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
        for number in range(1, 3):
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
        "security_history": {"capacity": HISTORY_CAPACITY, "ttl_seconds": 21_600,
                             "per_actor_capacity": PER_ACTOR_HISTORY},
        "audit": {"full_verify_every": 10_000},
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
    config["service"].update({"control_timeout_seconds": 10,
                              "max_connections": 64, "per_peer_connections": 4})
    # Validation is deliberately discarded: the public operator document, not
    # the normalized internal representation, is serialized into the deployment.
    validate(config)
    return config


def configuration_digest(config):
    raw = json.dumps(config, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def build_plan(parameters, config=None, targets=None):
    config = config if config is not None else endurance_config()
    targets = targets if targets is not None else load_targets()
    tenant_counts = Counter(item["tenant"] for item in config["agents"])
    credentials = [item["credential"] for item in config["connectors"]
                   if item["type"] == "chat_completions"]
    return {
        "schema": "enkstein-guard.ai-security-endurance-plan/v1",
        "mode": "plan",
        "docker_executed": False,
        "run_class": "full_endurance" if parameters.full_endurance else "short_smoke",
        "full_acceptance_eligible": parameters.full_endurance,
        "full_acceptance_passed": False,
        "short_smoke_passed": False,
        "parameters": {
            "actors": ACTORS, "actors_per_tenant": dict(sorted(tenant_counts.items())),
            "tenants": TENANTS, "per_actor_history": PER_ACTOR_HISTORY,
            "history_capacity": HISTORY_CAPACITY,
            "warmup_calls_per_actor": PER_ACTOR_HISTORY,
            "warmup_calls": WARMUP_CALLS,
            "duration_seconds": parameters.duration_seconds,
            "rate_per_actor": RATE_PER_ACTOR,
            "measured_calls_per_actor": parameters.measured_calls_per_actor,
            "measured_calls": parameters.measured_calls,
            "max_inflight_per_actor": MAX_INFLIGHT,
            "progress_window_seconds": WINDOW_SECONDS,
        },
        "configuration_sha256": configuration_digest(config),
        "targets": str(TARGETS_PATH.relative_to(ROOT)),
        "targets_sha256": sha256_file(TARGETS_PATH),
        "targets_defined_at": targets["defined_at"],
        "profile": config["profile"],
        "agent_uids": [item["uid"] for item in config["agents"]],
        "fixed_models": sorted({item["model"] for item in config["connectors"]}),
        "separate_credentials": sorted(credentials),
        "topology": {
            "guard_network": "none", "agents_network": "none",
            "egress": "independent_proxy", "tls_upstream": "fixed_synthetic",
            "inspector_routes_granted_to_agents": False,
            "configured_security_engines": 2,
        },
        "real_model_robustness": False,
        "synthetic_counter_fsync_overhead": True,
        "duplicate_execution_claim": False,
        "standard_p04_no_replay_is_separate": True,
        "limitations": targets["limitations"],
    }


def _parse_histogram(value, expected_count):
    if (type(value) is not dict or set(value) != {
            "unit", "maximum_bucket_ms", "count", "buckets"}
            or value.get("unit") != "milliseconds_ceiling"
            or type(value.get("maximum_bucket_ms")) is not int
            or value["maximum_bucket_ms"] <= 0
            or type(value.get("count")) is not int
            or value.get("count") != expected_count
            or type(value.get("buckets")) is not list):
        raise ValueError("invalid_endurance_histogram")
    result, prior, total = {}, -1, 0
    for pair in value["buckets"]:
        if (type(pair) is not list or len(pair) != 2
                or type(pair[0]) is not int or not 0 <= pair[0] <= value["maximum_bucket_ms"]
                or pair[0] <= prior or type(pair[1]) is not int or pair[1] <= 0):
            raise ValueError("invalid_endurance_histogram_bucket")
        prior = pair[0]
        result[pair[0]] = pair[1]
        total += pair[1]
    if total != expected_count:
        raise ValueError("inconsistent_endurance_histogram")
    return result


def _histogram_percentile(buckets, fraction):
    count = sum(buckets.values())
    if not count:
        return None
    rank, seen = max(1, int(math.ceil(fraction * count))), 0
    for bucket, amount in sorted(buckets.items()):
        seen += amount
        if seen >= rank:
            return float(bucket)
    raise ValueError("inconsistent_aggregate_histogram")


def aggregate_phase(results, expected, phase, duration_seconds):
    statuses, actors, histograms, windows = Counter(), {}, Counter(), []
    for actor, offered in expected.items():
        result = results.get(actor) or {}
        item = result.get("summary") or {}
        reported = item.get("statuses") or {}
        valid_statuses = (type(reported) is dict
                          and all(type(key) is str and key and type(value) is int and value >= 0
                                  for key, value in reported.items()))
        actual = sum(reported.values()) if valid_statuses else -1
        try:
            actor_histogram = _parse_histogram(item.get("total_histogram"), actual)
            for name in ("queue_histogram", "rpc_histogram"):
                _parse_histogram(item.get(name), actual)
            histograms.update(actor_histogram)
            valid_histograms = True
        except (TypeError, ValueError):
            valid_histograms = False
        actor_windows = result.get("windows") or []
        valid_windows = (type(actor_windows) is list and all(
            type(window) is dict and window.get("type") == "window"
            and window.get("actor") == actor and window.get("phase") == phase
            and type(window.get("requests")) is int and window["requests"] >= 0
            and type(window.get("statuses")) is dict
            and all(type(key) is str and key and type(value) is int and value >= 0
                    for key, value in window["statuses"].items())
            and sum(window["statuses"].values()) == window["requests"]
            and (window.get("p99_ms") is None or
                 type(window.get("p99_ms")) in (int, float)
                 and math.isfinite(window["p99_ms"]) and window["p99_ms"] >= 0)
            for window in actor_windows)
            and (phase == "warmup"
                 or sum(window["requests"] for window in actor_windows) == actual))
        summary_valid = bool(
            valid_statuses and valid_histograms and valid_windows
            and item.get("actor") == actor and item.get("phase") == phase
            and item.get("offered_calls") == offered and item.get("actual_calls") == actual
            and item.get("successful_calls") == reported.get("ok", 0)
            and item.get("error_calls") == actual - reported.get("ok", 0)
            and item.get("unique_request_ids") == actual
            and item.get("pending_cancelled") == 0 and item.get("retries") == 0
            and item.get("configured_max_inflight") == MAX_INFLIGHT
            and type(item.get("elapsed_seconds")) in (int, float)
            and math.isfinite(item["elapsed_seconds"]) and item["elapsed_seconds"] >= 0
            and ((phase == "warmup" and item.get("offered_window_seconds") is None
                  and item.get("drain_seconds") is None)
                 or (phase == "measurement"
                     and item.get("offered_window_seconds") == duration_seconds
                     and item["elapsed_seconds"] >= duration_seconds
                     and type(item.get("drain_seconds")) in (int, float)
                     and math.isfinite(item["drain_seconds"]) and item["drain_seconds"] >= 0)))
        if valid_statuses:
            statuses.update(reported)
        if valid_windows:
            windows.extend(dict(window, actor=actor) for window in actor_windows)
        actors[actor] = {
            "returncode": result.get("returncode"),
            "summary_present": bool(result.get("summary")),
            "internally_consistent": summary_valid,
            "offered_calls": item.get("offered_calls"),
            "actual_calls": item.get("actual_calls"),
            "successful_calls": item.get("successful_calls"),
            "error_calls": item.get("error_calls"),
            "statuses": item.get("statuses"),
            "elapsed_seconds": item.get("elapsed_seconds"),
            "drain_seconds": item.get("drain_seconds"),
            "stderr": result.get("stderr", ""),
        }
    complete = bool(actors) and all(
        value["returncode"] == 0 and value["summary_present"]
        and value["internally_consistent"]
        and value["actual_calls"] == expected[actor]
        for actor, value in actors.items())
    actual = sum(statuses.values())
    return {
        "phase": phase, "complete": complete, "actors": actors,
        "actors_complete": sum(value["returncode"] == 0 and value["internally_consistent"]
                               for value in actors.values()),
        "offered_calls": sum(expected.values()), "actual_calls": actual,
        "successful_calls": statuses.get("ok", 0),
        "error_calls": actual - statuses.get("ok", 0),
        "statuses": dict(sorted(statuses.items())),
        "total_p95_ms": _histogram_percentile(histograms, 0.95),
        "total_p99_ms": _histogram_percentile(histograms, 0.99),
        "total_max_bucket_ms": float(max(histograms)) if histograms else None,
        "total_histogram": {"unit": "milliseconds_ceiling",
                            "count": sum(histograms.values()),
                            "buckets": [[key, histograms[key]] for key in sorted(histograms)]},
        "windows": windows,
        "window_p99_ms_max": max((item["p99_ms"] for item in windows
                                  if item.get("p99_ms") is not None), default=None),
        "max_actor_elapsed_seconds": max((value["elapsed_seconds"] for value in actors.values()
                                          if type(value.get("elapsed_seconds")) in (int, float)),
                                         default=None),
    }


def counter_checks(delta, phase):
    inspection = {key for key in delta["header_hashes"]["inspection"]
                  if key not in ("missing", "other")}
    business = {key for key in delta["header_hashes"]["business"]
                if key not in ("missing", "other")}
    successful = phase.get("successful_calls")
    checks = {
        "inspection_matches_successful": delta["inspection"] == successful,
        "business_matches_successful": delta["business"] == successful,
        "unknown_is_zero": delta["unknown"] == 0,
        "inspection_credential_hashes_exact": len(inspection) == 2,
        "business_credential_hashes_exact": len(business) == 2,
        "credential_hash_sets_distinct": bool(inspection and business and inspection.isdisjoint(business)),
        "no_missing_or_overflow_hash_bucket": all(
            key not in ("missing", "other")
            for kind in ("inspection", "business", "unknown")
            for key in delta["header_hashes"][kind]),
    }
    return {"checks": checks, "complete": all(checks.values()),
            "inspection_hashes": sorted(inspection), "business_hashes": sorted(business)}


class AISecurityEnduranceDeployment(ProductionDeployment):
    def __init__(self, parameters, config):
        super().__init__(config, label="ai-security-endurance", overlays=(OVERLAY,),
                         upstream_mode="capture", project_prefix=PROJECT_PREFIX)
        self.parameters = parameters
        self.progress_path = self.run.parent / (
            "ai-security-endurance-progress-%s.jsonl" % self.project)
        descriptor = os.open(self.progress_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)

    def _agent_command(self, agent, phase):
        token = self.run / "credentials" / (agent["id"] + ".token")
        return [
            *self.base, "run", "--rm", "--no-deps", "-T",
            "--user", "%d:10001" % agent["uid"],
            "-v", str(LOAD_SCRIPT) + ":/ai_security_endurance_load.py:ro",
            "-v", str(token) + ":/run/agent-token:ro",
            "--entrypoint", "python", "agent", "/ai_security_endurance_load.py",
            "--phase", phase, "--actor", agent["id"],
            "--route", agent["tenant"] + ".business",
            "--duration", str(self.parameters.duration_seconds),
        ]

    def start_phase(self, phase):
        runs = {}
        for agent in self.config["agents"]:
            process = subprocess.Popen(
                self._agent_command(agent, phase), env=self.env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # AgentRun pumps stdout and stderr for the life of the process, so
            # three hours of progress can never fill a child pipe.
            runs[agent["id"]] = AgentRun(process)
        return runs

    def warmup(self):
        runs = self.start_phase("warmup")
        deadline = time.monotonic() + PER_ACTOR_HISTORY / RATE_PER_ACTOR + 180
        return {actor: run.result(max(0, deadline - time.monotonic()))
                for actor, run in runs.items()}

    def sample_with_status(self, started):
        value = self.sample()
        value["elapsed_seconds"] = round(time.monotonic() - started, 3)
        status = self.status() or {}
        value["status"] = {key: status.get(key) for key in (
            "outcomes", "audit", "vault", "retention", "security_history",
            "tracked_requests", "unsettled_outcomes", "audit_event_failures")}
        return value

    def append_progress(self, sample):
        with self.progress_path.open("a") as stream:
            stream.write(json.dumps(sample, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def measurement(self):
        runs = self.start_phase("measurement")
        started = time.monotonic()
        samples, operator_run, next_sample = [], None, started
        deadline = (started + self.parameters.duration_seconds + ACTOR_DRAIN_SECONDS
                    + PHASE_STARTUP_GRACE_SECONDS)
        while (any(run.poll() is None for run in runs.values())
               and time.monotonic() < deadline):
            now = time.monotonic()
            if now >= next_sample:
                sample = self.sample_with_status(started)
                samples.append(sample)
                self.append_progress(sample)
                next_sample += WINDOW_SECONDS
            if operator_run is None and now - started >= self.parameters.duration_seconds / 2:
                code, payload = self.guard_cli(
                    "retention", "run", "--store", "vault", check=False, timeout=300)
                operator_run = {"exit": code, "status": payload.get("status"),
                                "elapsed_seconds": round(now - started, 3)}
            time.sleep(min(1, max(0.05, next_sample - time.monotonic())))
        timed_out = any(run.poll() is None for run in runs.values())
        collection_deadline = time.monotonic() + (0 if timed_out else 180)
        results = {actor: run.result(max(0, collection_deadline - time.monotonic()))
                   for actor, run in runs.items()}
        sample = self.sample_with_status(started)
        samples.append(sample)
        self.append_progress(sample)
        return (results, samples, operator_run,
                round(time.monotonic() - started, 3), timed_out)

    def upstream_counters(self):
        result = self.compose("exec", "-T", "upstream", "cat", UPSTREAM_STATS,
                              check=False, timeout=60)
        if result.returncode:
            raise RuntimeError("upstream_counters_unavailable")
        try:
            return parse_upstream_counters(json.loads(result.stdout))
        except (TypeError, ValueError):
            raise RuntimeError("upstream_counters_malformed") from None


def _series(report, path):
    values = []
    for sample in report.get("samples") or []:
        node = sample
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        elapsed = sample.get("elapsed_seconds")
        if (type(node) in (int, float) and math.isfinite(node)
                and type(elapsed) in (int, float) and math.isfinite(elapsed)):
            values.append((elapsed, node))
    return values


def retention_telemetry(status):
    retention = (status or {}).get("retention")
    jobs, missing = {}, []
    if type(retention) is not dict:
        return {"complete": False, "failures": None,
                "jobs": {}, "missing": ["retention"]}
    for name in ("outcomes", "audit", "vault", "settlement"):
        item = retention.get(name)
        failures = item.get("failures") if type(item) is dict else None
        if type(failures) is not int or failures < 0:
            missing.append("retention.%s.failures" % name)
        else:
            jobs[name] = {"failures": failures}
    return {"complete": not missing,
            "failures": sum(item["failures"] for item in jobs.values()) if not missing else None,
            "jobs": jobs, "missing": missing}


def sample_telemetry(report):
    samples = report.get("samples")
    duration = report.get("duration_seconds")
    missing, elapsed = [], []
    fields = {
        "guard.rss_kib": ("guard", "process", "rss_kib"),
        "guard.fds": ("guard", "process", "fds"),
        "guard.threads": ("guard", "process", "threads"),
        "egress.rss_kib": ("egress", "process", "rss_kib"),
        "egress.fds": ("egress", "process", "fds"),
        "egress.threads": ("egress", "process", "threads"),
        "state.bytes": ("guard", "paths", "/state", "bytes"),
        "security_history.records": ("status", "security_history", "records"),
    }
    if type(samples) is not list or not samples:
        return {"complete": False, "missing": ["samples"], "sample_count": 0,
                "minimum_samples": None, "max_gap_seconds": None}
    for index, sample in enumerate(samples):
        value = sample.get("elapsed_seconds") if type(sample) is dict else None
        if type(value) not in (int, float) or type(value) is bool or not math.isfinite(value) or value < 0:
            missing.append("samples[%d].elapsed_seconds" % index)
        else:
            elapsed.append(value)
        for label, path in fields.items():
            node = sample
            for key in path:
                node = node.get(key) if type(node) is dict else None
            if (type(node) not in (int, float) or type(node) is bool
                    or not math.isfinite(node) or node < 0):
                missing.append("samples[%d].%s" % (index, label))
    minimum = (duration // WINDOW_SECONDS + 1
               if type(duration) is int and duration >= MIN_SMOKE_DURATION_SECONDS else None)
    gaps = [later - earlier for earlier, later in zip(elapsed, elapsed[1:])]
    coverage = bool(
        minimum is not None and len(samples) >= minimum and len(elapsed) == len(samples)
        and all(gap > 0 for gap in gaps)
        and elapsed[0] <= WINDOW_SECONDS
        and elapsed[-1] >= duration
        and max(gaps, default=0) <= WINDOW_SECONDS + 30)
    if not coverage:
        missing.append("samples.coverage")
    return {"complete": not missing, "missing": missing,
            "sample_count": len(samples), "minimum_samples": minimum,
            "first_elapsed_seconds": elapsed[0] if elapsed else None,
            "last_elapsed_seconds": elapsed[-1] if elapsed else None,
            "max_gap_seconds": max(gaps, default=None)}


def identity_checks(report):
    identity = report.get("evidence") or {}
    candidate = identity.get("candidate") or {}
    image = identity.get("image") or {}
    lock = (identity.get("dependencies") or {}).get("lock") or {}
    revisions = identity.get("revision") or {}
    configurations = identity.get("configuration") or []
    target_binding = report.get("target_binding") or {}
    checks = {
        "schema": identity.get("schema") == "enkstein-guard.evidence/v1",
        "image": bool(image.get("id")),
        "wheel": bool(candidate.get("wheel_sha256")),
        "installed_matches_wheel": candidate.get("installed_matches_wheel") is True,
        "dependency_lock": lock.get("matches_lock") is True and bool(lock.get("lock_sha256")),
        "raw_saved_configuration": bool(configurations)
            and all(item.get("preserved") for item in configurations),
        "configuration_hash": bool(configurations)
            and all(item.get("sha256") and item.get("policy_version") for item in configurations),
        "revision_digests": all((revisions.get(name) or {}).get("sha256")
                                for name in ("source", "tests", "tools", "deployment",
                                             "definitions")),
        "targets_sha256": target_binding.get("sha256") == sha256_file(TARGETS_PATH),
        "target_deployment_binding": bool(target_binding.get("deployment_revision_sha256"))
            and target_binding.get("deployment_revision_sha256")
            == (revisions.get("deployment") or {}).get("sha256"),
    }
    return {"checks": checks, "complete": all(checks.values())}


def topology_checks(config, ready, status):
    preflight = (status or {}).get("preflight") or {}
    summary = (status or {}).get("config") or {}
    checks = {
        "guard_ready": (ready or {}).get("ready") is True,
        "peer_bound": (status or {}).get("peer_bound") is True,
        "guard_network_none": preflight.get("network_interfaces") == ["lo"],
        "independent_egress_proxy_healthy": preflight.get("egress_proxy_healthy") is True,
        "four_distinct_agent_uids": len(config.get("agents") or []) == ACTORS
            and len({item.get("uid") for item in config["agents"]}) == ACTORS,
        "inspector_routes_ungranted": all(
            item.get("tenant", "") + ".security.inspect" not in item.get("routes", [])
            for item in config.get("agents") or []),
        "two_security_engines": summary.get("security_engine_count") == 2,
        "four_distinct_connector_credentials": len({
            item.get("credential") for item in config.get("connectors") or []
            if item.get("type") == "chat_completions"}) == 4,
    }
    return {"checks": checks, "complete": all(checks.values())}


def evaluate_verdicts(report, targets):
    target = {item["id"]: item["requirements"] for item in targets["targets"]}
    warmup, measured = report.get("warmup") or {}, report.get("measurement") or {}
    samples = report.get("samples") or []
    rss = _series(report, ("guard", "process", "rss_kib"))
    egress_rss = _series(report, ("egress", "process", "rss_kib"))
    fds = _series(report, ("guard", "process", "fds"))
    threads = _series(report, ("guard", "process", "threads"))
    state = _series(report, ("guard", "paths", "/state", "bytes"))
    history = _series(report, ("status", "security_history", "records"))
    first_hour = [value for elapsed, value in rss if elapsed <= 3600]
    last_hour = ([value for elapsed, value in rss if elapsed >= rss[-1][0] - 3600]
                 if rss else [])
    warm_history = (((report.get("status_after_warmup") or {}).get("security_history") or {})
                    .get("records"))
    end_history = (((report.get("final_status") or {}).get("security_history") or {})
                   .get("records"))
    retention = retention_telemetry(report.get("final_status"))
    telemetry = sample_telemetry(report)
    warm_counters = (report.get("counter_validation") or {}).get("warmup") or {}
    measured_counters = (report.get("counter_validation") or {}).get("measurement") or {}
    status_config = (report.get("final_status") or {}).get("config") or {}
    identities = identity_checks(report)
    required_measurements = {
        "warmup": warmup.get("actual_calls"), "measurement": measured.get("actual_calls"),
        "p95": measured.get("total_p95_ms"), "p99": measured.get("total_p99_ms"),
        "window_p99": measured.get("window_p99_ms_max"), "guard_rss": max(
            (value for _, value in rss), default=None), "egress_rss": max(
            (value for _, value in egress_rss), default=None), "fds": max(
            (value for _, value in fds), default=None), "threads": max(
            (value for _, value in threads), default=None), "state": max(
            (value for _, value in state), default=None), "warm_history": warm_history,
        "end_history": end_history,
        "retention": retention.get("complete") if retention.get("complete") is True else None,
        "audit_verify": report.get("audit_verify"),
        "outcome_archives": report.get("outcome_archives"),
        "warm_counters": warm_counters.get("complete"),
        "measurement_counters": measured_counters.get("complete"),
        "evidence": identities.get("complete"), "samples": samples or None,
        "topology": (report.get("topology_validation") or {}).get("complete"),
        "sample_telemetry": telemetry.get("complete") if telemetry.get("complete") is True else None,
        "progress_file": report.get("progress_file"),
        "measurement_supervision": (True
                                    if report.get("measurement_timed_out") is False else None),
    }
    missing = sorted(key for key, value in required_measurements.items() if value is None)
    missing = sorted(set(missing + retention.get("missing", [])
                         + telemetry.get("missing", [])))
    ae01 = target["AE-01"]
    ae02 = target["AE-02"]
    ae03 = target["AE-03"]
    ae04 = target["AE-04"]
    ae05 = target["AE-05"]
    ae06 = target["AE-06"]
    ae07 = target["AE-07"]
    verdicts = {
        "AE-01": {"passed": bool(
            report.get("full_acceptance_eligible") is True and warmup.get("complete") is True
            and warmup.get("actual_calls") == ae01["warmup_calls_exact"]
            and warmup.get("successful_calls") == ae01["warmup_calls_exact"]
            and warmup.get("error_calls") == 0
            and measured.get("complete") is True
            and measured.get("actual_calls") == ae01["measured_calls_exact"]
            and measured.get("successful_calls") == ae01["successful_calls_exact"]
            and type(measured.get("error_calls")) is int
            and measured.get("error_calls") <= ae01["error_calls_max"]
            and measured.get("actors_complete") == ae01["actors_complete_exact"]
            and report.get("duration_seconds") == ae01["duration_seconds_exact"]
            and type(report.get("actual_measurement_elapsed_seconds")) in (int, float)
            and report["actual_measurement_elapsed_seconds"] >= ae01["duration_seconds_exact"]),
            "measured": {"warmup_calls": warmup.get("actual_calls"),
                         "warmup_successful_calls": warmup.get("successful_calls"),
                         "warmup_error_calls": warmup.get("error_calls"),
                         "measured_calls": measured.get("actual_calls"),
                         "successful_calls": measured.get("successful_calls"),
                         "error_calls": measured.get("error_calls"),
                         "actors_complete": measured.get("actors_complete"),
                         "duration_seconds": report.get("duration_seconds"),
                         "actual_elapsed_seconds": report.get("actual_measurement_elapsed_seconds")}},
        "AE-02": {"passed": bool(
            type(measured.get("total_p95_ms")) in (int, float)
            and math.isfinite(measured["total_p95_ms"])
            and measured["total_p95_ms"] <= ae02["p95_ms_max"]
            and type(measured.get("total_p99_ms")) in (int, float)
            and math.isfinite(measured["total_p99_ms"])
            and measured["total_p99_ms"] <= ae02["p99_ms_max"]
            and type(measured.get("window_p99_ms_max")) in (int, float)
            and math.isfinite(measured["window_p99_ms_max"])
            and measured["window_p99_ms_max"] <= ae02["window_p99_ms_max"]),
            "measured": {"p95_ms": measured.get("total_p95_ms"),
                         "p99_ms": measured.get("total_p99_ms"),
                         "window_p99_ms_max": measured.get("window_p99_ms_max")}},
        "AE-03": {"passed": bool(
            telemetry["complete"] is True and rss and egress_rss and first_hour and last_hour
            and max(value for _, value in rss) / 1024 <= ae03["guard_rss_mib_max"]
            and max(value for _, value in egress_rss) / 1024 <= ae03["egress_rss_mib_max"]
            and (max(last_hour) - max(first_hour)) / 1024
            <= ae03["last_hour_max_over_first_hour_max_mib"]),
            "measured": {"guard_rss_mib_max": round(max(
                (value for _, value in rss), default=0) / 1024, 3),
                         "egress_rss_mib_max": round(max(
                (value for _, value in egress_rss), default=0) / 1024, 3),
                         "first_hour_rss_mib_max": round(max(first_hour, default=0) / 1024, 3),
                         "last_hour_rss_mib_max": round(max(last_hour, default=0) / 1024, 3)}},
        "AE-04": {"passed": bool(
            telemetry["complete"] is True and fds and threads
            and max(value for _, value in fds) <= ae04["guard_fds_max"]
            and max(value for _, value in threads) <= ae04["guard_threads_max"]),
            "measured": {"guard_fds_max": max((value for _, value in fds), default=None),
                         "guard_threads_max": max((value for _, value in threads), default=None)}},
        "AE-05": {"passed": bool(
            telemetry["complete"] is True and history and state
            and max(value for _, value in history)
            <= ae05["security_history_records_max"]
            and warm_history == ae05["security_history_records_after_warmup_exact"]
            and end_history == ae05["security_history_records_at_end_exact"]
            and max(value for _, value in state) <= ae05["active_state_bytes_max"]),
            "measured": {"security_history_records_max": max(
                (value for _, value in history), default=None),
                         "security_history_records_after_warmup": warm_history,
                         "security_history_records_at_end": end_history,
                         "active_state_bytes_max": max((value for _, value in state), default=None)}},
        "AE-06": {"passed": bool(
            retention["complete"] is True
            and retention["failures"] <= ae06["retention_failures_max"]
            and (report.get("audit_verify") or {}).get("verified") is True
            and (report.get("outcome_archives") or {}).get("verified") is True),
            "measured": {"retention": retention,
                         "audit_verify": report.get("audit_verify"),
                         "outcome_archives": report.get("outcome_archives")}},
        "AE-07": {"passed": bool(
            warm_counters.get("complete") is True
            and measured_counters.get("complete") is True
            and status_config.get("security_engine_count")
            == ae07["configured_security_engines_exact"]),
            "measured": {"warmup": warm_counters, "measurement": measured_counters,
                         "configured_security_engines": status_config.get("security_engine_count")}},
        "AE-08": {"passed": identities["complete"] is True
            and len(missing) <= target["AE-08"]["missing_measurements_max"],
            "measured": {"identities": identities, "missing_measurements": missing}},
    }
    return verdicts


def short_smoke_verdict(report):
    warmup, measured = report.get("warmup") or {}, report.get("measurement") or {}
    counters = report.get("counter_validation") or {}
    supporting = report.get("verdicts") or {}
    expected = ACTORS * RATE_PER_ACTOR * report["duration_seconds"]
    checks = {
        "short_duration": report.get("full_acceptance_eligible") is False
            and MIN_SMOKE_DURATION_SECONDS <= report["duration_seconds"] < FULL_DURATION_SECONDS,
        "warmup_complete": warmup.get("complete") is True
            and warmup.get("actual_calls") == WARMUP_CALLS,
        "measurement_complete": measured.get("complete") is True
            and measured.get("actual_calls") == expected
            and measured.get("successful_calls") == expected
            and measured.get("error_calls") == 0,
        "phase_counters": all((counters.get(name) or {}).get("complete") is True
                              for name in ("warmup", "measurement")),
        "supporting_guardrails": all((supporting.get(name) or {}).get("passed") is True
                                     for name in ("AE-02", "AE-03", "AE-04", "AE-05",
                                                  "AE-06", "AE-07", "AE-08")),
        "full_acceptance_passed_false": report.get("full_acceptance_passed") is False,
    }
    return {"passed": all(checks.values()), "checks": checks,
            "expected_measured_calls": expected}


def execute(parameters, config, targets):
    plan = build_plan(parameters, config, targets)
    report = {
        "schema": "enkstein-guard.ai-security-endurance-report/v1",
        "run_class": plan["run_class"],
        "duration_seconds": parameters.duration_seconds,
        "full_acceptance_eligible": parameters.full_endurance,
        "full_acceptance_passed": False,
        "short_smoke_passed": False,
        "passed": False,
        "real_model_robustness": False,
        "synthetic_counter_fsync_overhead": True,
        "duplicate_execution_claim": False,
        "standard_p04_no_replay_is_separate": True,
        "plan": plan,
        "targets": str(TARGETS_PATH.relative_to(ROOT)),
        "target_binding": {"sha256": sha256_file(TARGETS_PATH),
                           "defined_at": targets["defined_at"],
                           "deployment_revision_sha256": None},
        "evidence": None,
        "ready": None,
        "topology_validation": None,
        "status_before_warmup": None,
        "status_after_warmup": None,
        "final_status": None,
        "warmup": None,
        "measurement": None,
        "measurement_timed_out": None,
        "actual_measurement_elapsed_seconds": None,
        "samples": [],
        "progress_file": None,
        "operator_retention_run": None,
        "upstream_counters": {"initial": None, "after_warmup": None,
                              "warmup_delta": None, "after_measurement": None,
                              "measurement_delta": None},
        "counter_validation": {"warmup": None, "measurement": None},
        "audit_verify": None,
        "outcome_archives": None,
        "verdicts": {},
        "short_smoke": None,
        "limitations": targets["limitations"],
    }
    deployment = None
    try:
        deployment = AISecurityEnduranceDeployment(parameters, config)
        report["progress_file"] = str(deployment.progress_path)
        ready = deployment.up()
        report["ready"] = ready
        if ready.get("ready") is not True:
            raise RuntimeError("guard_not_ready")
        report["evidence"] = deployment.header("production-ai-security-endurance")
        report["target_binding"]["deployment_revision_sha256"] = (
            ((report["evidence"].get("revision") or {}).get("deployment") or {}).get("sha256"))
        report["status_before_warmup"] = deployment.status()
        report["topology_validation"] = topology_checks(
            config, ready, report["status_before_warmup"])
        if report["topology_validation"]["complete"] is not True:
            raise RuntimeError("endurance_topology_incomplete")
        initial = deployment.upstream_counters()
        report["upstream_counters"]["initial"] = initial
        expected_warm = {item["id"]: PER_ACTOR_HISTORY for item in config["agents"]}
        warmup = aggregate_phase(deployment.warmup(), expected_warm, "warmup",
                                 parameters.duration_seconds)
        after_warmup = deployment.upstream_counters()
        warm_delta = upstream_counter_delta(initial, after_warmup)
        warm_validation = counter_checks(warm_delta, warmup)
        report["warmup"] = warmup
        report["status_after_warmup"] = deployment.status()
        report["upstream_counters"].update(after_warmup=after_warmup,
                                           warmup_delta=warm_delta)
        report["counter_validation"]["warmup"] = warm_validation
        occupancy = ((report["status_after_warmup"] or {}).get("security_history") or {}).get("records")
        if (not warmup["complete"] or warmup["actual_calls"] != WARMUP_CALLS
                or warmup["successful_calls"] != WARMUP_CALLS
                or not warm_validation["complete"] or occupancy != HISTORY_CAPACITY):
            raise RuntimeError("warmup_incomplete")
        results, samples, operator_run, elapsed, timed_out = deployment.measurement()
        measured = aggregate_phase(
            results,
            {item["id"]: parameters.measured_calls_per_actor for item in config["agents"]},
            "measurement", parameters.duration_seconds)
        after_measurement = deployment.upstream_counters()
        measured_delta = upstream_counter_delta(after_warmup, after_measurement)
        measured_validation = counter_checks(measured_delta, measured)
        report.update(measurement=measured, samples=samples,
                      operator_retention_run=operator_run,
                      actual_measurement_elapsed_seconds=elapsed,
                      measurement_timed_out=timed_out)
        report["upstream_counters"].update(after_measurement=after_measurement,
                                           measurement_delta=measured_delta)
        report["counter_validation"]["measurement"] = measured_validation
        report["final_status"] = deployment.status()
        audit_code, audit = deployment.guard_cli(
            "audit", "verify", "--with-archives", check=False, timeout=1800)
        archive_code, archives = deployment.guard_cli(
            "outcomes", "verify-archives", check=False, timeout=1800)
        report["audit_verify"] = {"exit": audit_code,
                                  "verified": audit_code == 0 and audit.get("status") == "ok",
                                  "result": audit}
        report["outcome_archives"] = {"exit": archive_code,
                                      "verified": archive_code == 0
                                      and archives.get("verified") is True,
                                      "result": archives}
        if timed_out:
            raise RuntimeError("measurement_deadline_exceeded")
    except Exception as error:
        detail = str(error)
        report["error"] = type(error).__name__ + ":" + (
            deployment.redact(detail) if deployment is not None else detail)[-2000:]
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
                report["cleanup_error"] = (type(error).__name__ + ":"
                                           + deployment.redact(str(error))[-1000:])
    try:
        report["verdicts"] = evaluate_verdicts(report, targets)
    except Exception as error:
        detail = type(error).__name__ + ":" + str(error)[-1000:]
        report["verdict_evaluation_error"] = detail
        report["verdicts"] = {
            identifier: {"passed": False, "measured": {"evaluation_error": detail}}
            for identifier in EXPECTED_REQUIREMENTS}
    all_targets = len(report["verdicts"]) == len(EXPECTED_REQUIREMENTS) and all(
        item["passed"] for item in report["verdicts"].values())
    report["full_acceptance_passed"] = bool(
        parameters.full_endurance and all_targets
        and "error" not in report and "cleanup_error" not in report)
    if parameters.explicit_duration:
        report["short_smoke"] = short_smoke_verdict(report)
        report["short_smoke_passed"] = bool(
            report["short_smoke"]["passed"]
            and "error" not in report and "cleanup_error" not in report)
    report["passed"] = report["full_acceptance_passed"]
    output = write_report(FULL_REPORT if parameters.full_endurance else SMOKE_REPORT, report)
    print(json.dumps({
        "run_class": report["run_class"], "report": str(output),
        "full_acceptance_passed": report["full_acceptance_passed"],
        "short_smoke_passed": report["short_smoke_passed"],
        "verdicts": {key: value["passed"] for key, value in report["verdicts"].items()},
        "error": report.get("error"),
    }, sort_keys=True))
    success = (report["full_acceptance_passed"] if parameters.full_endurance
               else report["short_smoke_passed"])
    return 0 if success else 1


def argument_parser():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="validate and print plan (default)")
    mode.add_argument("--run", action="store_true", help="explicitly execute disposable Compose run")
    parser.add_argument(
        "--duration", type=int,
        help="explicit 30..10799 second smoke/harness check; never full acceptance")
    return parser


def main(argv=None):
    args = argument_parser().parse_args(argv)
    parameters = EnduranceParameters(
        duration_seconds=(FULL_DURATION_SECONDS if args.duration is None else args.duration),
        explicit_duration=args.duration is not None)
    targets = load_targets()
    config = endurance_config()
    if not args.run:
        print(json.dumps(build_plan(parameters, config, targets), indent=2, sort_keys=True))
        return 0
    return execute(parameters, config, targets)


if __name__ == "__main__":
    raise SystemExit(main())
