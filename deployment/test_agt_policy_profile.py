"""Opt-in physical deployment acceptance for optional local AGT policy.

Importing this module and running it without ``--run`` perform no Docker work.
The eventual explicit run uses synthetic credentials and a local TLS upstream;
it is not live-vendor, model-robustness, or general production acceptance.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys


os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deployment"))
sys.path.insert(0, str(ROOT / "tools"))

import evidence  # noqa: E402
from production_harness import (  # noqa: E402
    Deployment as ProductionDeployment,
    IMAGE,
    capacity_config,
    write_report,
)


REPORT = "container-agt-policy-profile"
PLAN_SCHEMA = "enkstein-guard.agt-policy-deployment-plan/v1"
SOURCE_VALIDATION_CONTEXT = "source_bootstrap_only_not_installed_candidate"
SENSITIVE_CARD = "4111111111111111"
SENSITIVE_KEY = "sk-" + "Z" * 32
AGT_POLICY_MODULE_SHA256 = "d7a4b68c5985fb5c784e4311176880400b1072299951cd6de7ae983b02a9a3fd"
AGENT_CHECKS = frozenset({
    "allowed_request_reached_provider",
    "int_mismatch_denied", "missing_denied", "null_denied", "bool_denied",
    "float_denied", "string_denied", "cross_tenant_denied",
    "ungranted_route_denied", "payload_identity_spoof_denied",
    "deterministic_privacy_denial_authoritative", "egress_socket_absent",
    "guard_state_absent", "direct_network_denied",
})
EXPECTED_CHECKS = frozenset({
    "guard_ready", "peer_bound_active", "guard_network_none",
    "independent_egress_proxy_healthy", "two_policy_engines_configured",
    "policy_engines_active", "agt_required_controls_active",
    "pinned_agt_distribution_and_api_probed", "separate_agent_uids",
    "agents_ran_as_separate_uids", "two_tenant_tokenized_fixed_routes",
    "fixed_broker_endpoint_model_credentials",
    "agt_added_no_network_calls", "exact_allowed_upstream_count",
    "only_allowed_scenarios_reached_upstream", "only_fixed_model_used",
    "all_calls_used_fixed_tls_path", "intended_broker_headers_valid",
    "tenant_credentials_separate", "broker_secrets_absent_from_bodies",
    "numeric_card_and_secret_absent_from_all_bodies",
    "identity_schema_recorded", "identity_image_recorded",
    "identity_wheel_recorded", "identity_installed_matches_wheel",
    "identity_dependency_lock_matches",
    "identity_configuration_hash_and_policy_recorded",
    "identity_revision_recorded",
    *{"agent_%s_%s" % (tenant, name)
      for tenant in ("a", "b") for name in AGENT_CHECKS},
})


def agt_policy_config():
    """Two tenants, one peer-bound agent and tokenized AGT route each."""
    config = capacity_config(
        rate=10, capacity=100_000, archive_age=7_200,
        archive_interval=600, agents_per_tenant=1)
    config["connectors"] = [
        connector for connector in config["connectors"]
        if connector["name"] in {"model-a", "model-b"}
    ]
    config["routes"] = [
        route for route in config["routes"]
        if route["name"] in {"a.model", "b.model"}
    ]
    policy_engines = []
    for tenant in ("a", "b"):
        route = next(item for item in config["routes"] if item["tenant"] == tenant)
        route["policy_engine"] = "gate-" + tenant
        agent = next(item for item in config["agents"] if item["tenant"] == tenant)
        agent["routes"] = [tenant + ".model"]
        policy_engines.append({
            "name": "gate-" + tenant, "kind": "agt", "tenant": tenant,
            "bindings": [{
                "agent": agent["id"], "route": tenant + ".model",
                "conditions": [{"field": "max_tokens", "operator": "eq", "value": 64}],
            }],
        })
    config["policy_engines"] = policy_engines
    config["service"]["control_timeout_seconds"] = 5
    return config


def exact_checks_passed(checks):
    return set(checks) == EXPECTED_CHECKS and all(value is True for value in checks.values())


def valid_agt_image_probe(packages, probe):
    digest = probe.get("module_sha256")
    return (packages.get("agent-governance-toolkit-control-plane") == "5.0.0"
            and probe.get("version") == "5.0.0"
            and probe.get("site_packages") is True
            and probe.get("api_probe") is True
            and digest == AGT_POLICY_MODULE_SHA256)


def plan():
    config = agt_policy_config()
    return {
        "schema": PLAN_SCHEMA,
        "docker_executed": False,
        "explicit_run_required": True,
        "evidence_class": "physical_deployment_acceptance_pending_execution",
        "source_validation_context": SOURCE_VALIDATION_CONTEXT,
        "parameters": {
            "tenants": len(config["tenants"]), "agents": len(config["agents"]),
            "routes": len(config["routes"]), "policy_engines": len(config["policy_engines"]),
            "agent_calls": 22, "expected_upstream_calls": 2,
        },
        "expected_checks": sorted(EXPECTED_CHECKS),
        "production_accepted": False,
        "live_vendor_integration": False,
    }


class AGTPolicyDeployment(ProductionDeployment):
    def __init__(self):
        super().__init__(agt_policy_config(), label="agt-policy",
                         upstream_mode="capture", project_prefix="egagt")

    def acceptance_agent(self, tenant):
        agent = next(item for item in self.config["agents"] if item["tenant"] == tenant)
        script = ROOT / "deployment/acceptance/agt_policy_agent.py"
        token = self.run / "credentials" / (agent["id"] + ".token")
        result = self.compose(
            "run", "--rm", "--no-deps", "-T", "--user", "%d:10001" % agent["uid"],
            "-v", str(script) + ":/agt_policy_agent.py:ro",
            "-v", str(token) + ":/run/agent-token:ro",
            "--entrypoint", "python", "agent", "/agt_policy_agent.py", tenant,
            check=False, timeout=180)
        lines = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        if result.returncode or not lines:
            raise RuntimeError(
                "agent_%s_failed:%s" % (tenant, self.redact(result.stderr[-1000:])))
        return lines[-1]

    def capture(self):
        output = self.compose(
            "exec", "-T", "upstream", "cat", "/capture/requests.jsonl",
            check=False, timeout=60).stdout
        return [json.loads(line) for line in output.splitlines() if line.strip()]

    def agt_image_probe(self):
        """Probe the imported SDK and frozen allow/deny API inside the image."""
        script = r'''
import hashlib, json
from importlib import metadata
from pathlib import Path
result = {"version": None, "module_sha256": None, "site_packages": False, "api_probe": False}
try:
    import agent_control_plane.policy_engine as module
    from agent_control_plane.policy_engine import Condition, ConditionalPermission, PolicyEngine
    path = Path(module.__file__).resolve()
    role = '["probe"]'
    conditions = [Condition("args.max_tokens", "eq", 64)]
    permission = ConditionalPermission("probe", conditions)
    engine = PolicyEngine()
    engine.add_constraint(role, ["probe"])
    engine.add_conditional_permission(role, permission)
    engine.freeze()
    allowed = engine.check_violation(role, "probe", {"max_tokens": 64})
    denied = engine.check_violation(role, "probe", {"max_tokens": 63})
    result.update(
        version=metadata.version("agent-governance-toolkit-control-plane"),
        module_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        site_packages="site-packages" in path.parts or "dist-packages" in path.parts,
        api_probe=(engine.is_frozen is True and engine.is_shadow_mode(role) is False
                   and allowed is None and isinstance(denied, str)),
    )
except Exception:
    pass
print(json.dumps(result, sort_keys=True))
'''
        result = self.compose(
            "exec", "-T", "guard", "python", "-c", script,
            check=False, timeout=60)
        lines = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        return lines[-1] if result.returncode == 0 and lines else {}

    @staticmethod
    def _identity_checks(identity):
        candidate = identity.get("candidate") or {}
        image = identity.get("image") or {}
        lock = (identity.get("dependencies") or {}).get("lock") or {}
        configurations = identity.get("configuration") or []
        revision = identity.get("revision") or {}
        return {
            "identity_schema_recorded": identity.get("schema") == evidence.SCHEMA,
            "identity_image_recorded": bool(image.get("id")),
            "identity_wheel_recorded": bool(candidate.get("wheel_sha256")),
            "identity_installed_matches_wheel": candidate.get("installed_matches_wheel") is True,
            "identity_dependency_lock_matches": lock.get("matches_lock") is True,
            "identity_configuration_hash_and_policy_recorded": bool(configurations) and all(
                item.get("sha256") and item.get("policy_version") for item in configurations),
            "identity_revision_recorded": all(
                (revision.get(name) or {}).get("sha256")
                for name in ("source", "tests", "tools", "deployment")),
        }

    def run_all(self):
        ready = self.up()
        status = self.status() or {}
        _, policy = self.guard_cli("policy", "explain", check=False, timeout=120)
        _, doctor = self.guard_cli("doctor", check=False, timeout=120)
        summary = status.get("config") or {}
        engines = summary.get("policy_engines") or []
        routes = policy.get("routes") or []
        packages = doctor.get("installed_packages_not_activation_status") or {}
        agt_probe = self.agt_image_probe()
        checks = {
            "guard_ready": ready.get("ready") is True,
            "peer_bound_active": status.get("peer_bound") is True,
            "guard_network_none": (status.get("preflight") or {}).get("network_interfaces") == ["lo"],
            "independent_egress_proxy_healthy": (
                status.get("preflight") or {}).get("egress_proxy_healthy") is True,
            "two_policy_engines_configured": summary.get("policy_engine_count") == 2,
            "policy_engines_active": len(engines) == 2 and all(
                item.get("stage") == "active" for item in engines),
            "agt_required_controls_active": (
                (doctor.get("controls") or {}).get("agt_policy_engine", {}).get("state") == "active"
                and len(routes) == 2
                and all("agt.gate-" + route["tenant"] in route.get("required_controls", ())
                        for route in routes)),
            "pinned_agt_distribution_and_api_probed": valid_agt_image_probe(
                packages, agt_probe),
            "separate_agent_uids": len({agent["uid"] for agent in self.config["agents"]}) == 2,
            "two_tenant_tokenized_fixed_routes": len(self.config["routes"]) == 2 and all(
                route["privacy"] == "tokenize" and route["name"] == route["tenant"] + ".model"
                and route["policy_engine"] == "gate-" + route["tenant"]
                for route in self.config["routes"]),
            "fixed_broker_endpoint_model_credentials": {
                (connector["name"], connector.get("endpoint"), connector.get("model"),
                 connector.get("credential"), connector.get("authentication"))
                for connector in self.config["connectors"]
            } == {
                ("model-a", "https://upstream.acceptance.test/v1/chat/completions",
                 "synthetic-model", "key-a", "x-api-key"),
                ("model-b", "https://upstream.acceptance.test/v1/chat/completions",
                 "synthetic-model", "key-b", "x-api-key"),
            },
        }

        agent_results = {tenant: self.acceptance_agent(tenant) for tenant in ("a", "b")}
        for tenant, result in agent_results.items():
            result_checks = result.get("checks") or {}
            for name in AGENT_CHECKS:
                checks["agent_%s_%s" % (tenant, name)] = result_checks.get(name) is True
        checks["agents_ran_as_separate_uids"] = [
            agent_results[tenant].get("uid") for tenant in ("a", "b")] == [11001, 11002]

        records = self.capture()
        capture_json = json.dumps(records, sort_keys=True)
        checks["exact_allowed_upstream_count"] = len(records) == 2
        checks["agt_added_no_network_calls"] = len(records) == 2
        checks["only_allowed_scenarios_reached_upstream"] = (
            sum("scenario:allowed-a" in json.dumps(item.get("body")) for item in records) == 1
            and sum("scenario:allowed-b" in json.dumps(item.get("body")) for item in records) == 1
            and not any("scenario:" in json.dumps(item.get("body"))
                        and "scenario:allowed-" not in json.dumps(item.get("body"))
                        for item in records))
        checks["only_fixed_model_used"] = bool(records) and all(
            (item.get("body") or {}).get("model") == "synthetic-model"
            and (item.get("body") or {}).get("stream") is False
            and (item.get("body") or {}).get("max_tokens") == 64
            for item in records)
        checks["all_calls_used_fixed_tls_path"] = bool(records) and all(
            item.get("method") == "POST" and item.get("path") == "/v1/chat/completions"
            for item in records)
        expected_headers = Counter(
            hashlib.sha256(self.secrets["key-" + tenant].encode()).hexdigest()
            for tenant in ("a", "b"))
        observed_headers = Counter(item.get("api_key_sha256") for item in records)
        checks["intended_broker_headers_valid"] = observed_headers == expected_headers and all(
            "x-api-key" in item.get("header_names", ()) for item in records)
        checks["tenant_credentials_separate"] = (
            len(self.secrets) == 2 and len(set(self.secrets.values())) == 2)
        checks["broker_secrets_absent_from_bodies"] = all(
            secret not in capture_json for secret in self.secrets.values())
        checks["numeric_card_and_secret_absent_from_all_bodies"] = (
            SENSITIVE_CARD not in capture_json and SENSITIVE_KEY not in capture_json)

        identity = self.header(REPORT)
        checks.update(self._identity_checks(identity))
        for name in EXPECTED_CHECKS:
            checks.setdefault(name, False)
        report = {
            "evidence": identity, "image": IMAGE, "checks": checks,
            "passed": exact_checks_passed(checks),
            "details": {
                "upstream_calls": len(records),
                "agt_image_probe": agt_probe,
                "agent_statuses": {tenant: result.get("statuses")
                                   for tenant, result in agent_results.items()},
            },
            "scope": (
                "Synthetic physical deployment wiring for optional local AGT policy; "
                "not live-vendor, live-model, or general production acceptance."),
            "limitations": [
                "Acceptance is bounded to this executed candidate and configuration",
                "Synthetic TLS provider and credentials only",
                "AGT evaluation is local and makes no model or network call",
                "No missing-SDK image mutation, musl claim, or live vendor service",
            ],
        }
        return report


def execute():
    deployment = AGTPolicyDeployment()
    report = None
    try:
        report = deployment.run_all()
    except Exception as error:
        report = {
            "evidence": None, "image": IMAGE,
            "checks": {name: False for name in sorted(EXPECTED_CHECKS)},
            "passed": False, "error": deployment.redact(str(error))[-3000:],
            "scope": "Synthetic local AGT deployment acceptance did not complete.",
        }
        try:
            report["diagnostic_logs"] = deployment.logs()
        except Exception:
            pass
        try:
            report["evidence"] = deployment.header(REPORT)
        except Exception:
            pass
    finally:
        try:
            if report is not None and report.get("passed") is True:
                deployment.down()
            else:
                # Failed state and the exact bootstrap config remain reviewable.
                # Stop only our project; do not delete its volumes or run directory.
                stopped = deployment.compose("stop", check=False)
                if report is not None:
                    report["retained_failed_run"] = {
                        "project": deployment.project, "directory": str(deployment.run),
                        "volumes_preserved": True, "stop_returncode": stopped.returncode,
                    }
        except Exception as error:
            if report is not None:
                report["passed"] = False
                report["cleanup_error"] = deployment.redact(str(error))[-1000:]
    output = write_report(REPORT + ".json", report)
    print(json.dumps({
        "passed": report["passed"],
        "failed": [name for name, passed in report["checks"].items() if passed is not True],
        "report": str(output), "error": report.get("error"),
    }, sort_keys=True))
    return 0 if report["passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="execute Docker deployment acceptance explicitly")
    arguments = parser.parse_args(argv)
    if not arguments.run:
        print(json.dumps(plan(), sort_keys=True))
        return 0
    return execute()


if __name__ == "__main__":
    raise SystemExit(main())
