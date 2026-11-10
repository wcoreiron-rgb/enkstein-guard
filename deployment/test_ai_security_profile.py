"""Synthetic production-profile acceptance for configured AI enforcement.

This module performs no Docker work at import time. Execute it explicitly only
after the staged wheel and image exist. It uses a disposable Compose project,
synthetic credentials, and the local TLS fixture; it is not a live-model test.
"""

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sys


os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deployment"))
sys.path.insert(0, str(ROOT / "tools"))

import evidence  # noqa: E402
from production_harness import (  # noqa: E402
    Deployment as ProductionDeployment,
    IMAGE,
    NETWORKS,
    capacity_config,
    write_report,
)


REPORT = "container-ai-security-profile"
SENSITIVE_CARD = "4111111111111111"
SENSITIVE_KEY = "sk-" + "Z" * 32
EXPECTED_CHECKS = frozenset({
    "guard_ready", "peer_bound_active", "guard_network_none", "independent_egress_proxy_healthy",
    "two_security_engines_configured", "no_internal_inspector_agent_grant", "separate_agent_uids",
    "same_allowed_tls_provider_host", "agents_ran_as_separate_uids",
    "inspection_and_business_calls_counted_separately", "only_fixed_models_used",
    "all_calls_used_fixed_tls_path", "intended_broker_headers_valid",
    "business_and_inspection_credentials_separate", "broker_secrets_absent_from_bodies",
    "numeric_card_and_sk_secret_absent_from_all_bodies",
    "sensitive_business_refs_and_inspection_opaque_markers",
    "denied_assessments_never_reached_business_target", "benign_requests_reached_business_target",
    "identity_schema_recorded", "identity_image_recorded", "identity_wheel_recorded",
    "identity_installed_matches_wheel", "identity_dependency_lock_matches",
    "identity_configuration_hash_and_policy_recorded", "identity_revision_recorded",
    "agent_a_deny_critical_malformed_low_confidence_blocked", "agent_a_sensitive_valid_request_allowed",
    "agent_a_benign_allowed", "agent_a_internal_inspector_not_agent_callable",
    "agent_a_cross_tenant_route_denied", "agent_a_egress_socket_absent", "agent_a_guard_state_absent",
    "agent_a_direct_network_denied", "agent_b_benign_allowed",
    "agent_b_internal_inspector_not_agent_callable", "agent_b_cross_tenant_route_denied",
    "agent_b_egress_socket_absent", "agent_b_guard_state_absent", "agent_b_direct_network_denied",
})

_NATIVE_REFERENCE = re.compile(r"\[\[EGV:[a-f0-9]{64}\]\]")
_PROTECTED_REFERENCE = re.compile(r"protected-reference:[a-f0-9]{64}")


def sensitive_reference_boundary(records):
    """Native refs reach only the target; inspection gets non-restorable hashes."""
    sensitive = [item for item in records if "scenario:sensitive" in json.dumps(item.get("body"))]
    business = [item for item in sensitive if item.get("kind") == "business"]
    inspection = [item for item in sensitive if item.get("kind") == "inspection"]
    if len(business) != 1 or len(inspection) != 1:
        return False
    business_body = json.dumps(business[0]["body"], sort_keys=True)
    inspection_body = json.dumps(inspection[0]["body"], sort_keys=True)
    native = set(_NATIVE_REFERENCE.findall(business_body))
    return (len(native) >= 2 and _PROTECTED_REFERENCE.search(inspection_body) is not None
            and _NATIVE_REFERENCE.search(inspection_body) is None
            and all(reference not in inspection_body for reference in native))


def ai_security_config():
    """Two tenant-bound business routes and two ungranted inspector routes."""
    config = capacity_config(rate=10, capacity=100_000, archive_age=7_200,
                             archive_interval=600, agents_per_tenant=1)
    connectors = [{"name": "kb", "type": "retrieval_local", "collection": "kb"}]
    routes, engines, agents = [], [], []
    for position, tenant in enumerate(("a", "b"), start=1):
        connectors.extend([
            {"name": "business-" + tenant, "type": "chat_completions",
             "endpoint": "https://upstream.acceptance.test/v1/chat/completions",
             "model": "synthetic-model", "credential": "business-key-" + tenant,
             "authentication": "x-api-key", "ca_file": "/bootstrap/ca.pem",
             "data_domain": "acceptance-upstream"},
            {"name": "security-" + tenant, "type": "chat_completions",
             "endpoint": "https://upstream.acceptance.test/v1/chat/completions",
             "model": "synthetic-security", "credential": "security-key-" + tenant,
             "authentication": "x-api-key", "ca_file": "/bootstrap/ca.pem",
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
                        "timeout_seconds": 1.5, "confidence_threshold": 0.7,
                        "failure_action": "deny"})
        agents.append({"id": "agent-" + tenant, "tenant": tenant,
                       "principal": tenant + "-bot", "uid": 11_000 + position,
                       "clearance": "internal", "routes": [tenant + ".business"]})
    config.update({"connectors": connectors, "routes": routes, "security_engines": engines,
                   "security_history": {"capacity": 256, "ttl_seconds": 3600,
                                        "per_actor_capacity": 32},
                   "agents": agents, "approvers": [],
                   "backend_inventory": {"schema_version": 1, "backends": [{
                       "backend_id": "acceptance-upstream", "account_id": "synthetic-shared",
                       "data_domain": "acceptance-upstream", "tenants": ["a", "b"],
                       "hosts": ["https://upstream.acceptance.test"]}]},
                   "egress": {"mode": "proxy", "socket": "/run/guard-egress/egress.sock",
                              "client_uids": [10001], "socket_group": 10003,
                              "allow": [{"host": "upstream.acceptance.test", "port": 443,
                                         "addresses": NETWORKS}]}})
    config["service"]["control_timeout_seconds"] = 5
    return config


class AISecurityDeployment(ProductionDeployment):
    def __init__(self):
        overlay = ROOT / "deployment/acceptance/ai_security_compose.yaml"
        super().__init__(ai_security_config(), label="ai-security", overlays=(overlay,),
                         upstream_mode="capture", project_prefix="egai")

    def acceptance_agent(self, tenant):
        agent = next(item for item in self.config["agents"] if item["tenant"] == tenant)
        script = ROOT / "deployment/acceptance/ai_security_agent.py"
        token = self.run / "credentials" / (agent["id"] + ".token")
        result = self.compose(
            "run", "--rm", "--no-deps", "-T", "--user", "%d:10001" % agent["uid"],
            "-v", str(script) + ":/ai_security_agent.py:ro",
            "-v", str(token) + ":/run/agent-token:ro",
            "--entrypoint", "python", "agent", "/ai_security_agent.py", tenant,
            check=False, timeout=180,
        )
        lines = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        if result.returncode or not lines:
            raise RuntimeError("agent_%s_failed:%s" % (tenant, self.redact(result.stderr[-1000:])))
        return lines[-1]

    def capture(self):
        output = self.compose("exec", "-T", "upstream", "cat", "/capture/ai-security-requests.jsonl",
                              check=False, timeout=60).stdout
        return [json.loads(line) for line in output.splitlines() if line.strip()]

    def _identity_checks(self, identity):
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
            "identity_configuration_hash_and_policy_recorded": bool(configurations)
                and all(item.get("sha256") and item.get("policy_version") for item in configurations),
            "identity_revision_recorded": all((revision.get(name) or {}).get("sha256")
                                                for name in ("source", "tests", "tools", "deployment")),
        }

    def run_all(self):
        ready = self.up()
        checks = {"guard_ready": ready.get("ready") is True}
        status = self.status() or {}
        checks.update({
            "peer_bound_active": status.get("peer_bound") is True,
            "guard_network_none": (status.get("preflight") or {}).get("network_interfaces") == ["lo"],
            "independent_egress_proxy_healthy": (status.get("preflight") or {}).get("egress_proxy_healthy") is True,
            "two_security_engines_configured": (status.get("config") or {}).get("security_engine_count") == 2,
            "no_internal_inspector_agent_grant": all(
                tenant + ".security.inspect" not in agent["routes"]
                for tenant, agent in zip(("a", "b"), self.config["agents"])),
            "separate_agent_uids": len({agent["uid"] for agent in self.config["agents"]}) == 2,
            "same_allowed_tls_provider_host": len({connector.get("endpoint") for connector in self.config["connectors"]
                                                    if connector["type"] == "chat_completions"}) == 1,
        })

        agents = {tenant: self.acceptance_agent(tenant) for tenant in ("a", "b")}
        for tenant, result in agents.items():
            checks.update({"agent_%s_%s" % (tenant, name): passed
                           for name, passed in result["checks"].items()})
        checks["agents_ran_as_separate_uids"] = [agents[t]["uid"] for t in ("a", "b")] == [11001, 11002]

        records = self.capture()
        inspections = [item for item in records if item.get("kind") == "inspection"]
        business = [item for item in records if item.get("kind") == "business"]
        checks["inspection_and_business_calls_counted_separately"] = len(inspections) == 7 and len(business) == 3
        checks["only_fixed_models_used"] = ({item.get("model") for item in inspections} == {"synthetic-security"}
                                             and {item.get("model") for item in business} == {"synthetic-model"})
        checks["all_calls_used_fixed_tls_path"] = bool(records) and all(
            item.get("method") == "POST" and item.get("path") == "/v1/chat/completions" for item in records)

        expected = Counter()
        for tenant, inspect_count, business_count in (("a", 6, 2), ("b", 1, 1)):
            expected[hashlib.sha256(self.secrets["security-key-" + tenant].encode()).hexdigest()] = inspect_count
            expected[hashlib.sha256(self.secrets["business-key-" + tenant].encode()).hexdigest()] = business_count
        observed = Counter(item.get("api_key_sha256") for item in records)
        checks["intended_broker_headers_valid"] = observed == expected and all(
            "x-api-key" in item.get("header_names", ()) for item in records)
        checks["business_and_inspection_credentials_separate"] = len(self.secrets) == 4 and len(set(self.secrets.values())) == 4

        capture_json = json.dumps(records, sort_keys=True)
        checks["broker_secrets_absent_from_bodies"] = all(secret not in capture_json for secret in self.secrets.values())
        checks["numeric_card_and_sk_secret_absent_from_all_bodies"] = (
            SENSITIVE_CARD not in capture_json and SENSITIVE_KEY not in capture_json)
        checks["sensitive_business_refs_and_inspection_opaque_markers"] = sensitive_reference_boundary(records)
        denied_markers = ("scenario:deny", "scenario:critical", "scenario:malformed", "scenario:low-confidence")
        checks["denied_assessments_never_reached_business_target"] = not any(
            marker in json.dumps(item["body"]) for item in business for marker in denied_markers)
        checks["benign_requests_reached_business_target"] = sum(
            "scenario:benign" in json.dumps(item["body"]) for item in business) == 2

        identity = self.header(REPORT)
        checks.update(self._identity_checks(identity))
        for name in EXPECTED_CHECKS:
            checks.setdefault(name, False)
        report = {
            "evidence": identity,
            "image": IMAGE,
            "checks": checks,
            "passed": all(checks.values()),
            "details": {"http_calls": {"inspection": len(inspections), "business": len(business)},
                        "agent_statuses": {tenant: value["statuses"] for tenant, value in agents.items()}},
            "scope": "Synthetic provider/control wiring and tenant isolation on one production-profile Docker host; not live-model robustness.",
            "limitations": ["Synthetic TLS provider and credentials only", "No claim about real-model semantic robustness"],
        }
        return report


def main():
    deployment = AISecurityDeployment()
    try:
        report = deployment.run_all()
    except Exception as error:
        report = {"evidence": None, "image": IMAGE,
                  "checks": {name: False for name in sorted(EXPECTED_CHECKS)}, "passed": False,
                  "error": deployment.redact(str(error))[-3000:],
                  "scope": "Synthetic provider/control wiring and tenant isolation; acceptance did not complete."}
        try:
            report["diagnostic_logs"] = deployment.logs()
        except Exception:
            pass
    finally:
        deployment.down()
    output = write_report(REPORT + ".json", report)
    print(json.dumps({"passed": report["passed"],
                      "failed": [name for name, passed in report["checks"].items() if not passed],
                      "report": str(output), "error": report.get("error")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

