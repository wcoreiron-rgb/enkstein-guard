"""Container acceptance for the production-linux-peer-bound CLI profile.

Builds nothing: requires GUARD_TEST_IMAGE (default enkstein-guard:<source version>).
Uses synthetic credentials, a synthetic TLS upstream and a disposable Compose
project; only that project's containers and volumes are removed. Writes
container-production-profile.json into the candidate's evidence directory.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import evidence  # noqa: E402
IMAGE = os.environ.get("GUARD_TEST_IMAGE", evidence.IMAGE_TAG)
SYNTHETIC_KEY = "synthetic-upstream-key-" + secrets.token_hex(8)


def certificates(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Enkstein Guard acceptance CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upstream.acceptance.test")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("upstream.acceptance.test")]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (directory / "upstream").mkdir(mode=0o755)
    (directory / "upstream/cert.pem").write_bytes(leaf.public_bytes(pem))
    (directory / "upstream/key.pem").write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                                   serialization.NoEncryption()))
    (directory / "bootstrap/ca.pem").write_bytes(ca.public_bytes(pem))
    for path in ((directory / "upstream/cert.pem"), (directory / "upstream/key.pem"), (directory / "bootstrap/ca.pem")):
        path.chmod(0o444)


def guard_config():
    networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    return {
        "schema_version": 2, "profile": "production-linux-peer-bound", "deployment": {"guard_uid": 10001},
        "paths": {"state_directory": "/state", "key_directory": "/state-keys", "socket": "/run/guard/guard.sock",
                  "admin_socket": "/run/guard-admin/admin.sock", "archive_directory": "/archive"},
        "service": {"socket_group": 10001, "max_connections": 16, "per_peer_connections": 4, "max_requests_per_second": 20},
        "outcomes": {"capacity": 200000, "max_request_age_seconds": 3600},
        "retention": {"outcome_archive_age_seconds": 7200, "outcome_archive_interval_seconds": 600},
        "tenants": [{"id": "a"}, {"id": "b"}],
        "backend_inventory": {"schema_version": 1, "backends": [{
            "backend_id": "acceptance-upstream", "account_id": "synthetic-shared",
            "data_domain": "acceptance-upstream", "tenants": ["a"],
            "hosts": ["https://upstream.acceptance.test"]}]},
        "connectors": [
            {"name": "tickets", "type": "fixture", "behavior": "echo"},
            {"name": "model", "type": "chat_completions", "endpoint": "https://upstream.acceptance.test/v1/chat/completions",
             "model": "synthetic-model", "credential": "upstream-key", "authentication": "x-api-key",
             "ca_file": "/bootstrap/ca.pem", "data_domain": "acceptance-upstream"},
            {"name": "kb", "type": "retrieval_local", "collection": "kb"}],
        "routes": [
            {"name": "a.ticket", "tenant": "a", "operation": "ticket.update", "resource": "ticket", "destination": "tickets",
             "connector": "tickets", "clearance": "confidential", "produces": "confidential",
             "task_boundaries": [{"principal": "support-bot", "workflow": "inc-42", "fields": [
                 {"path": ["ticket"], "kind": "str", "choices": ["INC-42"]}, {"path": ["comment"], "kind": "str", "max_length": 500}]}]},
            {"name": "a.close", "tenant": "a", "operation": "ticket.close", "resource": "ticket", "destination": "tickets",
             "connector": "tickets", "clearance": "confidential", "produces": "confidential", "approval": "required"},
            {"name": "a.model", "tenant": "a", "operation": "model.call", "connector": "model", "clearance": "internal",
             "produces": "internal", "privacy": "tokenize"},
            {"name": "a.model-plain", "tenant": "a", "operation": "model.call", "connector": "model",
             "clearance": "internal", "produces": "internal"},
            {"name": "b.read", "tenant": "b", "operation": "read", "resource": "records", "destination": "tickets",
             "connector": "tickets", "clearance": "confidential", "produces": "confidential"},
            {"name": "a.kb", "tenant": "a", "operation": "retrieve", "connector": "kb", "clearance": "confidential"},
            {"name": "a.notes", "tenant": "a", "operation": "notes.write", "resource": "notes", "destination": "notes",
             "connector": "tickets", "clearance": "restricted", "produces": "restricted"}],
        "agents": [
            {"id": "agent-a", "tenant": "a", "principal": "support-bot", "uid": 11001, "task": "inc-42",
             "clearance": "confidential", "groups": ["support"],
             "routes": ["a.ticket", "a.close", "a.model", "a.model-plain", "a.kb", "a.notes"]},
            {"id": "agent-b", "tenant": "b", "principal": "bot-b", "uid": 11002, "routes": ["b.read"]}],
        "approvers": [{"id": "alice", "tenants": ["a"]}],
        "sensitivity": {"declared_context": [{"name": "routing", "level": "restricted",
                                              "file": "/bootstrap/declared/hidden.txt"}]},
        "egress": {"mode": "proxy", "socket": "/run/guard-egress/egress.sock", "client_uids": [10001], "socket_group": 10003,
                   "allow": [{"host": "upstream.acceptance.test", "port": 443, "addresses": networks}]}}


class Harness:
    def __init__(self):
        local = ROOT / ".local-deploy"
        local.mkdir(exist_ok=True, mode=0o700)
        self.run = local / ("prod-" + secrets.token_hex(6))
        self.run.mkdir(mode=0o700)
        for name in ("bootstrap", "credentials"):
            (self.run / name).mkdir(mode=0o777 if name == "credentials" else 0o755)
        (self.run / "credentials").chmod(0o777)
        (self.run / "bootstrap/guard.json").write_text(json.dumps(guard_config(), indent=2))
        (self.run / "bootstrap/guard.json").chmod(0o444)
        (self.run / "bootstrap/declared").mkdir(mode=0o755)
        (self.run / "bootstrap/declared/hidden.txt").write_text("cobalt orchard")
        documents = {"a": [{"doc_id": "kb-1", "title": "Outage runbook", "content": "Restart the ticket service during an outage.",
                            "label": "internal", "principals": ["support-bot"]},
                           {"doc_id": "kb-team", "title": "Team notes", "content": "Support team outage notes.",
                            "label": "internal", "groups": ["support"]},
                           {"doc_id": "kb-restricted", "title": "Board memo", "content": "Restricted outage merger memo.",
                            "label": "restricted", "principals": ["support-bot"]},
                           {"doc_id": "kb-finance", "title": "Finance", "content": "Finance outage budget.",
                            "label": "internal", "principals": ["finance-bot"]}],
                     "b": [{"doc_id": "kb-b", "title": "Tenant B", "content": "Tenant B outage report.",
                            "label": "internal", "principals": ["*"]}]}
        for tenant, items in documents.items():
            path = self.run / "bootstrap" / ("docs-%s.jsonl" % tenant)
            path.write_text("".join(json.dumps(item) + "\n" for item in items))
            path.chmod(0o444)
        certificates(self.run)
        self.project = "egprod" + secrets.token_hex(5)
        self.env = {**os.environ, "GUARD_IMAGE": IMAGE, "GUARD_AGENT_IMAGE": IMAGE,
                    "GUARD_BOOTSTRAP_DIR": str(self.run / "bootstrap"),
                    "GUARD_ACCEPTANCE_DIR": str(ROOT / "deployment/acceptance"),
                    "GUARD_UPSTREAM_DIR": str(self.run / "upstream"),
                    "GUARD_AGENT_TOKEN_FILE": str(self.run / "credentials/agent-a.token")}
        self.base = ["docker", "compose", "-p", self.project, "-f", str(ROOT / "deployment/compose.production.yaml"),
                     "-f", str(ROOT / "deployment/acceptance/compose.acceptance.yaml")]
        self.checks = {}
        self.details = {}

    def compose(self, *args, stdin=None, check=True, env=None):
        result = subprocess.run([*self.base, *args], env=env or self.env, input=stdin, capture_output=True, text=True,
                                timeout=600)
        if check and result.returncode:
            raise RuntimeError("compose %s failed: %s" % (args[:3], result.stderr[-2000:].replace(SYNTHETIC_KEY, "[redacted]")))
        return result

    def guard_cli(self, *args, stdin=None, check=True, exec_=False):
        command = ["exec", "-T", "guard", "enkstein-guard"] if exec_ else [
            "run", "--rm", "--no-deps", "-T", "-v", str(self.run / "credentials") + ":/credentials", "guard"]
        result = self.compose(*command, "--config", "/bootstrap/guard.json", *args, stdin=stdin, check=False)
        lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
        payload = json.loads(lines[-1]) if lines else {"status": "no_output", "stderr": result.stderr[-500:]}
        if check and result.returncode:
            raise RuntimeError("guard cli %s failed: %s" % (args[:2], json.dumps(payload)))
        return result.returncode, payload

    def agent(self, *args, uid=11001, token="agent-a", stolen=None, extra_env=None):
        command = ["run", "--rm", "--no-deps", "-T", "--user", "%d:10001" % uid,
                   "-v", str(ROOT / "deployment/acceptance/production_agent.py") + ":/agent.py:ro",
                   "-v", str(self.run / "credentials" / (token + ".token")) + ":/run/agent-token:ro"]
        if stolen:
            command += ["-v", str(self.run / "credentials" / (stolen + ".token")) + ":/run/stolen-token:ro"]
        for key, value in (extra_env or {}).items():
            command += ["-e", "%s=%s" % (key, value)]
        result = self.compose(*command, "--entrypoint", "python", "agent", "/agent.py", *args, check=False)
        lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
        if not lines:
            raise RuntimeError("agent produced no result: " + result.stderr[-1500:])
        return json.loads(lines[-1])

    def wait_ready(self, timeout=90):
        deadline = time.time() + timeout
        while time.time() < deadline:
            code, payload = self.guard_cli("service", "ready", "--timeout", "3", check=False, exec_=True)
            if code == 0:
                return payload
            time.sleep(1)
        logs = self.compose("logs", "--no-color", "guard", "egress", check=False).stdout[-3000:]
        raise RuntimeError("guard_not_ready: " + logs)

    def run_all(self):
        self.compose("up", "--no-color", "initialize", "capture-init")
        self.guard_cli("init")
        for kind, name in (("agent", "agent-a"), ("agent", "agent-b"), ("approver", "alice")):
            self.guard_cli(kind, "issue", "--" + kind, name, "--output", "/credentials/%s.token" % name)
            (self.run / "credentials" / (name + ".token")).chmod(0o444)
        for tenant in ("a", "b"):
            self.guard_cli("retrieval", "ingest", "--tenant", tenant, "--collection", "kb",
                           "--file", "/bootstrap/docs-%s.jsonl" % tenant)
        self.guard_cli("connector", "secret-set", "--name", "upstream-key", "--tenant", "a",
                       "--destination", "upstream.acceptance.test", "--route", "a.model", "--route", "a.model-plain",
                       "--value-file", "-", stdin=SYNTHETIC_KEY + "\n")
        self.compose("up", "-d", "--no-color", "egress", "upstream", "guard")
        ready = self.wait_ready()
        self.checks["guard_ready"] = ready.get("ready") is True
        code, status = self.guard_cli("service", "status", exec_=True)
        self.checks["peer_bound_active"] = status.get("peer_bound") is True
        self.checks["guard_has_only_loopback"] = status["preflight"]["network_interfaces"] == ["lo"]
        self.checks["egress_proxy_healthy"] = status["preflight"].get("egress_proxy_healthy") is True
        close_id = "%010d-%s" % (int(time.time()), secrets.token_urlsafe(18))
        main = self.agent("main", stolen="agent-b", extra_env={"CLOSE_REQUEST_ID": close_id})
        self.checks.update({"agent_" + k: v for k, v in main["checks"].items()})
        self.details["model_status"] = main.get("model_status")
        if main.get("model_diagnostic_id"):
            code, report = self.guard_cli("diagnose", "--id", main["model_diagnostic_id"], exec_=True, check=False)
            self.details["model_diagnosis"] = {"final_outcome": report.get("final_outcome"),
                                               "controls": report.get("denying_or_failed_controls")}
        # Approver credential is copied into the guard container's tmpfs only for
        # the decision; it is never placed on the agent side.
        approver = (self.run / "credentials/alice.token").read_text()
        decided = self.compose("exec", "-T", "guard", "sh", "-c",
                               "umask 077; cat > /tmp/approver; enkstein-guard --config /bootstrap/guard.json approvals approve "
                               "--ticket %s --digest %s --approver-credential-file /tmp/approver; rm -f /tmp/approver"
                               % (main["ticket"], main["digest"]), stdin=approver, check=False)
        lines = [line for line in decided.stdout.splitlines() if line.startswith("{")]
        self.checks["approver_decision_recorded"] = bool(lines) and json.loads(lines[-1]).get("ticket_status") == "approved"
        approved = self.agent("approved", main["ticket"], extra_env={"CLOSE_REQUEST_ID": close_id})
        self.checks.update({"agent_" + k: v for k, v in approved["checks"].items()})
        capture = self.compose("exec", "-T", "upstream", "cat", "/capture/requests.jsonl", check=False).stdout
        records = [json.loads(line) for line in capture.splitlines() if line.strip()]
        self.checks["upstream_received_one_model_call"] = len(records) == 1
        self.checks["upstream_got_brokered_key"] = bool(records) and records[0]["api_key_sha256"] == hashlib.sha256(
            SYNTHETIC_KEY.encode()).hexdigest()
        self.checks["upstream_never_saw_raw_email"] = "jane@example.com" not in capture and "[[EGV:" in capture
        probe = ("import json,socket\nfrom enkstein_guard.egress import EgressClient, EgressDenied\nr={}\n"
                 "try:\n socket.create_connection(('1.1.1.1',443),timeout=2).close(); r['direct']='connected'\n"
                 "except OSError:\n r['direct']='blocked'\nc=EgressClient('/run/guard-egress/egress.sock')\n"
                 "try:\n c.connect('example.com',443); r['unlisted']='connected'\nexcept EgressDenied:\n r['unlisted']='blocked'\n"
                 "try:\n c.connect('upstream.acceptance.test',8443); r['wrong_port']='connected'\nexcept EgressDenied:\n r['wrong_port']='blocked'\n"
                 "print(json.dumps(r))\n")
        guard_probe = json.loads(self.compose("exec", "-T", "guard", "python", "-c", probe).stdout.strip().splitlines()[-1])
        self.checks["guard_direct_network_blocked"] = guard_probe["direct"] == "blocked"
        self.checks["guard_unlisted_destination_blocked"] = guard_probe["unlisted"] == "blocked"
        self.checks["guard_wrong_port_blocked"] = guard_probe["wrong_port"] == "blocked"
        # A non-Guard UID that can reach the socket (member of the socket group)
        # must still be refused by the proxy's own SO_PEERCRED check.
        foreign = self.compose("exec", "-T", "--user", "11001:10003", "egress", "python", "-c",
                               "from enkstein_guard.egress import EgressClient, EgressDenied\n"
                               "try:\n"
                               "    EgressClient('/run/guard-egress/egress.sock').connect('upstream.acceptance.test',443)\n"
                               "    print('connected')\n"
                               "except EgressDenied as error:\n"
                               "    print('denied:' + str(error))\n", check=False)
        self.details["egress_foreign_uid"] = foreign.stdout.strip()[-80:]
        self.checks["egress_rejects_non_guard_uid"] = foreign.stdout.strip().endswith("denied:egress_denied_403")
        durable_id = "%010d-%s" % (int(time.time()), secrets.token_urlsafe(18))
        first = self.agent("durable", extra_env={"DURABLE_ID": durable_id})
        self.compose("kill", "guard")
        self.compose("up", "-d", "--no-color", "guard")
        self.wait_ready()
        again = self.agent("durable", extra_env={"DURABLE_ID": durable_id})
        self.checks["restart_duplicate_suppressed"] = first["status"] == "ok" and again["status"] == "completed_no_replay"
        code, doctor = self.guard_cli("doctor", exec_=True)
        reasons = doctor["mandatory_enforcement_status"]["reasons"]
        self.checks["doctor_only_reports_synthetic_connector"] = reasons == ["synthetic_connectors_configured"]
        self.guard_cli("agent", "revoke", "--agent", "agent-a", exec_=True)
        revoked = self.agent("revoked")
        self.checks.update({"agent_" + k: v for k, v in revoked["checks"].items()})
        code, verified = self.guard_cli("audit", "verify", exec_=True)
        self.checks["audit_chain_verified"] = code == 0
        exported = self.compose("exec", "-T", "guard", "sh", "-c",
                                "enkstein-guard --config /bootstrap/guard.json audit export --output /tmp/audit.jsonl >/dev/null "
                                "&& cat /tmp/audit.jsonl && rm -f /tmp/audit.jsonl", check=False).stdout
        self.checks["audit_export_secret_free"] = (bool(exported) and SYNTHETIC_KEY not in exported
                                                   and "jane@example.com" not in exported)
        self.checks["audit_has_decisions"] = '"outcome":"authorized"' in exported and '"outcome":"denied"' in exported
        logs = self.compose("logs", "--no-color", check=False).stdout
        self.checks["logs_secret_free"] = SYNTHETIC_KEY not in logs and "jane@example.com" not in logs
        code, shown = self.guard_cli("config", "show", exec_=True, check=False)
        evidence_dir = Path(os.environ.get("GUARD_EVIDENCE_DIR", evidence.EVIDENCE_DIR))
        return {"evidence": evidence.header("container-production-profile", configurations=[
                    evidence.configuration(self.run / "bootstrap/guard.json", name="guard.json",
                                           policy_version=shown.get("policy_version") if code == 0 else None,
                                           preserve=(evidence_dir / "configurations",
                                                     "container-production-profile.guard.json"))],
                    image_info=evidence.image(IMAGE)),
                "image": IMAGE, "image_id": subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}", IMAGE],
                                                           capture_output=True, text=True).stdout.strip(),
                "checks": self.checks, "passed": all(self.checks.values()), "details": self.details,
                "audit_checkpoint": verified.get("checkpoint"),
                "scope": "Synthetic credentials and upstream; one Docker host (Colima VM, Docker Engine); Linux arm64 containers."}

    def collect_logs(self):
        logs = self.compose("logs", "--no-color", "egress", "upstream", check=False).stdout
        return logs.replace(SYNTHETIC_KEY, "[redacted]")[-6000:]

    def cleanup(self):
        self.compose("down", "--volumes", "--remove-orphans", check=False)
        shutil.rmtree(self.run, ignore_errors=True)


def main():
    harness = Harness()
    try:
        report = harness.run_all()
    except Exception as error:
        report = {"image": IMAGE, "checks": harness.checks, "passed": False, "details": harness.details,
                  "error": str(error).replace(SYNTHETIC_KEY, "[redacted]")[-3000:]}
    try:
        if not report["passed"]:
            report["diagnostic_logs"] = harness.collect_logs()
    finally:
        harness.cleanup()
    report["generated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    evidence.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    output = Path(os.environ.get("GUARD_EVIDENCE_DIR", evidence.EVIDENCE_DIR)) / "container-production-profile.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "failed": [k for k, v in report["checks"].items() if not v],
                      "error": report.get("error")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
