"""Subprocess CLI workflows: JSON contract, exit codes, secrets handling, lifecycle."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from test_host import make_config

ENV = dict(os.environ, ENKSTEIN_POLICY_PACK="/nonexistent/guard-test-pack")


@unittest.skipUnless(os.name == "posix", "Unix sockets")
class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text("cobalt orchard")
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps(make_config(self.root)))
        self.service = None
        self.addCleanup(self.stop_service)

    def run_cli(self, *args, stdin=None, config=True):
        command = [sys.executable, "-m", "enkstein_guard"] + (["--config", str(self.config)] if config else []) + list(args)
        result = subprocess.run(command, input=stdin, capture_output=True, text=True, env=ENV, timeout=60)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, result.stdout + result.stderr)
        payload = json.loads(lines[0])
        self.assertEqual(payload["schema"], "enkstein-guard.cli/v1")
        self.assertEqual(result.stderr, "")
        return result.returncode, payload

    def start_service(self):
        self.service = subprocess.Popen([sys.executable, "-m", "enkstein_guard", "--config", str(self.config),
                                         "service", "start"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, env=ENV)
        code, payload = self.run_cli("service", "wait-ready", "--timeout", "20")
        self.assertEqual(code, 0, payload)

    def stop_service(self):
        if self.service is not None and self.service.poll() is None:
            subprocess.run([sys.executable, "-m", "enkstein_guard", "--config", str(self.config), "service", "stop"],
                           capture_output=True, env=ENV, timeout=30)
            try:
                self.service.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                self.service.kill()
                self.service.communicate()

    def initialize(self):
        self.assertEqual(self.run_cli("init")[0], 0)
        code, issued = self.run_cli("agent", "issue", "--agent", "agent-a", "--output", str(self.root / "agent.token"))
        self.assertEqual(code, 0)
        return (self.root / "agent.token").read_text().strip()

    def test_usage_and_configuration_errors(self):
        code, payload = self.run_cli("service", "explode")
        self.assertEqual((code, payload["error"]), (64, "usage_error"))
        broken = make_config(self.root)
        broken["routes"][0]["clearance"] = "secret-value-should-not-echo"
        self.config.write_text(json.dumps(broken))
        code, payload = self.run_cli("config", "validate")
        self.assertEqual((code, payload["error"]), (3, "configuration_invalid"))
        self.assertIn({"path": "$.routes[0].clearance", "code": "unsupported_value"}, payload["errors"])
        self.assertNotIn("secret-value-should-not-echo", json.dumps(payload))
        code, payload = self.run_cli("init", config=False)
        self.assertEqual((code, payload["error"]), (64, "product_configuration_required"))

    def test_init_is_exclusive_and_credentials_never_printed(self):
        token = self.initialize()
        code, payload = self.run_cli("init")
        self.assertEqual((code, payload["error"]), (3, "state_already_initialized"))
        self.assertEqual((self.root / "agent.token").stat().st_mode & 0o777, 0o600)
        code, listing = self.run_cli("agent", "list")
        self.assertNotIn(token, json.dumps(listing))
        self.assertEqual(listing["identities"][0]["credential"], "active")
        code, payload = self.run_cli("agent", "issue", "--agent", "unknown", "--output", str(self.root / "x"))
        self.assertEqual((code, payload["error"]), (3, "identity_not_configured"))

    def test_connector_secret_from_private_file_or_stdin_only(self):
        self.initialize()
        data = make_config(self.root)
        data["connectors"].append({"name": "hatz", "type": "chat_completions", "credential": "hatz-key",
                                   "endpoint": "https://ai.example.test/v1/chat/completions", "model": "m"})
        data["routes"].append({"name": "model.chat", "tenant": "tenant-a", "operation": "model.call",
                               "connector": "hatz", "clearance": "internal"})
        data["egress"] = {"mode": "direct_development_only"}
        self.config.write_text(json.dumps(data))
        secret = self.root / "secret"
        secret.write_text("synthetic-connector-secret\n")
        secret.chmod(0o644)
        args = ("connector", "secret-set", "--name", "hatz-key", "--tenant", "tenant-a",
                "--destination", "ai.example.test", "--route", "model.chat")
        code, payload = self.run_cli(*args, "--value-file", str(secret))
        self.assertEqual((code, payload["error"]), (3, "secret_input_must_be_private_file"))
        code, payload = self.run_cli(*args, "--value-file", "-", stdin="synthetic-connector-secret\n")
        self.assertEqual(code, 0, payload)
        code, payload = self.run_cli(*args[:-2], "--route", "ticket.comment", "--value-file", "-", stdin="x\n")
        self.assertEqual((code, payload["error"]), (3, "secret_binding_does_not_match_route"))
        code, listing = self.run_cli("connector", "secret-list")
        self.assertNotIn("synthetic-connector-secret", json.dumps(listing))
        self.assertEqual(listing["secrets"][0]["routes"], ["model.chat"])

    def test_service_lifecycle_requests_diagnostics_and_backup(self):
        self.initialize()
        code, payload = self.run_cli("service", "ready", "--timeout", "1")
        self.assertEqual((code, payload["error"]), (4, "service_unavailable"))
        self.start_service()
        request = ("request", "--socket", str(self.root / "sock/guard.sock"), "--credential-file",
                   str(self.root / "agent.token"))
        ok_payload = self.root / "ok.json"
        ok_payload.write_text(json.dumps({"ticket": "INC-42", "comment": "hello"}))
        code, payload = self.run_cli(*request, "--route", "ticket.comment", "--payload-file", str(ok_payload),
                                     "--new-request-id")
        self.assertEqual((code, payload["status"]), (0, "ok"))
        code, payload = self.run_cli(*request, "--route", "ticket.comment", "--payload-file", "-", "--new-request-id",
                                     stdin=json.dumps({"ticket": "INC-77", "comment": "x"}))
        self.assertEqual((code, payload["status"]), (2, "denied"))
        diagnostic = payload["response"]["diagnostic_id"]
        code, report = self.run_cli("diagnose", "--id", diagnostic)
        self.assertEqual(report["denying_or_failed_controls"], ["task_boundary"])
        code, payload = self.run_cli("backup", "create", "--data", str(self.root / "b-data"),
                                     "--keys", str(self.root / "b-keys"))
        self.assertEqual((code, payload["error"]), (3, "service_running_or_state_locked"))
        code, doctor = self.run_cli("doctor")
        self.assertEqual(doctor["mandatory_enforcement_status"]["state"], "not_established")
        self.assertIn("profile_not_production", doctor["mandatory_enforcement_status"]["reasons"])
        self.assertEqual(doctor["controls"]["task_boundaries"]["state"], "active")
        code, status = self.run_cli("service", "status")
        self.assertEqual((code, status["service"]), (0, "running"))
        code, payload = self.run_cli("service", "stop")
        self.assertEqual(code, 0)
        self.service.communicate(timeout=30)
        self.assertEqual(self.service.returncode, 0)
        code, payload = self.run_cli("backup", "create", "--data", str(self.root / "b-data"),
                                     "--keys", str(self.root / "b-keys"))
        self.assertEqual(code, 0, payload)
        code, verified = self.run_cli("backup", "verify", "--data", str(self.root / "b-data"),
                                      "--keys", str(self.root / "b-keys"))
        self.assertEqual((code, verified["verified"]), (0, True))
        code, exported = self.run_cli("audit", "export", "--output", str(self.root / "audit.jsonl"))
        self.assertEqual(code, 0)
        self.assertNotIn("hello", (self.root / "audit.jsonl").read_text())
        mismatch = self.root / "checkpoint.json"
        mismatch.write_text(json.dumps({"sequence": 1, "head": "0" * 64}))
        code, payload = self.run_cli("audit", "verify", "--checkpoint", str(mismatch))
        self.assertEqual((code, payload["error"]), (3, "audit_verification_failed"))

    def test_forced_kill_restart_recovers_and_suppresses_duplicates(self):
        self.initialize()
        self.start_service()
        payload = self.root / "p.json"
        payload.write_text(json.dumps({"ticket": "INC-42", "comment": "durable"}))
        from enkstein_guard.outcomes import new_request_id
        request_id = new_request_id()
        request = ("request", "--socket", str(self.root / "sock/guard.sock"), "--credential-file",
                   str(self.root / "agent.token"), "--route", "ticket.comment", "--payload-file", str(payload),
                   "--request-id", request_id)
        self.assertEqual(self.run_cli(*request)[1]["status"], "ok")
        self.service.kill()
        self.service.communicate(timeout=30)
        self.assertTrue((self.root / "sock/guard.sock").exists())  # stale socket left by the crash
        self.start_service()
        code, payload = self.run_cli(*request)
        self.assertEqual((code, payload["status"]), (0, "completed_no_replay"))
        code, status = self.run_cli("service", "status")
        self.assertEqual(status["outcomes"]["records"], 1)

    def test_second_instance_refused_while_running(self):
        self.initialize()
        self.start_service()
        second = subprocess.run([sys.executable, "-m", "enkstein_guard", "--config", str(self.config), "service", "start"],
                                capture_output=True, text=True, env=ENV, timeout=60)
        self.assertEqual(second.returncode, 4)
        self.assertEqual(json.loads(second.stdout)["error"], "service_running_or_state_locked")
        code, status = self.run_cli("service", "status")
        self.assertEqual(status["service"], "running")

    def test_offline_vault_key_rotation_keeps_references(self):
        self.initialize()
        self.start_service()
        request = ("request", "--socket", str(self.root / "sock/guard.sock"), "--credential-file",
                   str(self.root / "agent.token"), "--route", "crm.lookup", "--payload-file", "-", "--new-request-id")
        code, looked = self.run_cli(*request, stdin=json.dumps({"email": "jane@example.com", "note": "x"}))
        reference = looked["response"]["result"]["payload"]["email"]
        code, payload = self.run_cli("keys", "rotate", "--store", "vault")
        self.assertEqual((code, payload["error"]), (3, "service_running_or_state_locked"))
        self.stop_service()
        self.assertEqual(self.run_cli("keys", "rotate", "--store", "vault")[0], 0)
        self.start_service()
        update = ("request", "--socket", str(self.root / "sock/guard.sock"), "--credential-file",
                  str(self.root / "agent.token"), "--route", "crm.update", "--payload-file", "-", "--new-request-id")
        code, payload = self.run_cli(*update, stdin=json.dumps({"email": reference, "status": "x"}))
        self.assertEqual((code, payload["status"]), (0, "ok"))

    def test_production_refuses_one_provider_secret_for_two_tenants(self):
        from test_product_config import production
        data = production()
        data["paths"] = {"state_directory": str(self.root / "state"), "key_directory": str(self.root / "keys"),
                         "socket": str(self.root / "sock/guard.sock"), "admin_socket": str(self.root / "admin/admin.sock"),
                         "archive_directory": str(self.root / "archive")}
        data["connectors"].append({"name": "hatz-b", "type": "chat_completions", "model": "m", "credential": "hatz-b-key",
                                   "endpoint": "https://ai.example.test/v1/chat/completions",
                                   "data_domain": "example-ai-primary-prod"})
        data["routes"].append({"name": "b.model", "tenant": "tenant-b", "operation": "model.call", "connector": "hatz-b",
                               "clearance": "internal", "produces": "internal"})
        self.config.write_text(json.dumps(data))
        self.assertEqual(self.run_cli("init")[0], 0)
        def secret(name, tenant, route, value):
            return self.run_cli("connector", "secret-set", "--name", name, "--tenant", tenant, "--destination",
                                "ai.example.test", "--route", route, "--value-file", "-", stdin=value + "\n")
        self.assertEqual(secret("hatz-key", "tenant-a", "model.chat", "synthetic-shared-account-key")[0], 0)
        code, payload = secret("hatz-b-key", "tenant-b", "b.model", "synthetic-shared-account-key")
        self.assertEqual((code, payload["error"]), (3, "secret_value_shared_across_tenants"))
        self.assertNotIn("synthetic-shared-account-key", json.dumps(payload))
        self.assertEqual(secret("hatz-b-key", "tenant-b", "b.model", "synthetic-tenant-b-key")[0], 0)

    def test_sizing_warnings_retention_and_outcome_commands_use_the_running_service(self):
        data = make_config(self.root)
        data["service"]["max_requests_per_second"] = 50
        self.config.write_text(json.dumps(data))
        code, validated = self.run_cli("config", "validate")
        self.assertEqual(code, 0)
        self.assertEqual([w["code"] for w in validated["warnings"]], ["outcome_capacity_insufficient_for_request_rate"])
        self.assertFalse(validated["outcome_sizing"]["sufficient"])
        code, payload = self.run_cli("retention", "run", "--store", "vault")
        self.assertEqual((code, payload["error"]), (4, "service_not_running_use_offline_archive_commands"))
        self.initialize()
        self.start_service()
        code, ran = self.run_cli("retention", "run", "--store", "vault")
        self.assertEqual((code, ran["store"], ran["runs"]), (0, "vault", 1))
        code, listed = self.run_cli("outcomes", "list")
        self.assertEqual((code, listed["records"]), (0, []))
        code, verified = self.run_cli("outcomes", "verify-archives")
        self.assertEqual((code, verified["verified"], verified["segments"]), (0, True, 0))
        code, doctor = self.run_cli("doctor")
        self.assertIn("outcome_capacity_insufficient_for_request_rate", [w["code"] for w in doctor["warnings"]])
        code, status = self.run_cli("service", "status")
        self.assertEqual(status["rate_limit"]["max_requests_per_second"], 50)
        self.assertIn("outcomes", status["retention"])

    def test_version_and_coverage_follow_json_contract(self):
        from enkstein_guard import __version__
        code, version = self.run_cli("--version", config=False)
        self.assertEqual((code, version["command"], version["version"]), (0, "version", __version__))
        code, coverage = self.run_cli("coverage", config=False)
        self.assertEqual(code, 0)
        self.assertEqual(coverage["mapping"]["evidence"]["gate"], "blocked_known_gaps")
        self.assertFalse(any(row["full_category_acceptance"] for row in coverage["mapping"]["requirements"]))

    def test_doctor_without_configuration(self):
        code, doctor = self.run_cli("doctor", config=False)
        self.assertEqual(code, 0)
        self.assertEqual(doctor["mandatory_enforcement_status"]["state"], "not_established")
        for name in ("streaming", "multimodal", "windows", "cloud_isolation"):
            self.assertEqual(doctor["controls"][name]["state"], "unsupported")
        self.assertEqual(doctor["mandatory_enforcement"], "requires_restricted_container_deployment_not_pip_install")


class ServiceWarningTests(unittest.TestCase):
    def test_unreconciled_outcomes_are_reported_and_checked_against_sizing(self):
        # Unreconciled uncertain records are kept past the archive horizon, so
        # the sizing headroom does not bound them; doctor reports them.
        from enkstein_guard.cli import service_warnings
        sizing = {"required_capacity": 184800}

        def codes(retained, records=1000):
            status = {"outcomes": {"records": records, "maximum": 200000, "retained_below_cutoff": retained}}
            return service_warnings(sizing, status)
        self.assertEqual(codes(0), [])
        self.assertEqual([w["code"] for w in codes(12)], ["outcome_records_unreconciled"])
        many = codes(20000, records=30000)
        self.assertEqual([w["code"] for w in many], ["outcome_records_unreconciled",
                                                      "outcome_capacity_reduced_by_unreconciled_records"])
        self.assertEqual(many[1]["detail"], {"required_capacity": 184800, "unreconciled": 20000, "maximum": 200000})
