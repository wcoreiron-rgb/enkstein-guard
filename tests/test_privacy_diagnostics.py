"""CLI control states must distinguish available, configured and active use."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_host import make_config


class PrivacyDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-privacy-diagnostics-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "declared.txt").write_text("synthetic declaration")
        self.path = self.root / "config.json"

    def invoke(self, data, *args):
        self.path.write_text(json.dumps(data))
        run = subprocess.run([sys.executable, "-m", "enkstein_guard", "--config", str(self.path), *args],
                             capture_output=True, text=True, timeout=30,
                             env={**os.environ, "ENKSTEIN_POLICY_PACK": "/nonexistent/diagnostics"})
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return json.loads(run.stdout)

    def model_config(self):
        data = make_config(self.root)
        data["connectors"].append({"name": "model", "type": "chat_completions", "model": "synthetic",
                                   "credential": "model-key", "endpoint": "https://model.example.test/v1/chat/completions"})
        data["routes"].append({"name": "model.chat", "tenant": "tenant-a", "operation": "model.call",
                               "connector": "model", "clearance": "internal"})
        data["egress"] = {"mode": "direct_development_only"}
        return data

    def test_default_model_policy_is_visible_before_service_start(self):
        result = self.invoke(self.model_config(), "doctor")
        self.assertEqual(result["controls"]["default_model_tokenization"]["state"], "configured")
        self.assertEqual(result["model_privacy"], {"routes": 1, "tokenized": 1, "exceptions": []})
        self.assertEqual(result["controls"]["durable_orchestration"]["state"], "installed")

    def test_exception_diagnostics_do_not_echo_freeform_reason(self):
        data = self.model_config()
        data["routes"][-1].update(privacy="none", privacy_exception_reason="operator-private-reason-marker")
        result = self.invoke(data, "doctor")
        self.assertEqual(result["model_privacy"]["exceptions"], [
            {"route": "model.chat", "privacy": "none", "reason_present": True}])
        self.assertNotIn("operator-private-reason-marker", json.dumps(result))
        explained = self.invoke(data, "policy", "explain", "--route", "model.chat")
        self.assertTrue(explained["routes"][0]["privacy_exception"])
        self.assertNotIn("operator-private-reason-marker", json.dumps(explained))

    def test_no_tokenize_routes_does_not_report_configured_vault_tokenization(self):
        data = make_config(self.root)
        data["routes"] = [r for r in data["routes"] if r["name"] == "ticket.comment"]
        data["agents"] = [data["agents"][0]]
        data["agents"][0]["routes"] = ["ticket.comment"]
        result = self.invoke(data, "doctor")
        self.assertEqual(result["controls"]["vault_tokenization"]["state"], "installed")
