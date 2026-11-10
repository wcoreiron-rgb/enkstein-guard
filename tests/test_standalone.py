import json
import os
import subprocess
import sys
import unittest

from enkstein_guard import scan_command, scan_content


class StandaloneTests(unittest.TestCase):
    def test_protected_delete_is_denied_but_build_cleanup_is_allowed(self):
        self.assertTrue(scan_command("rm -rf /").blocked)
        self.assertFalse(scan_command("rm -rf ./build").blocked)

    def test_cli_does_not_echo_secret(self):
        secret = "AKIA3ZK7QWERTYUIOPAS"
        env = dict(os.environ, ENKSTEIN_POLICY_PACK="/nonexistent/guard-test-pack")
        result = subprocess.run(
            [sys.executable, "-m", "enkstein_guard.cli", "scan", "--surface", "content"],
            input=secret, text=True, capture_output=True, env=env, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["decision"], "deny")

    def test_doctor_reports_incomplete_enforcement(self):
        result = subprocess.run(
            [sys.executable, "-m", "enkstein_guard.cli", "doctor"],
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(json.loads(result.stdout)["mandatory_enforcement"], "requires_restricted_container_deployment_not_pip_install")

    def test_placeholder_allowed_and_key_denied(self):
        self.assertFalse(scan_content("AKIAIOSFODNN7EXAMPLE").blocked)
        self.assertTrue(scan_content("AKIA3ZK7QWERTYUIOPAS").blocked)
