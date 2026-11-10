import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from enkstein_guard.config import GuardConfig, load_config


class ConfigTests(unittest.TestCase):
    def test_default(self):
        self.assertEqual(load_config(None).mode, "inspection_only")

    def test_unsupported_protection_and_bad_limits_rejected(self):
        for kwargs in ({"mode": "protected"}, {"max_input_bytes": True},
                       {"max_input_bytes": 0}, {"schema_version": True}):
            with self.assertRaises(ValueError):
                GuardConfig(**kwargs)

    def test_unknown_duplicate_and_non_object_config_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            for content in ('{"token":"must-not-load"}', '{"mode":"inspection_only","mode":"protected"}', '[]'):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    load_config(str(path))

    def test_oversized_input_fails_without_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"max_input_bytes": 4}))
            result = subprocess.run(
                [sys.executable, "-m", "enkstein_guard", "--config", str(path), "scan", "--surface", "prompt"],
                input="sensitive-payload", text=True, capture_output=True,
                env=dict(os.environ, ENKSTEIN_POLICY_PACK="/nonexistent/guard-test-pack"),
            )
            self.assertEqual(result.returncode, 3)
            self.assertNotIn("sensitive-payload", result.stdout + result.stderr)

    def test_multibyte_limit_is_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"max_input_bytes": 4}')
            result = subprocess.run(
                [sys.executable, "-m", "enkstein_guard", "--config", str(path), "scan", "--surface", "content"],
                input="界界", text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 3)
