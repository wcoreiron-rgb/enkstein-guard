import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from enkstein_guard.audit import DurableAudit
from enkstein_guard.host import StateLayout, initialize_state, state_lock
from enkstein_guard.productconfig import validate
from test_host import make_config


ENV = dict(os.environ, ENKSTEIN_POLICY_PACK="/nonexistent/guard-test-pack")


@unittest.skipUnless(os.name == "posix", "state locking requires POSIX flock")
class AuditRotationCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-audit-rotation-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text("cobalt orchard")
        self.config_path = self.root / "config.json"
        self.raw_config = make_config(self.root)
        self.config_path.write_text(json.dumps(self.raw_config))
        self.config = validate(self.raw_config, source=str(self.config_path))
        initialize_state(self.config)
        self.layout = StateLayout(self.config)

    def run_cli(self, *arguments):
        result = subprocess.run(
            [sys.executable, "-m", "enkstein_guard", "--config", str(self.config_path), *arguments],
            capture_output=True, text=True, env=ENV, timeout=30,
        )
        self.assertEqual(result.stderr, "")
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, result.stdout)
        return result.returncode, json.loads(lines[0])

    def test_audit_rotation_preserves_archives_and_records_new_primary_event(self):
        audit = DurableAudit(*self.layout.audit, full_verify_every=0)
        for number in range(5):
            audit({"event": "before_cli_rotation", "operation_id": "op-%d" % number})
        audit.archive(self.layout.archive, keep=2)
        before = audit.verify(archives=self.layout.archive)
        legacy_key = self.layout.audit[1].read_bytes()

        code, payload = self.run_cli("keys", "rotate", "--store", "audit")
        self.assertEqual(code, 0)
        self.assertEqual(payload["schema"], "enkstein-guard.cli/v1")
        self.assertEqual(payload["command"], "keys rotate")
        self.assertEqual((payload["status"], payload["store"], payload["rotated"]),
                         ("ok", "audit", True))
        self.assertEqual(payload["retained_keys"], 1)
        self.assertEqual(payload["checkpoint"]["sequence"], before["sequence"] + 1)
        keyring = json.loads(self.layout.audit[1].read_bytes())
        self.assertEqual(keyring[1], legacy_key.decode("ascii"))

        reopened = DurableAudit(*self.layout.audit, full_verify_every=0)
        self.assertEqual(reopened.verify(payload["checkpoint"], archives=self.layout.archive),
                         payload["checkpoint"])
        events = list(reopened.events(archives=self.layout.archive))
        self.assertEqual(events[-1][2], {"event": "audit_key_rotated", "outcome": "audit_key_rotated"})

    def test_audit_rotation_rejects_state_lock_and_corrupt_archive_without_changing_key(self):
        original_key = self.layout.audit[1].read_bytes()
        with state_lock(self.config):
            code, payload = self.run_cli("keys", "rotate", "--store", "audit")
        self.assertEqual((code, payload["status"], payload["error"]),
                         (3, "error", "service_running_or_state_locked"))
        self.assertEqual(self.layout.audit[1].read_bytes(), original_key)

        audit = DurableAudit(*self.layout.audit, full_verify_every=0)
        audit({"event": "archive_before_failed_rotation"})
        archived = audit.archive(self.layout.archive, keep=0)
        archive_path = self.layout.archive / archived["file"]
        archive_path.write_bytes(archive_path.read_bytes() + b"corrupt")
        code, payload = self.run_cli("keys", "rotate", "--store", "audit")
        self.assertEqual((code, payload["status"], payload["error"]),
                         (3, "error", "audit_key_rotation_failed"))
        self.assertEqual(self.layout.audit[1].read_bytes(), original_key)

    def test_vault_rotation_payload_and_audit_event_remain_unchanged(self):
        code, payload = self.run_cli("keys", "rotate", "--store", "vault")
        self.assertEqual(code, 0)
        self.assertEqual(payload, {
            "schema": "enkstein-guard.cli/v1", "command": "keys rotate", "status": "ok",
            "store": "vault", "rotated": True,
        })
        events = list(DurableAudit(*self.layout.audit, full_verify_every=0).events())
        self.assertEqual(events[-1][2], {"event": "vault_key_rotated", "outcome": "vault_key_rotated"})


if __name__ == "__main__":
    unittest.main()
