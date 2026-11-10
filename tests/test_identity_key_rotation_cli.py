"""Offline identity signing rotation preserves authentication and backup state."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import shutil
import unittest
from unittest.mock import patch

from enkstein_guard import cli, maintenance
from enkstein_guard.audit import DurableAudit
from enkstein_guard.host import HostError, StateLayout
from enkstein_guard.identities import IdentityStore
from enkstein_guard.productconfig import load
import test_cli as fixtures


class IdentityKeyRotationCLITests(unittest.TestCase):
    setUp = fixtures.CLITests.setUp
    run_cli = fixtures.CLITests.run_cli
    start_service = fixtures.CLITests.start_service
    stop_service = fixtures.CLITests.stop_service

    def prepare(self):
        token = fixtures.CLITests.initialize(self)
        config = load(self.config)
        layout = StateLayout(config)
        store = IdentityStore(*layout.identities)
        store.issue("agent", "revoked-agent", self.root / "revoked.token")
        store.revoke("agent", "revoked-agent")
        store.issue("approver", "reviewer", self.root / "reviewer.token")
        return config, layout, token, json.loads(layout.identities[0].read_text())["body"]

    def direct(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(["--config", str(self.config), *arguments])
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_rotation_resume_backup_and_service_authentication(self):
        config, layout, token, before = self.prepare()
        old_key = layout.identities[1].read_text()
        code, result = self.run_cli("keys", "rotate", "--store", "identities")
        self.assertEqual(code, 0, result)
        self.assertEqual((result["rotated"], result["key_count"], result["records_reauthenticated"]),
                         (True, 2, 3))
        self.assertNotIn("records_reencrypted", result)
        self.assertNotIn(old_key, json.dumps(result))
        self.assertNotIn(token, json.dumps(result))
        self.assertEqual(json.loads(layout.identities[0].read_text())["body"], before)
        ring = layout.identities[1].read_bytes()
        code, result = self.run_cli("keys", "rotate", "--store", "identities", "--resume")
        self.assertEqual(code, 0, result)
        self.assertTrue(result["resumed"])
        self.assertEqual(layout.identities[1].read_bytes(), ring)
        data, keys = self.root / "backup-data", self.root / "backup-keys"
        maintenance.create_backup(config, data, keys)
        self.assertTrue(maintenance.verify_backup(data, keys)["verified"])
        for directory in (layout.state, layout.keys, layout.archive):
            directory.relative_to(self.root)
            if directory.exists():
                shutil.rmtree(directory)
        maintenance.restore_backup(config, data, keys)
        self.assertEqual(json.loads(layout.identities[0].read_text())["body"], before)
        restored = IdentityStore(*layout.identities)
        self.assertNotIn("revoked-agent", restored.digests("agent"))
        self.assertEqual(restored.digests("agent")["agent-a"], hashlib.sha256(token.encode()).digest())
        self.start_service()
        payload = self.root / "request.json"
        payload.write_text(json.dumps({"ticket": "INC-42", "comment": "hello"}))
        code, response = self.run_cli(
            "request", "--socket", str(self.root / "sock/guard.sock"),
            "--credential-file", str(self.root / "agent.token"), "--route", "ticket.comment",
            "--payload-file", str(payload), "--new-request-id")
        self.assertEqual((code, response["status"]), (0, "ok"), response)

    def test_running_service_refuses_without_changing_identity_files(self):
        _, layout, _, _ = self.prepare()
        self.start_service()
        before = tuple(path.read_bytes() for path in layout.identities)
        code, result = self.run_cli("keys", "rotate", "--store", "identities")
        self.assertEqual((code, result["error"]), (3, "service_running_or_state_locked"))
        self.assertEqual(tuple(path.read_bytes() for path in layout.identities), before)

    def test_audit_failure_states_and_no_sensitive_errors(self):
        _, layout, _, _ = self.prepare()
        before = tuple(path.read_bytes() for path in layout.identities)
        with patch.object(DurableAudit, "verify", side_effect=RuntimeError("private-audit-detail")):
            code, result = self.direct("keys", "rotate", "--store", "identities")
        self.assertEqual((code, result["error"], result["rotated"]),
                         (3, "audit_verification_failed", False))
        self.assertEqual(tuple(path.read_bytes() for path in layout.identities), before)
        with patch.object(DurableAudit, "__call__", side_effect=RuntimeError("private-audit-detail")):
            code, result = self.direct("keys", "rotate", "--store", "identities")
        self.assertEqual((code, result["error"], result["rotated"]),
                         (3, "rotated_but_audit_unavailable", True))
        self.assertNotIn("private-audit-detail", json.dumps(result))
        self.assertNotEqual(layout.identities[1].read_bytes(), before[1])
        code, result = self.run_cli("keys", "rotate", "--store", "identities", "--resume")
        self.assertEqual(code, 0, result)
        self.assertEqual(result["key_count"], 2)

    def test_backup_rejects_identity_tamper_even_with_updated_manifest_hash(self):
        config, layout, _, _ = self.prepare()
        data, keys = self.root / "backup-data", self.root / "backup-keys"
        maintenance.create_backup(config, data, keys)
        manifest = json.loads((data / maintenance.MANIFEST).read_text())
        entry = next(row for row in manifest["files"] if row["store"] == "identities")
        path = data / entry["data"]
        envelope = json.loads(path.read_text())
        envelope["body"]["agent"]["revoked-agent"]["revoked_at"] = None
        path.write_text(json.dumps(envelope))
        entry["data_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        for directory in (data, keys):
            (directory / maintenance.MANIFEST).write_text(json.dumps(manifest))
        with self.assertRaisesRegex(HostError, "^backup_identity_store_invalid$"):
            maintenance.verify_backup(data, keys)
        for directory in (layout.state, layout.keys, layout.archive):
            directory.relative_to(self.root)
            if directory.exists():
                shutil.rmtree(directory)
        with self.assertRaisesRegex(HostError, "^backup_identity_store_invalid$"):
            maintenance.restore_backup(config, data, keys)
        self.assertFalse(any(database.exists() or key.exists()
                             for database, key in layout.stores().values()))
