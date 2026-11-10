"""Offline CLI rotation, recovery and rotated backup contracts."""
from contextlib import redirect_stdout
import fcntl
import hashlib
import io
import json
import os
import shutil
import time
import unittest
from unittest.mock import patch

from cryptography.fernet import MultiFernet
from enkstein_guard import cli, maintenance
from enkstein_guard.approval_store import ApprovalStore
from enkstein_guard.host import StateLayout
from enkstein_guard.identities import SecretStore
from enkstein_guard.productconfig import load
import test_cli as cli_fixtures
import test_approval_key_rotation as approval_fixtures


class StoreKeyRotationCLITests(unittest.TestCase):
    setUp = cli_fixtures.CLITests.setUp
    run_cli = cli_fixtures.CLITests.run_cli
    start_service = cli_fixtures.CLITests.start_service
    stop_service = cli_fixtures.CLITests.stop_service

    def prepare(self):
        self.assertEqual(self.run_cli("init")[0], 0)
        config = load(self.config)
        layout = StateLayout(config)
        SecretStore(*layout.secrets).set(
            "provider", "synthetic-private-provider-value", tenant="tenant-a",
            destination="api.example.test", routes=["model.answer"])
        store = ApprovalStore(*layout.approvals)
        binding = approval_fixtures.ApprovalKeyRotationTests.binding("consumed")
        digest = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        now = time.time()
        item = store.request(binding, digest, {"note": "synthetic-private-ticket"},
                             expires=now + 3600, created=now, max_pending=32, max_per_tenant=16)
        store.decide(item["ticket"], digest, "approved", "approver", "b" * 64, now)
        store.consume(item["ticket"], digest, now, "approver", "b" * 64)
        return config, layout, item["ticket"], store.get(item["ticket"])

    def direct(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(["--config", str(self.config), *arguments])
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_subprocess_rotation_resume_and_backup_preserve_state(self):
        config, layout, ticket, snapshot = self.prepare()
        for name, pair in (("secrets", layout.secrets), ("approvals", layout.approvals)):
            old_key = pair[1].read_text()
            code, result = self.run_cli("keys", "rotate", "--store", name)
            self.assertEqual(code, 0, result)
            self.assertEqual((result["rotated"], result["key_count"], result["resumed"]), (True, 2, False))
            self.assertEqual(result["records_reencrypted"], 1)
            self.assertRegex(result["current_key_fingerprint"], "^[a-f0-9]{64}$")
            serialized = json.dumps(result)
            for secret in (old_key, "synthetic-private-provider-value", "synthetic-private-ticket", ticket):
                self.assertNotIn(secret, serialized)
            ring = json.loads(pair[1].read_bytes())
            code, resumed = self.run_cli("keys", "rotate", "--store", name, "--resume")
            self.assertEqual(code, 0, resumed)
            self.assertTrue(resumed["resumed"])
            self.assertEqual(json.loads(pair[1].read_bytes()), ring)
        self.assertEqual(ApprovalStore(*layout.approvals).get(ticket), snapshot)
        self.assertEqual(SecretStore(*layout.secrets).resolve(
            "provider", tenant="tenant-a", route="model.answer", destination="api.example.test"),
            "synthetic-private-provider-value")
        data, keys = self.root / "backup-data", self.root / "backup-keys"
        maintenance.create_backup(config, data, keys)
        self.assertTrue(maintenance.verify_backup(data, keys)["verified"])
        # Offline replacement through the real restore path verifies both rings.
        for directory in (layout.state, layout.keys, layout.archive):
            if directory.exists():
                shutil.rmtree(directory)
        maintenance.restore_backup(config, data, keys)
        self.assertEqual(ApprovalStore(*layout.approvals).get(ticket), snapshot)

    def test_running_service_blocks_both_stores_without_changes(self):
        cli_fixtures.CLITests.initialize(self)
        layout = StateLayout(load(self.config))
        self.start_service()
        for name, pair in (("secrets", layout.secrets), ("approvals", layout.approvals)):
            before = tuple(path.read_bytes() for path in pair)
            code, result = self.run_cli("keys", "rotate", "--store", name)
            self.assertNotEqual(code, 0, result)
            self.assertEqual(tuple(path.read_bytes() for path in pair), before)

    def test_post_publish_failure_reports_uncertainty_and_cli_resumes(self):
        _, layout, ticket, snapshot = self.prepare()
        for name, pair in (("secrets", layout.secrets), ("approvals", layout.approvals)):
            with patch.object(MultiFernet, "rotate", side_effect=RuntimeError("private-fault-text")):
                code, result = self.direct("keys", "rotate", "--store", name)
            self.assertEqual(code, 3, result)
            self.assertEqual(result["error"], "key_rotation_state_unknown")
            self.assertTrue(result["resume_may_be_required"])
            self.assertNotIn("private-fault-text", json.dumps(result))
            ring = json.loads(pair[1].read_bytes())
            self.assertEqual(len(ring), 2)
            code, result = self.run_cli("keys", "rotate", "--store", name, "--resume")
            self.assertEqual(code, 0, result)
            self.assertEqual(json.loads(pair[1].read_bytes()), ring)
        self.assertEqual(ApprovalStore(*layout.approvals).get(ticket), snapshot)

    def test_audit_failure_before_and_after_rotation_is_honest(self):
        _, layout, _, _ = self.prepare()
        from enkstein_guard.audit import DurableAudit
        for name, pair in (("secrets", layout.secrets), ("approvals", layout.approvals)):
            old = pair[1].read_bytes()
            with patch.object(DurableAudit, "verify", side_effect=RuntimeError("private-audit-text")):
                code, result = self.direct("keys", "rotate", "--store", name)
            self.assertEqual((code, result["error"], result["rotated"]), (3, "audit_verification_failed", False))
            self.assertEqual(pair[1].read_bytes(), old)
            with patch.object(DurableAudit, "__call__", side_effect=RuntimeError("private-audit-text")):
                code, result = self.direct("keys", "rotate", "--store", name)
            self.assertEqual((code, result["error"], result["rotated"]), (3, "rotated_but_audit_unavailable", True))
            self.assertEqual(len(json.loads(pair[1].read_bytes())), 2)
            self.assertNotIn("private-audit-text", json.dumps(result))

    def test_resume_rejected_for_existing_stores_before_mutation(self):
        _, layout, _, _ = self.prepare()
        for name, pair in (("vault", layout.vault), ("audit", layout.audit)):
            before = tuple(p.read_bytes() for p in pair)
            code, result = self.run_cli("keys", "rotate", "--store", name, "--resume")
            self.assertEqual((code, result["error"]), (3, "resume_not_supported_for_store"))
            self.assertEqual(tuple(p.read_bytes() for p in pair), before)

    def test_competing_rotator_reports_busy_without_mutating_stores(self):
        _, layout, _, _ = self.prepare()
        cases = (
            ("secrets", layout.secrets, layout.secrets[0].with_name(
                layout.secrets[0].name + ".rotation.lock"), "secret_store_rotation_busy"),
            ("approvals", layout.approvals, layout.approvals[1].with_name(
                layout.approvals[1].name + ".rotation.lock"), "approval_key_rotation_in_progress"),
        )
        for name, paths, lock, error in cases:
            before = tuple(path.read_bytes() for path in paths)
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                code, result = self.run_cli("keys", "rotate", "--store", name)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            self.assertEqual((code, result["error"]), (3, error), result)
            self.assertNotIn("resume_may_be_required", result)
            self.assertEqual(tuple(path.read_bytes() for path in paths), before)
