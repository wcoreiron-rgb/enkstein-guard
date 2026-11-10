"""Offline history-key CLI, actor binding, expiry and backup contracts."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import shutil
import time
import unittest
from unittest.mock import patch

from enkstein_guard import cli, maintenance
from enkstein_guard.audit import DurableAudit
from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.host import StateLayout, security_history_limits
from enkstein_guard.productconfig import load
from enkstein_guard.runtime import Operation
from enkstein_guard.security_assessment import SecurityAssessment
from enkstein_guard.security_context import SecurityHistoryStore
import test_cli as fixtures


class HistoryKeyRotationCLITests(unittest.TestCase):
    setUp = fixtures.CLITests.setUp
    run_cli = fixtures.CLITests.run_cli
    start_service = fixtures.CLITests.start_service
    stop_service = fixtures.CLITests.stop_service

    @staticmethod
    def operation(tenant="tenant-a", principal="history-owner", agent="agent-a"):
        context = SecurityContext(tenant, principal, agent, "workflow-a", "operation-a",
                                  "ticket.update", "policy-1")
        payload = "{}"
        return Operation(context, "ticket.comment", "support-ticket", "internal-service",
                         payload, hashlib.sha256(payload.encode()).hexdigest())

    def prepare(self):
        self.assertEqual(self.run_cli("init")[0], 0)
        config = load(self.config)
        layout = StateLayout(config)
        store = SecurityHistoryStore(*layout.security_history, **security_history_limits(config))
        for index, operation in enumerate((self.operation(), self.operation(tenant="tenant-b"))):
            assessment = SecurityAssessment(1, f"{index + 1:064x}", "allow", "low", 0.9, ())
            store.record(operation, assessment, Action.ALLOW)
        snapshots = (store.recent(self.operation()), store.recent(self.operation(tenant="tenant-b")))
        return config, layout, snapshots

    def direct(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(["--config", str(self.config), *arguments])
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_rotation_resume_and_paired_backup_preserve_actor_histories(self):
        config, layout, snapshots = self.prepare()
        old_key = layout.security_history[1].read_text()
        code, result = self.run_cli("keys", "rotate", "--store", "security-history")
        self.assertEqual(code, 0, result)
        self.assertEqual((result["rotated"], result["key_count"], result["records_reencrypted"]),
                         (True, 2, 2))
        self.assertRegex(result["current_key_fingerprint"], "^[a-f0-9]{64}$")
        self.assertNotIn(old_key, json.dumps(result))
        ring = layout.security_history[1].read_bytes()
        code, result = self.run_cli("keys", "rotate", "--store", "security-history", "--resume")
        self.assertEqual(code, 0, result)
        self.assertTrue(result["resumed"])
        self.assertEqual(layout.security_history[1].read_bytes(), ring)
        store = SecurityHistoryStore(*layout.security_history, **security_history_limits(config))
        self.assertEqual(store.recent(self.operation()), snapshots[0])
        self.assertEqual(store.recent(self.operation(tenant="tenant-b")), snapshots[1])
        self.assertEqual(store.recent(self.operation(principal="other-owner")), ())
        self.assertEqual(store.recent(self.operation(agent="other-agent")), ())
        data, keys = self.root / "backup-data", self.root / "backup-keys"
        maintenance.create_backup(config, data, keys)
        self.assertTrue(maintenance.verify_backup(data, keys)["verified"])
        for directory in (layout.state, layout.keys, layout.archive):
            directory.relative_to(self.root)
            if directory.exists():
                shutil.rmtree(directory)
        maintenance.restore_backup(config, data, keys)
        restored = SecurityHistoryStore(*layout.security_history, **security_history_limits(config))
        self.assertEqual(restored.recent(self.operation()), snapshots[0])
        self.assertEqual(restored.recent(self.operation(tenant="tenant-b")), snapshots[1])

    def test_running_service_refuses_rotation_without_key_change(self):
        fixtures.CLITests.initialize(self)
        layout = StateLayout(load(self.config))
        self.start_service()
        before = tuple(path.read_bytes() for path in layout.security_history)
        code, result = self.run_cli("keys", "rotate", "--store", "security-history")
        self.assertNotEqual(code, 0, result)
        self.assertEqual(tuple(path.read_bytes() for path in layout.security_history), before)

    def test_audit_failures_distinguish_unchanged_from_already_rotated(self):
        _, layout, _ = self.prepare()
        before = layout.security_history[1].read_bytes()
        with patch.object(DurableAudit, "verify", side_effect=RuntimeError("synthetic-private-audit")):
            code, result = self.direct("keys", "rotate", "--store", "security-history")
        self.assertEqual((code, result["error"], result["rotated"]),
                         (3, "audit_verification_failed", False))
        self.assertEqual(layout.security_history[1].read_bytes(), before)
        with patch.object(DurableAudit, "__call__", side_effect=RuntimeError("synthetic-private-audit")):
            code, result = self.direct("keys", "rotate", "--store", "security-history")
        self.assertEqual((code, result["error"], result["rotated"]),
                         (3, "rotated_but_audit_unavailable", True))
        self.assertNotIn("synthetic-private-audit", json.dumps(result))
        self.assertEqual(len(json.loads(layout.security_history[1].read_bytes())), 2)

    def test_expiry_on_reopen_does_not_report_a_false_rotation_failure(self):
        config, layout, _ = self.prepare()
        clock = {"now": time.time()}
        original = SecurityHistoryStore.rotate_key

        def rotate_and_expire(store, *, resume=False):
            result = original(store, resume=resume)
            clock["now"] += config["security_history"]["ttl_seconds"] + 1
            return result

        with (patch.object(SecurityHistoryStore, "_now", lambda store: clock["now"]),
              patch.object(SecurityHistoryStore, "rotate_key", rotate_and_expire)):
            code, result = self.direct("keys", "rotate", "--store", "security-history")
        self.assertEqual(code, 0, result)
        self.assertEqual(result["records_reencrypted"], 2)
        self.assertEqual(SecurityHistoryStore(
            *layout.security_history, **security_history_limits(config)).verify()["records"], 0)
