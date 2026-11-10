from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.runtime import Operation
from enkstein_guard.security_assessment import SecurityAssessment
from enkstein_guard.security_context import SecurityHistoryError, SecurityHistoryStore


class Clock:
    def __init__(self):
        self.now = 1_900_000_000.0

    def __call__(self):
        return self.now


class SecurityHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-security-history-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state/history.sqlite3"
        self.key = root / "keys/history.key"
        self.clock = Clock()

    def operation(self, *, tenant="tenant-a", principal="operator",
                  agent="agent-a", workflow="workflow-a", operation_id="operation-a",
                  route="ticket.write"):
        context = SecurityContext(tenant, principal, agent, workflow, operation_id,
                                  "ticket.update", "policy-1")
        payload = "{}"
        return Operation(context, route, "support-ticket", "internal-service",
                         payload, hashlib.sha256(payload.encode()).hexdigest())

    @staticmethod
    def assessment(digest="a" * 64, *, decision="allow", risk="low", confidence=0.9):
        return SecurityAssessment(1, digest, decision, risk, confidence, ())

    def initialize(self, *, capacity=10_000, ttl=3600, per_actor=64):
        return SecurityHistoryStore.initialize(
            self.database, self.key, capacity=capacity, ttl_seconds=ttl,
            per_actor_capacity=per_actor, clock=self.clock)

    def test_actor_isolation_uses_only_trusted_operation_context(self):
        store = self.initialize()
        source = self.operation(principal="owner@example.test")
        store.record(source, self.assessment(), Action.ALLOW)
        self.assertEqual(len(store.recent(source)), 1)
        for other in (
            self.operation(tenant="tenant-b"),
            self.operation(principal="other"),
            self.operation(agent="agent-b"),
        ):
            self.assertEqual(store.recent(other), ())
        self.assertNotIn(b"owner@example.test", self.database.read_bytes())

    def test_expiry_and_recent_limit_are_bounded(self):
        store = self.initialize(ttl=10)
        operation = self.operation()
        for index in range(20):
            self.clock.now += 0.1
            item = self.operation(operation_id=f"operation-{index}")
            store.record(item, self.assessment(digest=f"{index:064x}"), Action.ALLOW)
        self.assertEqual(len(store.recent(operation, limit=16)), 16)
        self.clock.now += 11
        self.assertEqual(store.recent(operation), ())
        self.assertEqual(store.verify(), {"status": "verified", "records": 0})

    def test_noisy_actor_rolls_own_ring_without_evicting_other_actor(self):
        store = self.initialize(capacity=32, per_actor=16)
        quiet = self.operation(agent="quiet-agent", operation_id="quiet-operation")
        store.record(quiet, self.assessment(digest="f" * 64), Action.DENY)
        for index in range(1000):
            self.clock.now += 0.001
            noisy = self.operation(operation_id=f"noisy-{index}")
            store.record(noisy, self.assessment(digest=f"{index:064x}"), Action.ALLOW)
        self.assertEqual(len(store.recent(self.operation(), limit=16)), 16)
        self.assertEqual(len(store.recent(quiet)), 1)
        self.assertEqual(store.verify()["records"], 17)

    def test_full_store_does_not_evict_other_actors_for_new_actor(self):
        store = self.initialize(capacity=16, per_actor=16)
        for index in range(16):
            operation = self.operation(agent=f"agent-{index}", operation_id=f"operation-{index}")
            store.record(operation, self.assessment(digest=f"{index:064x}"), Action.ALLOW)
        with self.assertRaisesRegex(SecurityHistoryError, "security_history_capacity_reached"):
            store.record(self.operation(agent="new-agent"), self.assessment(), Action.ALLOW)
        self.assertEqual(store.verify()["records"], 16)

    def test_corruption_missing_key_and_configuration_change_fail_closed(self):
        store = self.initialize(capacity=32, per_actor=16)
        store.record(self.operation(), self.assessment(), Action.ALLOW)
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE history SET record=?", (b"corrupt",))
            connection.commit()
        with self.assertRaisesRegex(SecurityHistoryError, "security_history_integrity_failed"):
            SecurityHistoryStore(self.database, self.key, capacity=32,
                                 per_actor_capacity=16, clock=self.clock)
        with self.assertRaises(SecurityHistoryError):
            SecurityHistoryStore(self.database, self.key, capacity=33,
                                 per_actor_capacity=16, clock=self.clock)
        self.key.unlink()
        with self.assertRaises(SecurityHistoryError):
            SecurityHistoryStore(self.database, self.key, capacity=32,
                                 per_actor_capacity=16, clock=self.clock)

    def test_private_paths_and_sqlite_write_failure(self):
        store = self.initialize()
        self.assertEqual(os.stat(self.database).st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.key).st_mode & 0o077, 0)
        with mock.patch("enkstein_guard.security_context.sqlite3.connect",
                        side_effect=sqlite3.OperationalError("synthetic full disk")):
            with self.assertRaisesRegex(SecurityHistoryError, "security_history_storage_unavailable"):
                store.record(self.operation(), self.assessment(), Action.ALLOW)


if __name__ == "__main__":
    unittest.main()
