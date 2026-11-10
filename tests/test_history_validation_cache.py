from contextlib import closing
from dataclasses import FrozenInstanceError
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from cryptography.fernet import MultiFernet

os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.runtime import Operation
from enkstein_guard.security_assessment import SecurityAssessment
from enkstein_guard import security_context as history_module
from enkstein_guard.security_context import SecurityHistoryError, SecurityHistoryStore


class Clock:
    def __init__(self):
        self.now = 1_900_000_000.0

    def __call__(self):
        return self.now


class HistoryValidationCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-history-cache-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state/history.sqlite3"
        self.key = root / "keys/history.key"
        self.clock = Clock()

    def initialize(self, *, ttl=3600):
        return SecurityHistoryStore.initialize(
            self.database,
            self.key,
            capacity=32,
            ttl_seconds=ttl,
            per_actor_capacity=16,
            clock=self.clock,
        )

    def reopen(self, *, ttl=3600):
        return SecurityHistoryStore(
            self.database,
            self.key,
            capacity=32,
            ttl_seconds=ttl,
            per_actor_capacity=16,
            clock=self.clock,
        )

    @staticmethod
    def operation(*, tenant="tenant-a", principal="operator-a", agent="agent-a",
                  operation_id="operation-a"):
        context = SecurityContext(
            tenant,
            principal,
            agent,
            "workflow-a",
            operation_id,
            "ticket.update",
            "policy-1",
        )
        payload = "{}"
        return Operation(
            context,
            "ticket.write",
            "support-ticket",
            "internal-service",
            payload,
            hashlib.sha256(payload.encode()).hexdigest(),
        )

    @staticmethod
    def assessment(digest="a" * 64):
        return SecurityAssessment(1, digest, "allow", "low", 0.9, ())

    def rows(self):
        with closing(sqlite3.connect(self.database)) as connection:
            return connection.execute(
                "SELECT id,actor,tenant,created,expires,record FROM history ORDER BY id"
            ).fetchall()

    def test_unchanged_rows_reuse_validation_but_insert_is_not_primed(self):
        store = self.initialize()
        operation = self.operation()
        store.record(operation, self.assessment(), Action.ALLOW)
        self.assertEqual(len(store._history_cache), 0)

        with mock.patch.object(
                store, "_decode_record", wraps=store._decode_record) as decode:
            self.assertEqual(len(store.recent(operation)), 1)
            self.assertEqual(decode.call_count, 1)
            self.assertEqual(len(store.recent(operation)), 1)
            self.assertEqual(store.verify()["records"], 1)
            self.assertEqual(decode.call_count, 1)

    def test_changed_foreign_row_integrity_is_not_hidden_by_cached_rows(self):
        store = self.initialize()
        local = self.operation(operation_id="local")
        foreign = self.operation(tenant="tenant-b", agent="agent-b", operation_id="foreign")
        store.record(local, self.assessment("1" * 64), Action.ALLOW)
        store.record(foreign, self.assessment("2" * 64), Action.DENY)
        self.assertEqual(len(store.recent(local)), 1)
        self.assertEqual(len(store._history_cache), 2)

        foreign_id = self.rows()[1][0]
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                "UPDATE history SET actor=? WHERE id=?",
                (b"x" * 32, foreign_id),
            )
            connection.commit()

        with mock.patch.object(
                store, "_decode_record", wraps=store._decode_record) as decode:
            with self.assertRaisesRegex(
                    SecurityHistoryError, "^security_history_integrity_failed$"):
                store.recent(local)
            self.assertEqual(decode.call_count, 1)
        self.assertEqual(len(store._history_cache), 0)
        self.assertEqual(store._history_cache_bytes, 0)

    def test_ttl_is_rechecked_and_purge_immediately_evicts_cached_row(self):
        store = self.initialize(ttl=10)
        operation = self.operation()
        store.record(operation, self.assessment(), Action.ALLOW)
        self.assertEqual(len(store.recent(operation)), 1)
        self.assertEqual(len(store._history_cache), 1)

        self.clock.now += 11
        self.assertEqual(store.recent(operation), ())
        self.assertEqual(len(store._history_cache), 0)
        self.assertEqual(store._history_cache_bytes, 0)
        self.assertEqual(self.rows(), [])

    def test_cache_enforces_entry_byte_bounds_and_lru_order(self):
        self.assertEqual(history_module._HISTORY_CACHE_MAX_ENTRIES, 4096)
        self.assertEqual(history_module._HISTORY_CACHE_MAX_BYTES, 8 * 1024 * 1024)
        self.assertEqual(history_module._HISTORY_CACHE_ENTRY_OVERHEAD, 256)
        store = self.initialize()
        for index in range(3):
            store.record(
                self.operation(agent=f"agent-{index}", operation_id=f"operation-{index}"),
                self.assessment(f"{index:064x}"),
                Action.ALLOW,
            )
        rows = self.rows()

        with store._operation_lock, \
                mock.patch.object(history_module, "_HISTORY_CACHE_MAX_ENTRIES", 2), \
                mock.patch.object(history_module, "_HISTORY_CACHE_MAX_BYTES", 8 * 1024 * 1024):
            store._clear_history_cache(key_epoch=store._key_bytes)
            for row in (rows[0], rows[1], rows[0], rows[2]):
                store._cached_decode_record(row)
            self.assertEqual(tuple(store._history_cache), (rows[0][0], rows[2][0]))
            self.assertLessEqual(len(store._history_cache), 2)
            self.assertLessEqual(store._history_cache_bytes, 8 * 1024 * 1024)

        decoded = [store._decode_record(row) for row in rows[:2]]
        sizes = [store._history_cache_entry_bytes(row, item)
                 for row, item in zip(rows[:2], decoded)]
        byte_limit = max(sizes)
        with store._operation_lock, \
                mock.patch.object(history_module, "_HISTORY_CACHE_MAX_ENTRIES", 4096), \
                mock.patch.object(history_module, "_HISTORY_CACHE_MAX_BYTES", byte_limit):
            store._clear_history_cache(key_epoch=store._key_bytes)
            store._cached_decode_record(rows[0])
            store._cached_decode_record(rows[1])
            self.assertLessEqual(len(store._history_cache), 1)
            self.assertLessEqual(store._history_cache_bytes, byte_limit)

    def test_external_delete_is_pruned_before_decode_scan(self):
        store = self.initialize()
        first = self.operation(agent="agent-a", operation_id="first")
        second = self.operation(agent="agent-b", operation_id="second")
        store.record(first, self.assessment("1" * 64), Action.ALLOW)
        store.record(second, self.assessment("2" * 64), Action.ALLOW)
        store.verify()
        first_id, second_id = (row[0] for row in self.rows())
        self.assertEqual(tuple(store._history_cache), (first_id, second_id))

        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DELETE FROM history WHERE id=?", (first_id,))
            connection.commit()

        with mock.patch.object(
                store, "_decode_record", wraps=store._decode_record) as decode:
            self.assertEqual(store.verify()["records"], 1)
            self.assertEqual(decode.call_count, 0)
        self.assertEqual(tuple(store._history_cache), (second_id,))

    def test_actor_rollover_immediately_evicts_removed_row(self):
        store = self.initialize()
        operation = self.operation()
        for index in range(16):
            self.clock.now += 1
            store.record(
                self.operation(operation_id=f"operation-{index}"),
                self.assessment(f"{index:064x}"),
                Action.ALLOW,
            )
        store.verify()
        oldest_id = self.rows()[0][0]
        self.assertIn(oldest_id, store._history_cache)

        self.clock.now += 1
        store.record(
            self.operation(operation_id="operation-rollover"),
            self.assessment("f" * 64),
            Action.ALLOW,
        )

        self.assertNotIn(oldest_id, store._history_cache)
        self.assertEqual(len(store.recent(operation, limit=16)), 16)

    def test_rotation_stale_handle_and_published_rollback_invalidate_epochs(self):
        store = self.initialize()
        operation = self.operation(principal="rotation-owner")
        store.record(operation, self.assessment(), Action.DENY)
        stale = self.reopen()
        self.assertEqual(len(store.recent(operation)), 1)
        self.assertEqual(len(stale.recent(operation)), 1)
        old_epoch = store._history_cache_key_epoch

        with mock.patch.object(
                store, "_decode_record", wraps=store._decode_record) as decode:
            store.rotate_key()
            self.assertNotEqual(store._history_cache_key_epoch, old_epoch)
            self.assertEqual(len(store._history_cache), 0)
            self.assertEqual(len(store.recent(operation)), 1)
            self.assertEqual(decode.call_count, 1)
        with self.assertRaisesRegex(SecurityHistoryError, "^security_history_key_changed$"):
            stale.recent(operation)
        self.assertEqual(len(stale._history_cache), 0)

        self.assertEqual(len(store.recent(operation)), 1)
        with mock.patch.object(
                MultiFernet, "rotate", side_effect=RuntimeError("synthetic rollback")):
            with self.assertRaisesRegex(
                    SecurityHistoryError, "^security_history_key_rotation_failed$"):
                store.rotate_key()
        self.assertEqual(len(store._history_cache), 0)
        self.assertEqual(store._history_cache_key_epoch, self.key.read_bytes())
        self.assertEqual(len(store.recent(operation)), 1)

    def test_external_write_is_visible_and_returned_records_are_immutable(self):
        reader = self.initialize()
        first = self.operation(operation_id="first")
        reader.record(first, self.assessment("1" * 64), Action.ALLOW)
        initial = reader.recent(first)
        self.assertEqual(len(initial), 1)
        self.assertIsInstance(initial[0].signals, tuple)
        with self.assertRaises(FrozenInstanceError):
            initial[0].decision = "deny"

        writer = self.reopen()
        second = self.operation(operation_id="second")
        self.clock.now += 1
        writer.record(second, self.assessment("2" * 64), Action.DENY)

        with mock.patch.object(
                reader, "_decode_record", wraps=reader._decode_record) as decode:
            visible = reader.recent(first)
            self.assertEqual({item.operation_id for item in visible}, {"first", "second"})
            self.assertEqual(decode.call_count, 1)


if __name__ == "__main__":
    unittest.main()
