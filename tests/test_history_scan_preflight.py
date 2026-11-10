from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.runtime import Operation
from enkstein_guard.security_assessment import SecurityAssessment
from enkstein_guard.security_context import (
    MAX_RECORD_BYTES,
    SecurityHistoryError,
    SecurityHistoryStore,
)


class Clock:
    def __init__(self):
        self.now = 1_900_000_000.0

    def __call__(self):
        return self.now


class TrackingConnection:
    def __init__(self, connection, *, forbid_rows=False):
        self.connection = connection
        self.forbid_rows = forbid_rows
        self.queries = []

    def execute(self, statement, parameters=()):
        self.queries.append((statement, parameters))
        if self.forbid_rows and statement.startswith(
                "SELECT id, actor, tenant, created, expires, record"):
            raise AssertionError("ciphertext rows fetched after failed preflight")
        return self.connection.execute(statement, parameters)


class ScalarCursor:
    def __init__(self, value, *, scalar):
        self.value = value
        self.scalar = scalar
        self.fetchone_calls = 0
        self.fetchall_calls = 0

    def fetchone(self):
        if not self.scalar:
            raise AssertionError("row cursor used as scalar")
        self.fetchone_calls += 1
        return self.value

    def fetchall(self):
        if self.scalar:
            raise AssertionError("aggregate metadata was materialized")
        self.fetchall_calls += 1
        return self.value


class ScalarConnection:
    def __init__(self, metadata, rows=()):
        self.metadata = ScalarCursor(metadata, scalar=True)
        self.rows = ScalarCursor(list(rows), scalar=False)
        self.queries = []

    def execute(self, statement, parameters=()):
        self.queries.append((statement, parameters))
        if statement.startswith("SELECT COUNT(*)"):
            return self.metadata
        if statement.startswith("SELECT id, actor, tenant, created, expires, record"):
            return self.rows
        raise AssertionError(f"unexpected query: {statement}")


class HistoryScanPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-history-scan-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state/history.sqlite3"
        self.key = root / "keys/history.key"
        self.clock = Clock()

    def initialize(self):
        return SecurityHistoryStore.initialize(
            self.database,
            self.key,
            capacity=32,
            ttl_seconds=3600,
            per_actor_capacity=16,
            clock=self.clock,
        )

    @staticmethod
    def operation(operation_id="operation-a"):
        context = SecurityContext(
            "tenant-a",
            "operator-a",
            "agent-a",
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
    def assessment():
        return SecurityAssessment(1, "a" * 64, "allow", "low", 0.9, ())

    def test_empty_store_uses_one_scalar_preflight_before_full_row_fetch(self):
        store = self.initialize()
        connection = ScalarConnection((0, None))

        with store._operation_lock:
            self.assertEqual(store._records(connection), [])

        self.assertEqual(connection.metadata.fetchone_calls, 1)
        self.assertEqual(connection.metadata.fetchall_calls, 0)
        self.assertEqual(connection.rows.fetchall_calls, 1)
        self.assertEqual(len(connection.queries), 2)
        preflight, parameters = connection.queries[0]
        self.assertIn("COUNT(*)", preflight)
        self.assertIn("MAX(CASE WHEN", preflight)
        self.assertEqual(preflight.count("IS NULL"), 3)
        self.assertNotIn("GROUP BY", preflight)
        self.assertEqual(parameters, (MAX_RECORD_BYTES * 2,))

    def test_valid_store_runs_preflight_then_unchanged_six_column_fetch(self):
        store = self.initialize()
        store.record(self.operation(), self.assessment(), Action.ALLOW)
        with closing(sqlite3.connect(self.database)) as raw:
            raw.execute("BEGIN IMMEDIATE")
            connection = TrackingConnection(raw)
            with store._operation_lock:
                records = store._records(connection)

        self.assertEqual(len(records), 1)
        self.assertEqual(len(connection.queries), 2)
        self.assertTrue(connection.queries[0][0].startswith("SELECT COUNT(*)"))
        self.assertEqual(
            connection.queries[1][0],
            "SELECT id, actor, tenant, created, expires, record FROM history",
        )

    def test_bad_lengths_fail_before_ciphertext_rows_even_when_cached(self):
        store = self.initialize()
        operation = self.operation()
        store.record(operation, self.assessment(), Action.ALLOW)
        store.recent(operation)
        with closing(sqlite3.connect(self.database)) as connection:
            original = connection.execute(
                "SELECT actor,tenant,record FROM history"
            ).fetchone()

        cases = (
            ("actor", b"a" * 31),
            ("tenant", b"t" * 33),
            ("record", b"r" * (MAX_RECORD_BYTES * 2 + 1)),
        )
        for column, malformed in cases:
            with self.subTest(column=column):
                with closing(sqlite3.connect(self.database)) as connection:
                    connection.execute(f"UPDATE history SET {column}=?", (malformed,))
                    connection.commit()
                with closing(sqlite3.connect(self.database)) as raw:
                    raw.execute("BEGIN IMMEDIATE")
                    tracked = TrackingConnection(raw, forbid_rows=True)
                    with store._operation_lock, self.assertRaisesRegex(
                            SecurityHistoryError, "^security_history_integrity_failed$"):
                        store._records(tracked)
                    self.assertEqual(len(tracked.queries), 1)
                with closing(sqlite3.connect(self.database)) as connection:
                    connection.execute(
                        "UPDATE history SET actor=?,tenant=?,record=?",
                        original,
                    )
                    connection.commit()

    def test_global_capacity_fails_before_ciphertext_rows(self):
        store = self.initialize()
        store.record(self.operation(), self.assessment(), Action.ALLOW)
        with closing(sqlite3.connect(self.database)) as connection:
            for _ in range(store.capacity):
                connection.execute(
                    "INSERT INTO history(actor,tenant,created,expires,record) "
                    "SELECT actor,tenant,created,expires,record FROM history WHERE id=1"
                )
            connection.commit()

        with closing(sqlite3.connect(self.database)) as raw:
            raw.execute("BEGIN IMMEDIATE")
            tracked = TrackingConnection(raw, forbid_rows=True)
            with store._operation_lock, self.assertRaisesRegex(
                    SecurityHistoryError, "^security_history_integrity_failed$"):
                store._records(tracked)
            self.assertEqual(len(tracked.queries), 1)

    def test_malformed_scalar_shapes_and_null_semantics_fail_closed(self):
        store = self.initialize()
        malformed = (
            None,
            [0, None],
            (0,),
            (True, None),
            (-1, None),
            (0, 0),
            (1, None),
            (1, True),
            (1, 1),
            (store.capacity + 1, 0),
        )
        for metadata in malformed:
            with self.subTest(metadata=metadata):
                connection = ScalarConnection(metadata)
                with store._operation_lock, self.assertRaisesRegex(
                        SecurityHistoryError, "^security_history_integrity_failed$"):
                    store._records(connection)
                self.assertEqual(len(connection.queries), 1)
                self.assertEqual(connection.rows.fetchall_calls, 0)


if __name__ == "__main__":
    unittest.main()
