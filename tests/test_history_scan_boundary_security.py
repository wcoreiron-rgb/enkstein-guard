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
from enkstein_guard.security_context import SecurityHistoryError, SecurityHistoryStore


class Clock:
    def __init__(self):
        self.now = 1_900_000_000.0

    def __call__(self):
        return self.now


class HistoryScanBoundarySecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-history-scan-security-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock()

    def initialize(self, name, *, capacity=32, ttl=3600, per_actor=16):
        root = self.root / name
        database = root / "state/history.sqlite3"
        key = root / "keys/history.key"
        store = SecurityHistoryStore.initialize(
            database,
            key,
            capacity=capacity,
            ttl_seconds=ttl,
            per_actor_capacity=per_actor,
            clock=self.clock,
        )
        return store, database

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
    def assessment(index=0):
        return SecurityAssessment(1, f"{index:064x}", "allow", "low", 0.9, ())

    def record(self, store, operation, index=0):
        store.record(operation, self.assessment(index), Action.ALLOW)

    @staticmethod
    def warm(store, operation):
        store.recent(operation)
        store.verify()

    def assert_all_data_operations_fail(self, store, operation):
        calls = {
            "verify": store.verify,
            "recent": lambda: store.recent(operation),
            "record": lambda: self.record(
                store,
                self.operation(
                    tenant=operation.context.tenant_id,
                    principal=operation.context.principal_id,
                    agent=operation.context.agent_id,
                    operation_id="post-corruption-write",
                ),
                999,
            ),
        }
        for api, call in calls.items():
            with self.subTest(api=api):
                with self.assertRaisesRegex(
                        SecurityHistoryError, "^security_history_integrity_failed$"):
                    call()

    @staticmethod
    def replace_history_with_nullable_copy(database, null_column):
        columns = ("id", "actor", "tenant", "created", "expires", "record")
        with closing(sqlite3.connect(database)) as connection:
            rows = connection.execute(
                "SELECT id,actor,tenant,created,expires,record "
                "FROM history ORDER BY id"
            ).fetchall()
            connection.execute("ALTER TABLE history RENAME TO history_original")
            connection.execute(
                "CREATE TABLE history ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, actor BLOB, tenant BLOB, "
                "created REAL, expires REAL, record BLOB)"
            )
            for index, row in enumerate(rows):
                values = list(row)
                if index == len(rows) - 1:
                    values[columns.index(null_column)] = None
                connection.execute(
                    "INSERT INTO history(id,actor,tenant,created,expires,record) "
                    "VALUES (?,?,?,?,?,?)",
                    values,
                )
            connection.commit()

    def test_empty_store_scan_is_valid_and_first_record_remains_available(self):
        store, _ = self.initialize("empty", capacity=16, per_actor=16)
        operation = self.operation()

        self.assertEqual(store.verify(), {"status": "verified", "records": 0})
        self.assertEqual(store.recent(operation), ())

        self.record(store, operation, 1)
        self.assertEqual(store.verify(), {"status": "verified", "records": 1})
        self.assertEqual(store.recent(operation)[0].operation_id, "operation-a")

    def test_null_selector_or_ciphertext_from_replaced_table_fails_closed(self):
        for column in ("actor", "tenant", "record"):
            with self.subTest(column=column):
                store, database = self.initialize(f"null-{column}")
                selected = self.operation(agent="selected", operation_id="selected")
                foreign = self.operation(agent="foreign", operation_id="foreign")
                self.record(store, selected, 1)
                self.record(store, foreign, 2)
                self.warm(store, selected)

                self.replace_history_with_nullable_copy(database, column)

                self.assert_all_data_operations_fail(store, selected)

    def test_wrong_selector_lengths_and_oversize_ciphertext_fail_before_cache_use(self):
        mutations = {
            "short-actor": ("actor", b"a" * 31),
            "long-tenant": ("tenant", b"t" * 33),
            "oversize-record": ("record", b"r" * 32_769),
        }
        for name, (column, value) in mutations.items():
            with self.subTest(mutation=name):
                store, database = self.initialize(name)
                selected = self.operation(agent="selected", operation_id="selected")
                foreign = self.operation(agent="foreign", operation_id="foreign")
                self.record(store, selected, 1)
                self.record(store, foreign, 2)
                self.warm(store, selected)
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(
                        f"UPDATE history SET {column}=? WHERE id=(SELECT max(id) FROM history)",
                        (value,),
                    )
                    connection.commit()

                self.assert_all_data_operations_fail(store, selected)

    def test_global_overcount_includes_foreign_rows_expired_before_scan(self):
        store, database = self.initialize(
            "expired-overcount", capacity=16, ttl=10, per_actor=16
        )
        selected = self.operation(agent="selected", operation_id="selected")
        self.record(store, selected, 0)
        for index in range(1, 16):
            self.record(
                store,
                self.operation(agent=f"foreign-{index}", operation_id=f"foreign-{index}"),
                index,
            )
        self.warm(store, selected)
        self.clock.now += 11
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "INSERT INTO history(actor,tenant,created,expires,record) "
                "SELECT actor,tenant,created,expires,record FROM history WHERE id=2"
            )
            connection.commit()

        self.assert_all_data_operations_fail(store, selected)
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM history").fetchone()[0], 17)

    def test_per_actor_overcount_still_fails_after_scan_preflight(self):
        store, database = self.initialize(
            "actor-overcount", capacity=32, per_actor=16
        )
        actor = self.operation(agent="noisy", operation_id="lookup")
        for index in range(16):
            self.record(
                store,
                self.operation(agent="noisy", operation_id=f"noisy-{index}"),
                index,
            )
        self.warm(store, actor)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "INSERT INTO history(actor,tenant,created,expires,record) "
                "SELECT actor,tenant,created,expires,record FROM history WHERE id=1"
            )
            connection.commit()

        self.assert_all_data_operations_fail(store, actor)

    def test_same_length_foreign_ciphertext_corruption_is_not_hidden_by_warm_cache(self):
        store, database = self.initialize("foreign-ciphertext")
        selected = self.operation(agent="selected", operation_id="selected")
        foreign = self.operation(agent="foreign", operation_id="foreign")
        self.record(store, selected, 1)
        self.record(store, foreign, 2)
        self.warm(store, selected)
        with closing(sqlite3.connect(database)) as connection:
            encrypted = connection.execute(
                "SELECT record FROM history WHERE id=(SELECT max(id) FROM history)"
            ).fetchone()[0]
            corrupted = bytes((encrypted[0] ^ 1,)) + encrypted[1:]
            self.assertEqual(len(corrupted), len(encrypted))
            connection.execute(
                "UPDATE history SET record=? WHERE id=(SELECT max(id) FROM history)",
                (corrupted,),
            )
            connection.commit()

        self.assert_all_data_operations_fail(store, selected)


if __name__ == "__main__":
    unittest.main()
