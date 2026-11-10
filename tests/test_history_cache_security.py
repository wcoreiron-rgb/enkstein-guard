from contextlib import closing
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from cryptography.fernet import Fernet, MultiFernet

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


class HistoryCacheSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-history-cache-security-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock()

    def paths(self, name="store"):
        root = self.root / name
        return root / "state/history.sqlite3", root / "keys/history.key"

    def initialize(self, name="store", *, capacity=32, ttl=3600, per_actor=16):
        database, key = self.paths(name)
        store = SecurityHistoryStore.initialize(
            database, key, capacity=capacity, ttl_seconds=ttl,
            per_actor_capacity=per_actor, clock=self.clock,
        )
        return store, database, key

    def reopen(self, database, key, *, capacity=32, ttl=3600, per_actor=16):
        return SecurityHistoryStore(
            database, key, capacity=capacity, ttl_seconds=ttl,
            per_actor_capacity=per_actor, clock=self.clock,
        )

    @staticmethod
    def operation(*, tenant="tenant-a", principal="operator-a", agent="agent-a",
                  operation_id="operation-a"):
        context = SecurityContext(
            tenant, principal, agent, "workflow-a", operation_id,
            "ticket.update", "policy-1",
        )
        payload = "{}"
        return Operation(
            context, "ticket.write", "support-ticket", "internal-service",
            payload, hashlib.sha256(payload.encode()).hexdigest(),
        )

    @staticmethod
    def assessment(index=0):
        return SecurityAssessment(1, f"{index:064x}", "allow", "low", 0.9, ())

    def record(self, store, operation, index=0, action=Action.ALLOW):
        store.record(operation, self.assessment(index), action)

    @staticmethod
    def warm(store, operation):
        rows = store.recent(operation)
        store.verify()
        return rows

    def assert_integrity_failure(self, call):
        with self.assertRaisesRegex(
                SecurityHistoryError, "^security_history_integrity_failed$"):
            call()

    def test_warmed_exact_row_changes_and_wrong_selector_record_fail_closed(self):
        mutations = {
            "ciphertext": ("UPDATE history SET record=? WHERE id=1", (b"corrupt",)),
            "actor": ("UPDATE history SET actor=? WHERE id=1", (b"x" * 32,)),
            "tenant": ("UPDATE history SET tenant=? WHERE id=1", (b"y" * 32,)),
            "created": ("UPDATE history SET created=created+1 WHERE id=1", ()),
            "expires": ("UPDATE history SET expires=expires+1 WHERE id=1", ()),
        }
        for name, (statement, parameters) in mutations.items():
            with self.subTest(mutation=name):
                store, database, _ = self.initialize(name)
                selected = self.operation(operation_id=f"selected-{name}")
                self.record(store, selected)
                self.warm(store, selected)
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(statement, parameters)
                    connection.commit()
                self.assert_integrity_failure(lambda: store.recent(selected))

        store, database, _ = self.initialize("wrong-selector-record")
        selected = self.operation(agent="agent-a", operation_id="selected")
        foreign = self.operation(agent="agent-b", operation_id="foreign")
        self.record(store, selected, 1)
        self.record(store, foreign, 2)
        self.warm(store, selected)
        with closing(sqlite3.connect(database)) as connection:
            ciphertexts = connection.execute(
                "SELECT id,record FROM history ORDER BY id"
            ).fetchall()
            connection.execute(
                "UPDATE history SET record=? WHERE id=?",
                (ciphertexts[1][1], ciphertexts[0][0]),
            )
            connection.commit()
        self.assert_integrity_failure(lambda: store.recent(selected))

    def test_unselected_actor_corruption_blocks_every_public_data_operation(self):
        for method in ("recent", "record", "verify"):
            with self.subTest(method=method):
                store, database, _ = self.initialize(f"unselected-{method}")
                selected = self.operation(agent="selected", operation_id="selected")
                foreign = self.operation(agent="foreign", operation_id="foreign")
                self.record(store, selected, 1)
                self.record(store, foreign, 2)
                self.warm(store, selected)
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(
                        "UPDATE history SET record=? WHERE id=(SELECT max(id) FROM history)",
                        (b"corrupt-unselected-row",),
                    )
                    connection.commit()
                if method == "recent":
                    call = lambda: store.recent(selected)
                elif method == "record":
                    call = lambda: self.record(
                        store,
                        self.operation(agent="selected", operation_id="new-selected"), 3,
                    )
                else:
                    call = store.verify
                self.assert_integrity_failure(call)

    def test_warmed_identity_options_and_private_paths_are_rechecked(self):
        operation = self.operation()
        store, database, _ = self.initialize("identity-ciphertext")
        self.record(store, operation)
        self.warm(store, operation)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("UPDATE identity SET record=?", (b"corrupt-identity",))
            connection.commit()
        self.assert_integrity_failure(lambda: store.recent(operation))

        store, database, key = self.initialize("identity-options")
        self.record(store, operation)
        self.warm(store, operation)
        cipher = Fernet(key.read_bytes())
        with closing(sqlite3.connect(database)) as connection:
            encrypted = connection.execute("SELECT record FROM identity").fetchone()[0]
            identity = json.loads(cipher.decrypt(encrypted))
            identity["capacity"] += 1
            replacement = cipher.encrypt(json.dumps(
                identity, sort_keys=True, separators=(",", ":")
            ).encode())
            connection.execute("UPDATE identity SET record=?", (replacement,))
            connection.commit()
        with self.assertRaisesRegex(
                SecurityHistoryError, "^security_history_configuration_mismatch$"):
            store.verify()

        store, database, _ = self.initialize("private-path")
        self.record(store, operation)
        self.warm(store, operation)
        os.chmod(database, 0o644)
        with self.assertRaises(SecurityHistoryError):
            store.recent(operation)

    def test_external_handle_row_is_immediately_visible_and_capacity_is_current(self):
        store, database, key = self.initialize("external", capacity=16, per_actor=16)
        operations = [
            self.operation(agent=f"agent-{index}", operation_id=f"operation-{index}")
            for index in range(16)
        ]
        for index, operation in enumerate(operations[:15]):
            self.record(store, operation, index)
        self.warm(store, operations[0])

        external = self.reopen(database, key, capacity=16, per_actor=16)
        self.record(external, operations[15], 15)

        self.assertEqual(store.recent(operations[15])[0].operation_id, "operation-15")
        with self.assertRaisesRegex(
                SecurityHistoryError, "^security_history_capacity_reached$"):
            self.record(
                store,
                self.operation(agent="agent-16", operation_id="operation-16"), 16,
            )
        self.assertEqual(store.verify()["records"], 16)

    def test_new_malformed_and_over_capacity_sql_rows_are_not_hidden_by_warm_cache(self):
        store, database, _ = self.initialize("new-malformed")
        operation = self.operation()
        self.record(store, operation)
        self.warm(store, operation)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "INSERT INTO history(actor,tenant,created,expires,record) VALUES (?,?,?,?,?)",
                (b"a" * 32, b"t" * 32, self.clock.now,
                 self.clock.now + 3600, b"new-malformed-row"),
            )
            connection.commit()
        self.assert_integrity_failure(lambda: store.recent(operation))

        store, database, _ = self.initialize(
            "global-over-capacity", capacity=16, per_actor=16
        )
        for index in range(16):
            self.record(
                store,
                self.operation(agent=f"agent-{index}", operation_id=f"operation-{index}"),
                index,
            )
        self.warm(store, self.operation(agent="agent-0", operation_id="operation-0"))
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "INSERT INTO history(actor,tenant,created,expires,record) "
                "SELECT actor,tenant,created,expires,record FROM history WHERE id=1"
            )
            connection.commit()
        self.assert_integrity_failure(store.verify)

        store, database, _ = self.initialize(
            "actor-over-capacity", capacity=32, per_actor=16
        )
        noisy = self.operation(agent="noisy")
        for index in range(16):
            self.record(
                store,
                self.operation(agent="noisy", operation_id=f"noisy-{index}"), index,
            )
        self.warm(store, noisy)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "INSERT INTO history(actor,tenant,created,expires,record) "
                "SELECT actor,tenant,created,expires,record FROM history WHERE id=1"
            )
            connection.commit()
        self.assert_integrity_failure(lambda: store.recent(noisy))

    def test_warmed_rows_expire_and_are_purged_using_the_current_clock(self):
        store, database, _ = self.initialize("ttl", capacity=16, ttl=10, per_actor=16)
        operation = self.operation()
        for index in range(16):
            self.record(
                store,
                self.operation(operation_id=f"operation-{index}"), index,
            )
        self.assertEqual(len(self.warm(store, operation)), 16)

        self.clock.now += 11

        self.assertEqual(store.recent(operation), ())
        self.assertEqual(store.verify(), {"status": "verified", "records": 0})
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM history").fetchone()[0], 0)

    def test_roll_and_full_store_preserve_other_actors_after_warm_reads(self):
        store, _, _ = self.initialize("roll", capacity=32, per_actor=16)
        quiet = self.operation(agent="quiet", operation_id="quiet")
        self.record(store, quiet, 100, Action.DENY)
        for index in range(16):
            self.clock.now += 0.01
            self.record(
                store,
                self.operation(agent="noisy", operation_id=f"noisy-{index}"), index,
            )
        noisy = self.operation(agent="noisy")
        self.warm(store, noisy)
        self.record(store, self.operation(agent="noisy", operation_id="noisy-16"), 16)
        noisy_ids = {item.operation_id for item in store.recent(noisy)}
        self.assertEqual(len(noisy_ids), 16)
        self.assertNotIn("noisy-0", noisy_ids)
        self.assertIn("noisy-16", noisy_ids)
        self.assertEqual(store.recent(quiet)[0].operation_id, "quiet")

        store, _, _ = self.initialize("full", capacity=16, per_actor=16)
        existing = []
        for index in range(16):
            operation = self.operation(
                agent=f"actor-{index}", operation_id=f"existing-{index}"
            )
            existing.append(operation)
            self.record(store, operation, index)
        self.warm(store, existing[0])
        with self.assertRaisesRegex(
                SecurityHistoryError, "^security_history_capacity_reached$"):
            self.record(
                store,
                self.operation(agent="new-actor", operation_id="must-not-evict"), 17,
            )
        self.assertEqual(store.verify()["records"], 16)
        self.assertEqual(store.recent(existing[-1])[0].operation_id, "existing-15")

    def test_rotation_after_warm_requires_fresh_handle_and_preserves_rows(self):
        store, database, key = self.initialize("rotation")
        operations = [
            self.operation(agent=f"agent-{index}", operation_id=f"operation-{index}")
            for index in range(16)
        ]
        for index, operation in enumerate(operations):
            self.record(store, operation, index)
        stale = self.reopen(database, key)
        self.warm(store, operations[0])
        self.warm(stale, operations[1])

        store.rotate_key()

        fresh = self.reopen(database, key)
        self.assertEqual(fresh.verify()["records"], 16)
        for operation in operations:
            self.assertEqual(
                fresh.recent(operation)[0].operation_id,
                operation.context.operation_id,
            )
        with self.assertRaisesRegex(
                SecurityHistoryError, "^security_history_key_changed$"):
            stale.recent(operations[0])

    def test_partial_publication_resume_keeps_selector_binding(self):
        store, database, key = self.initialize("resume")
        first = self.operation(agent="agent-a", operation_id="first")
        second = self.operation(agent="agent-b", operation_id="second")
        self.record(store, first, 1)
        self.record(store, second, 2)
        self.warm(store, first)

        with mock.patch.object(
                MultiFernet, "rotate", side_effect=RuntimeError("synthetic failure")):
            with self.assertRaisesRegex(
                    SecurityHistoryError, "^security_history_key_rotation_failed$"):
                store.rotate_key()

        recovery = self.reopen(database, key)
        self.assertEqual(recovery.recent(first)[0].operation_id, "first")
        self.assertEqual(recovery.recent(second)[0].operation_id, "second")
        result = recovery.rotate_key(resume=True)
        self.assertTrue(result["resumed"])
        self.warm(recovery, first)

        with closing(sqlite3.connect(database)) as connection:
            first_actor = connection.execute(
                "SELECT actor FROM history WHERE id=1"
            ).fetchone()[0]
            connection.execute("UPDATE history SET actor=? WHERE id=2", (first_actor,))
            connection.commit()
        self.assert_integrity_failure(lambda: recovery.recent(first))

    def test_recent_results_are_immutable_and_cannot_poison_later_reads(self):
        store, _, _ = self.initialize("immutable")
        operation = self.operation(operation_id="original")
        self.record(store, operation, 1)
        rows = self.warm(store, operation)

        with self.assertRaises(FrozenInstanceError):
            rows[0].operation_id = "poisoned"
        with self.assertRaises(TypeError):
            rows[0] = None
        with self.assertRaises(FrozenInstanceError):
            rows[0].signals += ("poisoned",)

        later = store.recent(operation)
        self.assertEqual(later[0].operation_id, "original")
        self.assertEqual(later[0].signals, ())


if __name__ == "__main__":
    unittest.main()
