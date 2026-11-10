from contextlib import closing
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
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


class HistoryKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-history-key-rotation-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.database = root / "state/history.sqlite3"
        self.key = root / "keys/history.key"
        self.clock = Clock()

    def operation(self, *, tenant="tenant-a", principal="operator-a", agent="agent-a",
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
    def assessment(digest="a" * 64):
        return SecurityAssessment(1, digest, "allow", "low", 0.9, ())

    def initialize(self, *, database=None, key=None, capacity=32, ttl=3600, per_actor=16):
        return SecurityHistoryStore.initialize(
            database or self.database,
            key or self.key,
            capacity=capacity,
            ttl_seconds=ttl,
            per_actor_capacity=per_actor,
            clock=self.clock,
        )

    def reopen(self, *, database=None, key=None, capacity=32, ttl=3600, per_actor=16):
        return SecurityHistoryStore(
            database or self.database,
            key or self.key,
            capacity=capacity,
            ttl_seconds=ttl,
            per_actor_capacity=per_actor,
            clock=self.clock,
        )

    def test_legacy_rotation_reopen_preserves_rows_selectors_and_limits(self):
        store = self.initialize()
        actors = (
            self.operation(operation_id="first"),
            self.operation(principal="operator-b", operation_id="second"),
            self.operation(agent="agent-b", operation_id="third"),
            self.operation(tenant="tenant-b", operation_id="fourth"),
        )
        for index, operation in enumerate(actors):
            self.clock.now += 1
            store.record(operation, self.assessment(f"{index:064x}"), Action.ALLOW)

        legacy_key = self.key.read_bytes()
        self.assertFalse(legacy_key.startswith(b"["))
        with closing(sqlite3.connect(self.database)) as connection:
            before = connection.execute(
                "SELECT id,created,expires FROM history ORDER BY id"
            ).fetchall()

        result = store.rotate_key()

        self.assertEqual(set(result), {
            "current_key_fingerprint", "key_count", "records_reencrypted", "resumed",
        })
        self.assertEqual(result["key_count"], 2)
        self.assertEqual(result["records_reencrypted"], 4)
        self.assertFalse(result["resumed"])
        self.assertRegex(result["current_key_fingerprint"], r"^[a-f0-9]{64}$")
        ring = json.loads(self.key.read_text())
        self.assertEqual(ring[1].encode(), legacy_key)
        self.assertEqual(result["current_key_fingerprint"],
                         hashlib.sha256(ring[0].encode()).hexdigest())

        reopened = self.reopen()
        for operation in actors:
            rows = reopened.recent(operation)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].operation_id, operation.context.operation_id)
        with closing(sqlite3.connect(self.database)) as connection:
            after = connection.execute(
                "SELECT id,created,expires FROM history ORDER BY id"
            ).fetchall()
        self.assertEqual(after, before)

        outsider = self.operation(tenant="tenant-c", principal="operator-c", agent="agent-c")
        self.assertEqual(reopened.recent(outsider), ())
        for index in range(28):
            operation = self.operation(agent=f"capacity-{index}", operation_id=f"capacity-{index}")
            reopened.record(operation, self.assessment(f"{index + 10:064x}"), Action.ALLOW)
        with self.assertRaisesRegex(SecurityHistoryError, "security_history_capacity_reached"):
            reopened.record(outsider, self.assessment(), Action.ALLOW)

    def test_rotation_does_not_opportunistically_purge_expired_rows(self):
        store = self.initialize(ttl=10)
        store.record(self.operation(), self.assessment(), Action.ALLOW)
        self.clock.now += 11

        result = store.rotate_key()

        self.assertEqual(result["records_reencrypted"], 1)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM history").fetchone()[0], 1)
        self.assertEqual(self.reopen(ttl=10).verify()["records"], 0)

    def test_legacy_raw_key_whitespace_remains_part_of_selector_key(self):
        self.initialize()
        whitespace_key = self.key.read_bytes() + b"\n"
        self.key.write_bytes(whitespace_key)
        legacy = self.reopen()
        operation = self.operation(principal="whitespace-owner")
        legacy.record(operation, self.assessment(), Action.ALLOW)

        result = legacy.rotate_key()

        self.assertEqual(result["records_reencrypted"], 1)
        ring = json.loads(self.key.read_text())
        self.assertEqual(ring[1].encode(), whitespace_key)
        self.assertEqual(self.reopen().recent(operation)[0].principal_id,
                         "whitespace-owner")

    def test_tampered_rows_fail_before_key_publication_without_leakage(self):
        store = self.initialize()
        store.record(self.operation(), self.assessment(), Action.ALLOW)
        key_before = self.key.read_bytes()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE history SET tenant=?", (b"x" * 32,))
            connection.commit()

        with self.assertRaises(SecurityHistoryError) as caught:
            store.rotate_key()

        self.assertEqual(str(caught.exception), "security_history_key_rotation_failed")
        self.assertNotIn(key_before.decode(), str(caught.exception))
        self.assertEqual(self.key.read_bytes(), key_before)

    def test_corrupt_ciphertext_fails_before_key_publication(self):
        store = self.initialize()
        store.record(self.operation(), self.assessment(), Action.ALLOW)
        key_before = self.key.read_bytes()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE history SET record=?", (b"corrupt",))
            connection.commit()

        with self.assertRaisesRegex(SecurityHistoryError,
                                    "^security_history_key_rotation_failed$"):
            store.rotate_key()

        self.assertEqual(self.key.read_bytes(), key_before)

    def test_published_ring_survives_rollback_and_resume_does_not_grow_it(self):
        store = self.initialize()
        operation = self.operation(principal="rollback-owner")
        store.record(operation, self.assessment(), Action.DENY)
        old_key = self.key.read_bytes()
        raw_connection = sqlite3.connect(self.database, timeout=0)
        cleanup = {"rollback": False, "close": False}

        class CleanupFailingConnection:
            def __getattr__(self, name):
                return getattr(raw_connection, name)

            def rollback(self):
                cleanup["rollback"] = True
                raw_connection.rollback()
                raise RuntimeError("cleanup-secret-marker")

            def close(self):
                cleanup["close"] = True
                raw_connection.close()
                raise RuntimeError("cleanup-secret-marker")

        with mock.patch("enkstein_guard.security_context.sqlite3.connect",
                        return_value=CleanupFailingConnection()), \
                mock.patch.object(MultiFernet, "rotate",
                                  side_effect=RuntimeError("primary-secret-marker")):
            with self.assertRaisesRegex(SecurityHistoryError,
                                        "^security_history_key_rotation_failed$"):
                store.rotate_key()

        self.assertEqual(cleanup, {"rollback": True, "close": True})
        published = self.key.read_bytes()
        ring = json.loads(published)
        self.assertEqual(len(ring), 2)
        self.assertEqual(ring[1].encode(), old_key)
        fresh = self.reopen()
        self.assertEqual(fresh.recent(operation)[0].principal_id, "rollback-owner")

        resumed = fresh.rotate_key(resume=True)

        self.assertEqual(resumed["key_count"], 2)
        self.assertEqual(resumed["records_reencrypted"], 1)
        self.assertTrue(resumed["resumed"])
        self.assertEqual(self.key.read_bytes(), published)
        self.assertEqual(len(self.reopen().recent(operation)), 1)

    def test_same_object_waiting_writer_uses_new_primary(self):
        store = self.initialize()
        entered = threading.Event()
        release = threading.Event()
        original_publish = __import__(
            "enkstein_guard.security_context", fromlist=["_atomic_private_write"]
        )._atomic_private_write
        results = []

        def blocking_publish(path, data):
            entered.set()
            self.assertTrue(release.wait(5))
            original_publish(path, data)

        def rotate():
            try:
                results.append(("rotate", store.rotate_key()))
            except Exception as error:  # pragma: no cover - asserted below
                results.append(("rotate-error", error))

        def write():
            try:
                store.record(self.operation(operation_id="waiting"),
                             self.assessment(), Action.ALLOW)
                results.append(("write", None))
            except Exception as error:  # pragma: no cover - asserted below
                results.append(("write-error", error))

        with mock.patch("enkstein_guard.security_context._atomic_private_write",
                        side_effect=blocking_publish):
            rotation = threading.Thread(target=rotate)
            rotation.start()
            self.assertTrue(entered.wait(5))
            with self.assertRaisesRegex(SecurityHistoryError,
                                        "^security_history_key_rotation_busy$"):
                store.rotate_key()
            writer = threading.Thread(target=write)
            writer.start()
            release.set()
            rotation.join(5)
            writer.join(5)

        self.assertFalse(rotation.is_alive())
        self.assertFalse(writer.is_alive())
        self.assertEqual([name for name, _ in results], ["rotate", "write"])
        reopened = self.reopen()
        self.assertEqual(reopened.recent(self.operation())[0].operation_id, "waiting")
        with closing(sqlite3.connect(self.database)) as connection:
            encrypted = connection.execute("SELECT record FROM history").fetchone()[0]
        ring = [item.encode() for item in json.loads(self.key.read_text())]
        Fernet(ring[0]).decrypt(encrypted)
        with self.assertRaises(Exception):
            Fernet(ring[1]).decrypt(encrypted)

    def test_competing_rotators_and_stale_handle_fail_closed(self):
        store = self.initialize()
        stale = self.reopen()
        descriptor = os.open(store._rotation_lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(SecurityHistoryError,
                                        "^security_history_key_rotation_busy$"):
                store.rotate_key()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        store.rotate_key()
        with self.assertRaisesRegex(SecurityHistoryError, "^security_history_key_changed$"):
            stale.record(self.operation(), self.assessment(), Action.ALLOW)
        with self.assertRaisesRegex(SecurityHistoryError, "^security_history_key_changed$"):
            stale.rotate_key(resume=True)

    def test_malformed_full_and_unsafe_key_paths_are_rejected(self):
        store = self.initialize()
        old_key = self.key.read_bytes()
        keys = [old_key, *(Fernet.generate_key() for _ in range(31))]
        self.key.write_text(json.dumps([key.decode() for key in keys], separators=(",", ":")))
        full = self.reopen()
        with self.assertRaisesRegex(SecurityHistoryError, "^security_history_keyring_full$"):
            full.rotate_key()

        cases = (
            b"[]",
            json.dumps([old_key.decode(), old_key.decode()]).encode(),
            b'["not-a-fernet-key"]',
            b"{}",
        )
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        character = old_key[-2]
        position = alphabet.index(character)
        alias_position = (position & ~3) | ((position + 1) & 3)
        alias = old_key[:-2] + bytes((alphabet[alias_position],)) + b"="
        self.assertNotEqual(alias, old_key)
        self.assertEqual(base64.urlsafe_b64decode(alias), base64.urlsafe_b64decode(old_key))
        Fernet(alias)
        cases += (json.dumps([old_key.decode(), alias.decode()]).encode(),)
        for index, malformed in enumerate(cases):
            database = Path(self.temp.name) / f"malformed-{index}/history.sqlite3"
            key = Path(self.temp.name) / f"malformed-{index}/history.key"
            self.initialize(database=database, key=key)
            key.write_bytes(malformed)
            with self.subTest(malformed=index):
                with self.assertRaisesRegex(SecurityHistoryError,
                                            "^security_history_key_unavailable$"):
                    self.reopen(database=database, key=key)

        target = Path(self.temp.name) / "symlink-target"
        target.write_bytes(old_key)
        os.chmod(target, 0o600)
        self.key.unlink()
        self.key.symlink_to(target)
        with self.assertRaisesRegex(SecurityHistoryError,
                                    "^security_history_key_rotation_failed$"):
            store.rotate_key()

    def test_rotation_lock_is_private_and_invalid_resume_is_sanitized(self):
        store = self.initialize()
        store.rotate_key()
        self.assertEqual(os.stat(store._rotation_lock_path).st_mode & 0o077, 0)
        with self.assertRaisesRegex(SecurityHistoryError,
                                    "^security_history_key_rotation_invalid_resume$"):
            store.rotate_key(resume=1)


if __name__ == "__main__":
    unittest.main()
