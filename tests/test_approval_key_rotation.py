"""Offline recoverable key rotation for durable approval tickets."""

from contextlib import closing
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

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from enkstein_guard import approval_store as store_module
from enkstein_guard.approval_store import ApprovalStore, ApprovalStoreError


class ApprovalKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-approval-rotation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "state/approvals.sqlite3"
        self.key_file = self.root / "keys/approvals.key"
        self.store = ApprovalStore.initialize(self.database, self.key_file)

    def create_store(self, name):
        return ApprovalStore.initialize(
            self.root / (name + "/state/approvals.sqlite3"),
            self.root / (name + "/keys/approvals.key"),
        )

    @staticmethod
    def binding(name, tenant="tenant-a"):
        payload_digest = hashlib.sha256(("payload-" + name).encode()).hexdigest()
        return {
            "tenant": tenant,
            "principal": "support-bot",
            "agent": "agent-" + name,
            "route": "ticket.close",
            "operation": "ticket.close",
            "resource": "support-ticket",
            "destination": "ticket-service",
            "policy_version": "cfg-rotation",
            "payload_sha256": payload_digest,
        }

    def issue(self, name, *, tenant="tenant-a", store=None):
        store = store or self.store
        binding = self.binding(name, tenant)
        digest = hashlib.sha256(
            json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        item = store.request(
            binding, digest, {"ticket": name, "note": "synthetic review"},
            expires=10_000, created=100, max_pending=32, max_per_tenant=16)
        return digest, item

    def ciphertexts(self):
        with closing(sqlite3.connect(self.database)) as connection:
            identity = connection.execute("SELECT record FROM identity").fetchone()[0]
            rows = connection.execute(
                "SELECT id,record FROM approvals ORDER BY id").fetchall()
        return identity, rows

    def test_legacy_rotation_restart_preserves_all_states_and_bindings(self):
        legacy_key = self.key_file.read_bytes()
        self.assertFalse(legacy_key.startswith(b"["))
        pending_digest, pending = self.issue("pending")
        approved_digest, approved = self.issue("approved")
        consumed_digest, consumed = self.issue("consumed", tenant="tenant-b")
        approver_digest = "b" * 64
        self.store.decide(
            approved["ticket"], approved_digest, "approved", "alice", approver_digest, 101)
        self.store.decide(
            consumed["ticket"], consumed_digest, "approved", "bob", approver_digest, 101)
        self.store.consume(
            consumed["ticket"], consumed_digest, 102, "bob", approver_digest)

        # Future authenticated metadata must survive byte-for-byte rotation too.
        approved_name = hashlib.sha256(approved["ticket"].encode()).hexdigest()
        with closing(sqlite3.connect(self.database)) as connection:
            encrypted = connection.execute(
                "SELECT record FROM approvals WHERE id=?", (approved_name,)).fetchone()[0]
            record = self.store._decode(approved_name, encrypted)
            record["revocation"] = {"scope": "synthetic", "generation": 7}
            connection.execute(
                "UPDATE approvals SET record=? WHERE id=?",
                (self.store._encode(record), approved_name))
            connection.commit()

        snapshots = {
            item["ticket"]: self.store.get(item["ticket"])
            for item in (pending, approved, consumed)
        }
        stale = ApprovalStore(self.database, self.key_file)
        before_identity, before_rows = self.ciphertexts()
        result = self.store.rotate_key()

        keyring = json.loads(self.key_file.read_bytes())
        self.assertEqual(keyring[1], legacy_key.decode("ascii"))
        self.assertEqual(result, {
            "rotated": True,
            "key_fingerprint": hashlib.sha256(keyring[0].encode("ascii")).hexdigest(),
            "key_count": 2,
            "records": 3,
            "resumed": False,
        })
        serialized_result = json.dumps(result)
        self.assertNotIn(keyring[0], serialized_result)
        self.assertNotIn(keyring[1], serialized_result)

        reopened = ApprovalStore(self.database, self.key_file)
        for ticket, expected in snapshots.items():
            self.assertEqual(reopened.get(ticket), expected)
        self.assertEqual(reopened.get(consumed["ticket"])["status"], "consumed")
        self.assertEqual(
            reopened.get(approved["ticket"])["revocation"],
            {"scope": "synthetic", "generation": 7})
        self.assertEqual(
            [item["ticket"] for item in reopened.pending(["tenant-a"], 103)],
            [pending["ticket"], approved["ticket"]])
        self.assertNotIn(consumed["ticket"], [
            item["ticket"] for item in reopened.pending(None, 103)])

        after_identity, after_rows = self.ciphertexts()
        self.assertNotEqual(before_identity, after_identity)
        self.assertNotEqual(before_rows, after_rows)
        old_cipher = Fernet(legacy_key)
        with self.assertRaises(InvalidToken):
            old_cipher.decrypt(after_identity)
        with self.assertRaises(InvalidToken):
            old_cipher.decrypt(after_rows[0][1])
        Fernet(keyring[0].encode("ascii")).decrypt(after_identity)

        with self.assertRaisesRegex(ApprovalStoreError, "approval_store_key_changed"):
            stale.request(
                self.binding("stale"), "a" * 64, {}, expires=10_000, created=103,
                max_pending=32, max_per_tenant=16)
        # Consumed state never becomes pending/approved after rotation.
        self.assertIsNone(reopened.get(consumed["ticket"]))
        _, after = self.issue("after-rotation", store=self.store)
        self.assertEqual(self.store.get(after["ticket"])["status"], "pending")

    def test_concurrent_rotation_lock_and_stale_handle_fail_closed(self):
        self.issue("one")
        second = ApprovalStore(self.database, self.key_file)
        entered = threading.Event()
        release = threading.Event()
        results = []
        original = store_module._atomic_private_write

        def paused_publish(path, data):
            entered.set()
            self.assertTrue(release.wait(5))
            return original(path, data)

        def rotate():
            try:
                results.append(self.store.rotate_key())
            except Exception as error:  # pragma: no cover - asserted below
                results.append(error)

        with mock.patch.object(store_module, "_atomic_private_write", paused_publish):
            thread = threading.Thread(target=rotate)
            thread.start()
            self.assertTrue(entered.wait(5))
            with self.assertRaisesRegex(
                    ApprovalStoreError, "approval_key_rotation_in_progress"):
                second.rotate_key()
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["key_count"], 2)
        with self.assertRaisesRegex(ApprovalStoreError, "approval_store_key_changed"):
            second.pending(None, 101)

    def test_writer_that_opened_before_rotation_rechecks_after_sqlite_lock(self):
        stale = ApprovalStore(self.database, self.key_file)
        original_connect = stale._connect
        waiting = threading.Event()
        rotated = threading.Event()
        outcome = []

        class WaitingConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, statement, *parameters):
                if statement == "BEGIN IMMEDIATE":
                    waiting.set()
                    if not rotated.wait(5):
                        raise RuntimeError("rotation did not finish")
                return self.connection.execute(statement, *parameters)

            def close(self):
                self.connection.close()

        def connect_before_rotation():
            return WaitingConnection(original_connect())

        def write():
            try:
                stale.request(
                    self.binding("waiting"), "c" * 64, {},
                    expires=10_000, created=100,
                    max_pending=32, max_per_tenant=16)
                outcome.append("unexpected_allow")
            except Exception as error:
                outcome.append(error)

        with mock.patch.object(stale, "_connect", side_effect=connect_before_rotation):
            thread = threading.Thread(target=write)
            thread.start()
            self.assertTrue(waiting.wait(5))
            self.store.rotate_key()
            rotated.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], ApprovalStoreError)
        self.assertEqual(str(outcome[0]), "approval_store_key_changed")
        self.assertEqual(ApprovalStore(self.database, self.key_file).verify()["tickets"], 0)

    def test_after_publish_failure_reopens_and_resumes_without_another_key(self):
        _, ticket = self.issue("crash")
        expected = self.store.get(ticket["ticket"])
        before = self.ciphertexts()
        original = store_module._atomic_private_write

        def publish_then_fail(path, data):
            original(path, data)
            raise OSError("injected after key publish")

        with mock.patch.object(store_module, "_atomic_private_write", publish_then_fail):
            with self.assertRaisesRegex(
                    ApprovalStoreError, "approval_key_rotation_failed"):
                self.store.rotate_key()
        keyring = json.loads(self.key_file.read_bytes())
        self.assertEqual(len(keyring), 2)
        self.assertEqual(self.ciphertexts(), before)

        recovered = ApprovalStore(self.database, self.key_file)
        self.assertEqual(recovered.get(ticket["ticket"]), expected)
        result = recovered.rotate_key(resume=True)
        self.assertTrue(result["resumed"])
        self.assertEqual(result["key_count"], 2)
        self.assertEqual(json.loads(self.key_file.read_bytes()), keyring)
        self.assertNotEqual(self.ciphertexts(), before)
        self.assertEqual(recovered.get(ticket["ticket"]), expected)

    def test_database_reencryption_failure_rolls_back_logical_state(self):
        _, first = self.issue("first")
        _, second = self.issue("second")
        expected = {
            ticket["ticket"]: self.store.get(ticket["ticket"])
            for ticket in (first, second)
        }
        before = self.ciphertexts()
        original_rotate = MultiFernet.rotate
        calls = 0

        def fail_during_records(cipher, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise sqlite3.OperationalError("injected update failure")
            return original_rotate(cipher, value)

        with mock.patch.object(MultiFernet, "rotate", fail_during_records):
            with self.assertRaisesRegex(
                    ApprovalStoreError, "approval_key_rotation_failed"):
                self.store.rotate_key()
        self.assertEqual(self.ciphertexts(), before)
        self.assertEqual(len(json.loads(self.key_file.read_bytes())), 2)
        recovered = ApprovalStore(self.database, self.key_file)
        for ticket, item in expected.items():
            self.assertEqual(recovered.get(ticket), item)
        self.assertEqual(recovered.rotate_key(resume=True)["key_count"], 2)

    def test_corrupt_record_and_full_keyring_reject_before_change(self):
        _, ticket = self.issue("corrupt")
        key_before = self.key_file.read_bytes()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE approvals SET record=?", (b"corrupt",))
            connection.commit()
        with self.assertRaisesRegex(
                ApprovalStoreError, "approval_store_integrity_failed"):
            self.store.rotate_key()
        self.assertEqual(self.key_file.read_bytes(), key_before)

        full = self.create_store("full")
        legacy = full.key_file.read_bytes()
        values = [legacy.decode("ascii")] + [
            Fernet.generate_key().decode("ascii") for _ in range(31)]
        full.key_file.write_text(json.dumps(values))
        reopened = ApprovalStore(full.database, full.key_file)
        before = full.key_file.read_bytes()
        database_before = full.database.read_bytes()
        with self.assertRaisesRegex(ApprovalStoreError, "approval_keyring_full"):
            reopened.rotate_key()
        self.assertEqual(full.key_file.read_bytes(), before)
        self.assertEqual(full.database.read_bytes(), database_before)

    def test_malformed_duplicate_and_oversize_keyrings_fail_closed(self):
        for number, value in enumerate((
                b"[]",
                b'["not-a-fernet-key"]',
                json.dumps(["x"] * 2).encode(),
                json.dumps([Fernet.generate_key().decode("ascii") for _ in range(33)]).encode(),
                b'{"key":"opaque"}',
        )):
            store = self.create_store("malformed-%d" % number)
            store.key_file.write_bytes(value)
            with self.subTest(value=value[:32]):
                with self.assertRaisesRegex(
                        ApprovalStoreError, "approval_store_key_unavailable"):
                    ApprovalStore(store.database, store.key_file)

    def test_private_permissions_and_symlinks_are_rejected(self):
        permissions = self.create_store("permissions")
        permissions.key_file.chmod(0o644)
        with self.assertRaises(ApprovalStoreError):
            ApprovalStore(permissions.database, permissions.key_file)

        linked = self.create_store("linked")
        real_key = linked.key_file.with_name("real.key")
        linked.key_file.rename(real_key)
        linked.key_file.symlink_to(real_key)
        with self.assertRaises(ApprovalStoreError):
            ApprovalStore(linked.database, linked.key_file)

        unsafe_lock = self.create_store("unsafe-lock")
        lock_path = unsafe_lock._rotation_lock_path
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)
        with self.assertRaisesRegex(
                ApprovalStoreError, "approval_key_rotation_lock_unavailable"):
            unsafe_lock.rotate_key()

        symlink_lock = self.create_store("symlink-lock")
        target = symlink_lock.key_file.parent / "lock-target"
        target.write_bytes(b"")
        target.chmod(0o600)
        symlink_lock._rotation_lock_path.symlink_to(target)
        with self.assertRaisesRegex(
                ApprovalStoreError, "approval_key_rotation_lock_unavailable"):
            symlink_lock.rotate_key()

    def test_invalid_resume_and_manual_lock_have_fixed_errors(self):
        with self.assertRaisesRegex(
                ApprovalStoreError, "approval_key_rotation_invalid_resume"):
            self.store.rotate_key(resume=1)
        descriptor = os.open(
            self.store._rotation_lock_path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(
                    ApprovalStoreError, "approval_key_rotation_in_progress"):
                self.store.rotate_key()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
