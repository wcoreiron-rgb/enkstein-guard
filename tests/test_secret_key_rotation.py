import asyncio
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from enkstein_guard.contracts import SecurityContext
from enkstein_guard.identities import IdentityError, SecretBroker, SecretStore
from enkstein_guard.runtime import Operation, RejectedBeforeDispatch
from enkstein_guard.vault import _atomic_private_write


class SecretKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "state/secrets.sqlite3"
        self.key_file = self.root / "keys/secrets.key"
        self.store = SecretStore.initialize(self.database, self.key_file)
        self.store.set("provider-a", "synthetic-secret-a", tenant="tenant-a",
                       destination="api.example.test", routes=["model.chat", "model.embed"])
        self.store.set("provider-b", "synthetic-secret-b", tenant="tenant-b",
                       destination="api.example.test", routes=["model.chat"])

    def _ciphertexts(self):
        with closing(sqlite3.connect(self.database)) as connection:
            identity = connection.execute("SELECT record FROM identity").fetchall()
            records = connection.execute("SELECT name,record FROM secrets ORDER BY name").fetchall()
        return identity, records

    def test_legacy_rotation_restart_and_broker_scope(self):
        legacy_key = self.key_file.read_bytes()
        self.assertFalse(legacy_key.startswith(b"["))
        before = self.store.listing()

        result = self.store.rotate_key()

        keyring = json.loads(self.key_file.read_bytes())
        self.assertEqual(len(keyring), 2)
        self.assertEqual(keyring[1], legacy_key.decode("ascii"))
        self.assertEqual(result["key_count"], 2)
        self.assertEqual(result["records_reencrypted"], 2)
        self.assertFalse(result["resumed"])
        self.assertRegex(result["current_key_fingerprint"], r"^[a-f0-9]{64}$")
        self.assertNotIn("synthetic-secret", json.dumps(result))
        self.assertNotIn(keyring[0], json.dumps(result))

        identity, records = self._ciphertexts()
        old_cipher = Fernet(legacy_key)
        for encrypted in [identity[0][0], *(record for _, record in records)]:
            with self.assertRaises(InvalidToken):
                old_cipher.decrypt(encrypted)

        reopened = SecretStore(self.database, self.key_file)
        self.assertEqual(reopened.listing(), before)
        broker = SecretBroker(reopened)
        context = SecurityContext("tenant-a", "principal", "agent", "workflow", "root", "op", "v")
        operation = Operation(context, "model.chat", "m", "api.example.test", "{}", "digest")

        async def connector(secret, payload):
            return secret

        self.assertEqual(asyncio.run(broker.invoke("provider-a", operation, connector)), "synthetic-secret-a")
        wrong_context = SecurityContext("tenant-b", "principal", "agent", "workflow", "root", "op", "v")
        wrong_tenant = Operation(wrong_context, "model.chat", "m", "api.example.test", "{}", "digest")
        wrong_route = Operation(context, "other", "m", "api.example.test", "{}", "digest")
        for denied in (wrong_tenant, wrong_route):
            with self.assertRaises(RejectedBeforeDispatch):
                asyncio.run(broker.invoke("provider-a", denied, connector))

    def test_stale_handles_fail_for_reads_sets_and_removes(self):
        stale = SecretStore(self.database, self.key_file)
        self.store.rotate_key()
        operations = (
            lambda: stale.resolve("provider-a", tenant="tenant-a", route="model.chat",
                                  destination="api.example.test"),
            lambda: stale.set("stale-write", "value", tenant="tenant-a",
                              destination="api.example.test", routes=["model.chat"]),
            lambda: stale.remove("provider-a"),
        )
        for operation in operations:
            with self.assertRaisesRegex(IdentityError, "^secret_store_key_changed$"):
                operation()
        reopened = SecretStore(self.database, self.key_file)
        self.assertEqual(reopened.resolve("provider-a", tenant="tenant-a", route="model.chat",
                                          destination="api.example.test"), "synthetic-secret-a")
        self.assertNotIn("stale-write", {record["name"] for record in reopened.listing()})

    def test_pending_writer_rechecks_key_after_begin_immediate(self):
        pending = SecretStore(self.database, self.key_file)
        entered = threading.Event()
        original_connect = pending._connect

        def announced_connect():
            connection = original_connect()
            entered.set()
            return connection

        outcome = []
        with closing(sqlite3.connect(self.database)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            with mock.patch.object(pending, "_connect", side_effect=announced_connect):
                thread = threading.Thread(
                    target=lambda: self._capture_error(
                        outcome, lambda: pending.set("pending", "value", tenant="tenant-a",
                                                     destination="api.example.test", routes=["model.chat"])))
                thread.start()
                self.assertTrue(entered.wait(2))
                legacy = self.key_file.read_bytes().strip()
                _atomic_private_write(
                    self.key_file,
                    json.dumps([Fernet.generate_key().decode("ascii"), legacy.decode("ascii")],
                               separators=(",", ":")).encode())
                blocker.rollback()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcome, ["secret_store_key_changed"])
        self.assertNotIn("pending", {record["name"] for record in SecretStore(
            self.database, self.key_file).listing()})

    @staticmethod
    def _capture_error(outcome, operation):
        try:
            operation()
        except IdentityError as error:
            outcome.append(str(error))

    def test_concurrent_rotator_is_rejected_by_private_admin_lock(self):
        lock = self.database.with_name(self.database.name + ".rotation.lock")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(IdentityError, "^secret_store_rotation_busy$"):
                self.store.rotate_key()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        result = self.store.rotate_key()
        self.assertEqual(result["key_count"], 2)
        self.assertEqual(len(json.loads(self.key_file.read_bytes())), 2)

    def test_malformed_duplicate_permissions_symlink_and_full_keyrings_fail_closed(self):
        original = self.key_file.read_bytes()
        malformed = (
            b"[]",
            b"{}",
            b'["not-a-fernet-key"]',
            json.dumps([original.decode(), original.decode()]).encode(),
        )
        for value in malformed:
            with self.subTest(value=value[:20]):
                self.key_file.write_bytes(value)
                self.key_file.chmod(0o600)
                with self.assertRaises(IdentityError):
                    SecretStore(self.database, self.key_file)
        self.key_file.write_bytes(original)
        self.key_file.chmod(0o644)
        with self.assertRaisesRegex(IdentityError, "^secret_store_path_unsafe$"):
            SecretStore(self.database, self.key_file)

        self.key_file.chmod(0o600)
        target = self.root / "private-target.key"
        target.write_bytes(original)
        target.chmod(0o600)
        self.key_file.unlink()
        self.key_file.symlink_to(target)
        with self.assertRaisesRegex(IdentityError, "^secret_store_path_unsafe$"):
            SecretStore(self.database, self.key_file)
        self.key_file.unlink()

        keys = [original.decode(), *(Fernet.generate_key().decode() for _ in range(31))]
        self.key_file.write_text(json.dumps(keys, separators=(",", ":")))
        self.key_file.chmod(0o600)
        full = SecretStore(self.database, self.key_file)
        key_before, database_before = self.key_file.read_bytes(), self.database.read_bytes()
        with self.assertRaisesRegex(IdentityError, "^secret_store_keyring_full$"):
            full.rotate_key()
        self.assertEqual(self.key_file.read_bytes(), key_before)
        self.assertEqual(self.database.read_bytes(), database_before)

    def test_corrupt_record_prevents_keyring_change(self):
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE secrets SET record=? WHERE name='provider-a'", (b"corrupt",))
            connection.commit()
        key_before = self.key_file.read_bytes()
        with self.assertRaisesRegex(IdentityError, "^secret_store_rotation_failed$"):
            self.store.rotate_key()
        self.assertEqual(self.key_file.read_bytes(), key_before)

    def test_authenticated_malformed_record_is_rejected_before_key_publication(self):
        key = self.key_file.read_bytes()
        malformed = {"name": "provider-a", "value": "synthetic-secret-a", "tenant": "tenant-a",
                     "destination": "api.example.test", "routes": ["model.chat", 7],
                     "updated_at": 1}
        encrypted = Fernet(key).encrypt(json.dumps(malformed).encode())
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE secrets SET record=? WHERE name='provider-a'", (encrypted,))
            connection.commit()
        with self.assertRaisesRegex(IdentityError, "^secret_store_rotation_failed$"):
            self.store.rotate_key()
        self.assertEqual(self.key_file.read_bytes(), key)

    def test_failure_after_keyring_publish_is_readable_and_resumable_without_new_key(self):
        publish = self.store._publish_keyring

        def publish_then_fail(keys):
            publish(keys)
            raise OSError("synthetic post-publish failure")

        with mock.patch.object(self.store, "_publish_keyring", side_effect=publish_then_fail):
            with self.assertRaisesRegex(IdentityError, "^secret_store_rotation_failed$"):
                self.store.rotate_key()
        self.assertEqual(len(json.loads(self.key_file.read_bytes())), 2)
        recovered = SecretStore(self.database, self.key_file)
        self.assertEqual(recovered.resolve("provider-a", tenant="tenant-a", route="model.chat",
                                           destination="api.example.test"), "synthetic-secret-a")
        result = recovered.rotate_key(resume=True)
        self.assertTrue(result["resumed"])
        self.assertEqual(result["key_count"], 2)
        self.assertEqual(len(json.loads(self.key_file.read_bytes())), 2)

    def test_transactional_rewrite_failure_rolls_back_exact_ciphertexts_and_logical_records(self):
        before_listing = self.store.listing()
        before_ciphertexts = self._ciphertexts()
        original_rotate = MultiFernet.rotate
        calls = 0

        def fail_after_first_record(cipher, token):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError("synthetic record rewrite failure")
            return original_rotate(cipher, token)

        with mock.patch.object(MultiFernet, "rotate", new=fail_after_first_record):
            with self.assertRaisesRegex(IdentityError, "^secret_store_rotation_failed$"):
                self.store.rotate_key()
        self.assertEqual(len(json.loads(self.key_file.read_bytes())), 2)
        self.assertEqual(self._ciphertexts(), before_ciphertexts)
        recovered = SecretStore(self.database, self.key_file)
        self.assertEqual(recovered.listing(), before_listing)
        self.assertEqual(recovered.rotate_key(resume=True)["key_count"], 2)


if __name__ == "__main__":
    unittest.main()
