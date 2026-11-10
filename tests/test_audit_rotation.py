from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from cryptography.fernet import Fernet, InvalidToken

from enkstein_guard.audit import AuditError, DurableAudit


class AuditKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "state/audit.sqlite3"
        self.key_file = self.root / "keys/audit.key"
        self.archives = self.root / "archives"
        self.archives.mkdir(mode=0o700)
        self.audit = DurableAudit.initialize(self.database, self.key_file, full_verify_every=0)

    def _append(self, count):
        for number in range(count):
            self.audit({"event": "rotation_test", "operation_id": "op-%d" % number})

    def _active_ciphertexts(self):
        with closing(sqlite3.connect(self.database)) as connection:
            return connection.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall()

    def test_rotate_restart_append_and_verify_archives_without_rehashing_history(self):
        self._append(6)
        external_checkpoint = self.audit.verify()
        self.audit.archive(self.archives, keep=2)
        archived_bytes = {path.name: path.read_bytes() for path in self.archives.iterdir()}
        active_before = self._active_ciphertexts()
        legacy_key = self.key_file.read_bytes()
        stale_writer = DurableAudit(self.database, self.key_file, full_verify_every=0)

        # A recorded archive must be supplied and verified by an offline rotation.
        with self.assertRaises(AuditError):
            self.audit.rotate_key()
        self.assertEqual(self.key_file.read_bytes(), legacy_key)

        result = self.audit.rotate_key(archives=self.archives)
        self.assertTrue(result["rotated"])
        self.assertEqual(result["retained_keys"], 1)
        self.assertEqual(result["checkpoint"], external_checkpoint)
        keyring = json.loads(self.key_file.read_bytes())
        self.assertEqual(keyring[1], legacy_key.decode("ascii"))
        self.assertNotEqual(keyring[0], keyring[1])
        self.assertEqual(self._active_ciphertexts(), active_before)
        self.assertEqual({path.name: path.read_bytes() for path in self.archives.iterdir()}, archived_bytes)

        # Exact external checkpoints and the complete archived chain survive.
        reopened = DurableAudit(self.database, self.key_file, full_verify_every=0)
        self.assertEqual(reopened.verify(external_checkpoint, archives=self.archives), external_checkpoint)
        self.assertEqual([item[0] for item in reopened.events(archives=self.archives)], list(range(1, 7)))
        with self.assertRaises(AuditError):
            stale_writer({"event": "stale_writer"})

        reopened({"event": "after_rotation", "outcome": "allowed"})
        final_checkpoint = reopened.verify(archives=self.archives)
        self.assertEqual(final_checkpoint["sequence"], 7)
        self.assertEqual([item[0] for item in reopened.events(archives=self.archives)], list(range(1, 8)))
        old_cipher = Fernet(legacy_key)
        old_cipher.decrypt(active_before[-1][1])
        newest = self._active_ciphertexts()[-1][1]
        with self.assertRaises(InvalidToken):
            old_cipher.decrypt(newest)
        Fernet(keyring[0].encode("ascii")).decrypt(newest)

    def test_failed_keyring_publish_leaves_legacy_key_and_store_writable(self):
        self._append(1)
        original_key = self.key_file.read_bytes()
        with mock.patch("enkstein_guard.audit.os.replace", side_effect=OSError("injected publish failure")):
            with self.assertRaises(AuditError):
                self.audit.rotate_key(archives=self.archives)
        self.assertEqual(self.key_file.read_bytes(), original_key)
        self.assertEqual(list(self.key_file.parent.glob("*.tmp")), [])
        self.audit({"event": "after_failed_rotation"})
        self.assertEqual(self.audit.verify()["sequence"], 2)

    def test_restart_recovers_if_directory_fsync_fails_after_keyring_publish(self):
        self._append(2)
        checkpoint = self.audit.verify()
        original_fsync = os.fsync
        calls = 0

        def fail_after_replace(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected post-replace failure")
            return original_fsync(descriptor)

        with mock.patch("enkstein_guard.audit.os.fsync", side_effect=fail_after_replace):
            with self.assertRaises(AuditError):
                self.audit.rotate_key(archives=self.archives)
        self.assertEqual(len(json.loads(self.key_file.read_bytes())), 2)
        with self.assertRaises(AuditError):
            self.audit({"event": "stale_in_memory_key"})

        recovered = DurableAudit(self.database, self.key_file, full_verify_every=0)
        self.assertEqual(recovered.verify(checkpoint), checkpoint)
        recovered({"event": "after_recovery"})
        self.assertEqual(recovered.verify()["sequence"], 3)

    def test_active_sqlite_writer_causes_offline_rotation_to_fail_closed(self):
        self._append(1)
        original_key = self.key_file.read_bytes()
        with closing(sqlite3.connect(self.database)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            with self.assertRaises(AuditError):
                self.audit.rotate_key(archives=self.archives)
            self.assertEqual(self.key_file.read_bytes(), original_key)
            writer.rollback()
        self.assertTrue(self.audit.rotate_key(archives=self.archives)["rotated"])


if __name__ == "__main__":
    unittest.main()
