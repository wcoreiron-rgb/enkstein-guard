"""Offline recoverable signing-key rotation for the identity store."""

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from enkstein_guard.identities import IdentityError, IdentityStore


class IdentityKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-identity-rotation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store_file = self.root / "state/identities.json"
        self.key_file = self.root / "keys/identities.key"
        self.store = IdentityStore.initialize(self.store_file, self.key_file)

    def create_store(self, name):
        return IdentityStore.initialize(
            self.root / (name + "/state/identities.json"),
            self.root / (name + "/keys/identities.key"),
        )

    @staticmethod
    def _capture(outcome, operation):
        try:
            outcome.append(operation())
        except Exception as error:  # pragma: no cover - asserted by callers
            outcome.append(error)

    def test_legacy_rotation_preserves_exact_body_credentials_and_revocation(self):
        legacy_key = self.key_file.read_bytes()
        self.assertEqual(len(legacy_key), 64)
        self.store.issue("agent", "active-agent", self.root / "active.token")
        self.store.issue("approver", "revoked-approver", self.root / "revoked.token")
        self.store.revoke("approver", "revoked-approver")

        body = self.store._read()
        body["rotation_metadata"] = {"source": "synthetic", "flags": [True, False]}
        body["agent"]["active-agent"]["credential_metadata"] = {"owner": "tenant-a"}
        body["approver"]["revoked-approver"]["revoked"] = True
        self.store._write_authenticated_body(body)
        expected_body = json.loads(json.dumps(body))
        serial = self.store.serial
        listing = self.store.listing()
        digests = {kind: self.store.digests(kind) for kind in ("agent", "approver")}

        result = self.store.rotate_key()

        ring = json.loads(self.key_file.read_bytes())
        self.assertEqual(ring[1], legacy_key.decode("ascii"))
        self.assertEqual(result, {
            "current_key_fingerprint": hashlib.sha256(bytes.fromhex(ring[0])).hexdigest(),
            "key_count": 2,
            "records_reauthenticated": 2,
            "resumed": False,
        })
        self.assertEqual(self.store.verify(), {"records": 2, "serial": serial})
        reopened = IdentityStore(self.store_file, self.key_file)
        self.assertEqual(reopened._read(), expected_body)
        self.assertEqual(reopened.listing(), listing)
        self.assertEqual(reopened.serial, serial)
        self.assertEqual({kind: reopened.digests(kind) for kind in digests}, digests)
        self.assertNotIn("revoked-approver", reopened.digests("approver"))
        serialized_result = json.dumps(result)
        self.assertNotIn(ring[0], serialized_result)
        self.assertNotIn(ring[1], serialized_result)

        envelope = json.loads(self.store_file.read_bytes())
        canonical = json.dumps(
            envelope["body"], sort_keys=True, separators=(",", ":")).encode()
        old_mac = hmac.new(bytes.fromhex(legacy_key.decode()), canonical,
                           hashlib.sha256).hexdigest()
        self.assertFalse(hmac.compare_digest(envelope["mac"], old_mac))

    def test_coherent_backup_restore_remains_readable(self):
        self.store.issue("agent", "backup-agent", self.root / "backup.token")
        self.store.rotate_key()
        expected = self.store.listing()
        backup = self.root / "backup"
        (backup / "state").mkdir(parents=True, mode=0o700)
        (backup / "keys").mkdir(parents=True, mode=0o700)
        shutil.copy2(self.store_file, backup / "state/identities.json")
        shutil.copy2(self.key_file, backup / "keys/identities.key")

        self.store.rotate_key()

        restored = IdentityStore(
            backup / "state/identities.json", backup / "keys/identities.key")
        self.assertEqual(restored.listing(), expected)
        self.assertEqual(restored.verify()["records"], 1)

    def test_legacy_raw_uppercase_and_ascii_whitespace_remains_compatible(self):
        compatible = self.create_store("legacy-whitespace")
        raw = compatible.key_file.read_text().upper()
        spaced = " \t".join(raw[index:index + 2] for index in range(0, len(raw), 2)) + "\n"
        compatible.key_file.write_text(spaced)
        compatible.key_file.chmod(0o600)

        opened = IdentityStore(compatible.path, compatible.key_file)
        opened.issue("agent", "legacy-agent", self.root / "legacy-agent.token")
        expected = opened.listing()
        result = opened.rotate_key()

        ring = json.loads(compatible.key_file.read_bytes())
        self.assertEqual(result["key_count"], 2)
        self.assertEqual(ring[1], raw.lower())
        reopened = IdentityStore(compatible.path, compatible.key_file)
        self.assertEqual(reopened.listing(), expected)
        self.assertIn("legacy-agent", reopened.digests("agent"))

    def test_corruption_and_authenticated_bad_schema_refuse_before_publication(self):
        self.store.issue("agent", "agent-a", self.root / "agent-a.token")
        key_before = self.key_file.read_bytes()
        envelope = json.loads(self.store_file.read_bytes())
        envelope["mac"] = "0" * 64
        self.store_file.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(IdentityError, "^identity_store_rotation_failed$"):
            self.store.rotate_key()
        self.assertEqual(self.key_file.read_bytes(), key_before)

        malformed = self.create_store("malformed-record")
        malformed.issue("agent", "agent-a", self.root / "malformed.token")
        body = malformed._read()
        body["agent"]["agent-a"]["generation"] = True
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        mac = hmac.new(malformed._keys[0], canonical, hashlib.sha256).hexdigest()
        malformed.path.write_text(json.dumps({"body": body, "mac": mac}))
        malformed.path.chmod(0o600)
        malformed_key_before = malformed.key_file.read_bytes()
        with self.assertRaisesRegex(IdentityError, "^identity_store_rotation_failed$"):
            malformed.rotate_key()
        self.assertEqual(malformed.key_file.read_bytes(), malformed_key_before)

    def test_postpublication_failure_is_recoverable_and_resume_does_not_grow(self):
        self.store.issue("agent", "agent-a", self.root / "agent-a.token")
        before = self.store_file.read_bytes()
        serial = self.store.serial
        def fail_reauthentication(body):
            raise OSError("synthetic failure after key publication")

        with mock.patch.object(
                self.store, "_write_authenticated_body", side_effect=fail_reauthentication):
            with self.assertRaisesRegex(IdentityError, "^identity_store_rotation_failed$"):
                self.store.rotate_key()
        ring = json.loads(self.key_file.read_bytes())
        self.assertEqual(len(ring), 2)
        self.assertEqual(self.store_file.read_bytes(), before)

        recovered = IdentityStore(self.store_file, self.key_file)
        self.assertEqual(recovered.verify(), {"records": 1, "serial": serial})
        result = recovered.rotate_key(resume=True)
        self.assertEqual(result["key_count"], 2)
        self.assertTrue(result["resumed"])
        self.assertEqual(json.loads(self.key_file.read_bytes()), ring)
        self.assertEqual(recovered.serial, serial)
        self.assertNotEqual(self.store_file.read_bytes(), before)

    def test_stale_handle_fails_reads_and_normal_mutation(self):
        stale = IdentityStore(self.store_file, self.key_file)
        self.store.rotate_key()
        operations = (
            stale.verify,
            stale.listing,
            lambda: stale.digests("agent"),
            lambda: stale.issue("agent", "stale", self.root / "stale.token"),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(IdentityError, "^identity_store_key_changed$"):
                    operation()
        self.assertFalse((self.root / "stale.token").exists())
        self.assertEqual(IdentityStore(self.store_file, self.key_file).verify()["records"], 0)

    def test_concurrent_writer_waits_then_rejects_stale_key_and_rotator_is_nonblocking(self):
        stale = IdentityStore(self.store_file, self.key_file)
        published = threading.Event()
        release = threading.Event()
        writer_started = threading.Event()
        rotation_outcome = []
        writer_outcome = []
        publish = self.store._publish_keyring

        def paused_publish(keys):
            publish(keys)
            published.set()
            if not release.wait(5):
                raise RuntimeError("test release timed out")

        def writer():
            writer_started.set()
            self._capture(
                writer_outcome,
                lambda: stale.issue("agent", "waiting", self.root / "waiting.token"),
            )

        with mock.patch.object(self.store, "_publish_keyring", side_effect=paused_publish):
            rotating = threading.Thread(
                target=lambda: self._capture(rotation_outcome, self.store.rotate_key))
            rotating.start()
            self.assertTrue(published.wait(5))
            writing = threading.Thread(target=writer)
            writing.start()
            self.assertTrue(writer_started.wait(5))
            with self.assertRaisesRegex(IdentityError, "^identity_key_rotation_busy$"):
                self.store.rotate_key()
            release.set()
            rotating.join(5)
            writing.join(5)

        self.assertFalse(rotating.is_alive())
        self.assertFalse(writing.is_alive())
        self.assertIsInstance(rotation_outcome[0], dict)
        self.assertEqual(str(writer_outcome[0]), "identity_store_key_changed")
        self.assertFalse((self.root / "waiting.token").exists())
        self.assertEqual(IdentityStore(self.store_file, self.key_file).verify()["records"], 0)

    def test_manual_rotation_lock_is_nonblocking(self):
        descriptor = os.open(
            self.store._lock_path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(IdentityError, "^identity_key_rotation_busy$"):
                self.store.rotate_key()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def test_unlock_failure_still_closes_descriptor_and_allows_resume(self):
        original_flock = fcntl.flock

        def fail_unlock(descriptor, operation):
            if operation == fcntl.LOCK_UN:
                raise OSError("synthetic unlock failure")
            return original_flock(descriptor, operation)

        with mock.patch("enkstein_guard.identities.fcntl.flock", side_effect=fail_unlock):
            with self.assertRaisesRegex(IdentityError, "^identity_store_rotation_failed$"):
                self.store.rotate_key()
        ring = json.loads(self.key_file.read_bytes())
        self.assertEqual(len(ring), 2)

        recovered = IdentityStore(self.store_file, self.key_file)
        result = recovered.rotate_key(resume=True)
        self.assertTrue(result["resumed"])
        self.assertEqual(result["key_count"], 2)
        self.assertEqual(json.loads(self.key_file.read_bytes()), ring)

    def test_malformed_duplicate_noncanonical_and_full_rings_fail_closed(self):
        values = (
            b"[]",
            b"{}",
            b'["not-a-key"]',
            json.dumps(["0" * 64, "0" * 64], separators=(",", ":")).encode(),
            b'[ "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a" ]',
        )
        for number, value in enumerate(values):
            store = self.create_store("bad-ring-%d" % number)
            store.key_file.write_bytes(value)
            store.key_file.chmod(0o600)
            with self.subTest(value=value[:24]):
                with self.assertRaisesRegex(IdentityError, "^identity_key_unavailable$"):
                    IdentityStore(store.path, store.key_file)

        oversized = self.create_store("oversized-ring")
        oversized.key_file.write_bytes(b"0" * (IdentityStore._MAX_KEY_FILE_BYTES + 1))
        oversized.key_file.chmod(0o600)
        with self.assertRaisesRegex(IdentityError, "^identity_key_unavailable$"):
            IdentityStore(oversized.path, oversized.key_file)

        full = self.create_store("full-ring")
        legacy = full.key_file.read_text()
        ring = [legacy, *(secrets.token_bytes(32).hex() for _ in range(31))]
        full.key_file.write_text(json.dumps(ring, separators=(",", ":")))
        full.key_file.chmod(0o600)
        reopened = IdentityStore(full.path, full.key_file)
        key_before, store_before = full.key_file.read_bytes(), full.path.read_bytes()
        with self.assertRaisesRegex(IdentityError, "^identity_keyring_full$"):
            reopened.rotate_key()
        self.assertEqual(full.key_file.read_bytes(), key_before)
        self.assertEqual(full.path.read_bytes(), store_before)
        self.assertEqual(reopened.rotate_key(resume=True)["key_count"], 32)

    def test_private_regular_paths_and_key_lock_collision_fail_closed(self):
        permissions = self.create_store("permissions")
        permissions.key_file.chmod(0o644)
        with self.assertRaises(IdentityError):
            IdentityStore(permissions.path, permissions.key_file)

        linked = self.create_store("linked")
        target = linked.key_file.with_name("real.key")
        linked.key_file.rename(target)
        linked.key_file.symlink_to(target)
        with self.assertRaises(IdentityError):
            IdentityStore(linked.path, linked.key_file)

        unsafe_lock = self.create_store("unsafe-lock")
        unsafe_lock._lock_path.write_bytes(b"")
        unsafe_lock._lock_path.chmod(0o644)
        with self.assertRaisesRegex(IdentityError, "^identity_store_rotation_failed$"):
            unsafe_lock.rotate_key()

        linked_lock = self.create_store("linked-lock")
        lock_target = linked_lock._lock_path.with_name("lock-target")
        lock_target.write_bytes(b"")
        lock_target.chmod(0o600)
        linked_lock._lock_path.symlink_to(lock_target)
        with self.assertRaisesRegex(IdentityError, "^identity_store_rotation_failed$"):
            linked_lock.rotate_key()

        collision_path = self.root / "collision/identities.json"
        collision_key = collision_path.with_name(collision_path.name + ".lock")
        with self.assertRaisesRegex(IdentityError, "^identity_store_exists$"):
            IdentityStore.initialize(collision_path, collision_key)

    def test_invalid_resume_and_reentrant_rotation_have_fixed_errors(self):
        with self.assertRaisesRegex(IdentityError, "^identity_store_rotation_failed$"):
            self.store.rotate_key(resume=1)

        publish = self.store._publish_keyring
        nested = []

        def reentrant(keys):
            self._capture(nested, self.store.rotate_key)
            publish(keys)

        with mock.patch.object(self.store, "_publish_keyring", side_effect=reentrant):
            result = self.store.rotate_key()
        self.assertEqual(str(nested[0]), "identity_key_rotation_busy")
        self.assertEqual(result["records_reauthenticated"], 0)


if __name__ == "__main__":
    unittest.main()
