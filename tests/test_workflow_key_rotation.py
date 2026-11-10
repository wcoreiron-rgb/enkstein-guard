import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.fernet import Fernet

import enkstein_guard.workflow_store as workflow_store
from enkstein_guard.workflow_store import WorkflowStore, WorkflowStoreError


def _records(database):
    with sqlite3.connect(database) as connection:
        identity = connection.execute("SELECT record FROM identity").fetchone()[0]
        snapshot = connection.execute(
            "SELECT record FROM snapshot WHERE id=1").fetchone()[0]
    return identity, snapshot


class WorkflowKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="eg-workflow-rotation-")
        self.root = Path(self.temporary.name)
        self.database = self.root / "workflows" / "data.sqlite3"
        self.key_file = self.root / "keys" / "workflows.key"
        self.store = None

    def tearDown(self):
        if self.store is not None:
            self.store.close()
        self.temporary.cleanup()

    def initialize(self):
        self.store = WorkflowStore.initialize(self.database, self.key_file)
        return self.store

    def test_legacy_raw_key_remains_readable_until_explicit_rotation(self):
        store = self.initialize()
        raw_key = self.key_file.read_bytes()
        self.assertFalse(raw_key.lstrip().startswith(b"["))
        expected = store.load()
        store.close()
        self.store = WorkflowStore(self.database, self.key_file)
        self.assertEqual(self.store.load(), expected)
        self.assertEqual(self.key_file.read_bytes(), raw_key)
        self.store.close()

        # Fernet-compatible legacy whitespace remains supported before the
        # explicit conversion to a canonical ordered ring.
        self.key_file.write_bytes(b"\n" + raw_key + b"\n")
        self.store = WorkflowStore(self.database, self.key_file)
        self.assertEqual(self.store.load(), expected)
        self.store.rotate_key()
        ring = json.loads(self.key_file.read_text("ascii"))
        self.assertEqual(ring[1], raw_key.decode("ascii"))

    def test_empty_and_nonempty_rotation_reopen_with_exact_logical_state(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                if self.store is not None:
                    self.store.close()
                root = self.root / ("populated" if populated else "empty")
                database = root / "workflows.sqlite3"
                key_file = root / "workflows.key"
                store = WorkflowStore.initialize(database, key_file)
                if populated:
                    expected = store.load()
                    expected.update({
                        "unknown_outcome": {"opaque": [1, "two", None]},
                        "durable_budget": {"calls": 7, "units": 11},
                        "memory": {"labels": ["sensitive"], "grant": "write"},
                    })
                    store.save(expected)
                else:
                    expected = store.load()
                before_plaintext = Fernet(key_file.read_bytes()).decrypt(_records(database)[1])

                result = store.rotate_key()
                ring = json.loads(key_file.read_text("ascii"))
                self.assertEqual(result, {
                    "current_key_fingerprint": hashlib.sha256(
                        ring[0].encode("ascii")).hexdigest(),
                    "key_count": 2,
                    "records_reencrypted": 1,
                    "resumed": False,
                })
                self.assertEqual(Fernet(ring[0].encode("ascii")).decrypt(
                    _records(database)[1]), before_plaintext)
                store.close()

                reopened = WorkflowStore(database, key_file)
                try:
                    self.assertEqual(reopened.load(), expected)
                finally:
                    reopened.close()

    def test_attached_closed_unowned_and_second_owner_are_refused(self):
        store = self.initialize()
        with self.assertRaisesRegex(WorkflowStoreError, "already_owned"):
            WorkflowStore(self.database, self.key_file)

        store.attach()
        with self.assertRaisesRegex(WorkflowStoreError, "rotation_attached"):
            store.rotate_key()
        store.close()
        with self.assertRaisesRegex(WorkflowStoreError, "workflow_store_closed"):
            store.rotate_key()

        self.store = WorkflowStore(self.database, self.key_file)
        self.store._release()
        with self.assertRaisesRegex(WorkflowStoreError, "requires_ownership"):
            self.store.rotate_key()

    def test_corrupt_snapshot_or_identity_never_changes_key_file(self):
        for table in ("snapshot", "identity"):
            with self.subTest(table=table):
                root = self.root / table
                database = root / "data.sqlite3"
                key_file = root / "workflows.key"
                store = WorkflowStore.initialize(database, key_file)
                before = key_file.read_bytes()
                with sqlite3.connect(database) as connection:
                    connection.execute(f"UPDATE {table} SET record=?", (b"corrupt",))
                    connection.commit()
                with self.assertRaises(WorkflowStoreError):
                    store.rotate_key()
                self.assertEqual(key_file.read_bytes(), before)
                store.close()

    def test_post_publish_rewrite_failure_is_reopenable_and_resumable(self):
        store = self.initialize()
        expected = store.load()
        expected["unknown_outcome"] = {"operation": "uncertain", "replay": False}
        store.save(expected)
        old_key = self.key_file.read_bytes()
        old_records = _records(self.database)
        original_rotate = workflow_store.MultiFernet.rotate
        rotate_calls = 0

        def fail_snapshot_rewrite(cipher, token):
            nonlocal rotate_calls
            rotate_calls += 1
            if rotate_calls == 2:
                raise RuntimeError("injected snapshot rewrite failure")
            return original_rotate(cipher, token)

        with mock.patch.object(workflow_store.MultiFernet, "rotate",
                               new=fail_snapshot_rewrite):
            with self.assertRaisesRegex(WorkflowStoreError, "rotation_failed"):
                store.rotate_key()

        published = self.key_file.read_bytes()
        ring = json.loads(published)
        self.assertNotEqual(published, old_key)
        self.assertEqual(len(ring), 2)
        self.assertEqual(_records(self.database), old_records)
        self.assertEqual(store.load(), expected)
        store.close()

        self.store = WorkflowStore(self.database, self.key_file)
        self.assertEqual(self.store.load(), expected)
        result = self.store.rotate_key(resume=True)
        self.assertEqual(result["key_count"], 2)
        self.assertTrue(result["resumed"])
        self.assertEqual(self.key_file.read_bytes(), published)
        self.assertEqual(self.store.load(), expected)
        primary = Fernet(ring[0].encode("ascii"))
        identity, snapshot = _records(self.database)
        self.assertEqual(primary.decrypt(identity), workflow_store.IDENTITY)
        self.assertEqual(json.loads(primary.decrypt(snapshot)), expected)

    def test_malformed_keyrings_fail_closed_without_sensitive_errors(self):
        canonical = Fernet.generate_key()
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        final_index = alphabet.index(canonical[-2])
        alternate = canonical[:-2] + bytes((alphabet[final_index + 1],)) + b"="
        self.assertEqual(base64.urlsafe_b64decode(canonical),
                         base64.urlsafe_b64decode(alternate))
        malformed = (
            b"[]",
            json.dumps(["not-a-fernet-key"]).encode(),
            json.dumps(["duplicate", "duplicate"]).encode(),
            json.dumps([canonical.decode("ascii"), alternate.decode("ascii")]).encode(),
            json.dumps([Fernet.generate_key().decode("ascii") for _ in range(33)]).encode(),
            b"[\"operator-secret-marker\"",
        )
        for index, data in enumerate(malformed):
            with self.subTest(index=index):
                root = self.root / f"malformed-{index}"
                database = root / "data.sqlite3"
                key_file = root / "workflow.key"
                store = WorkflowStore.initialize(database, key_file)
                store.close()
                key_file.write_bytes(data)
                with self.assertRaises(WorkflowStoreError) as raised:
                    WorkflowStore(database, key_file)
                message = str(raised.exception)
                self.assertNotIn("operator-secret-marker", message)
                self.assertNotIn(str(key_file), message)

    def test_full_ring_rejects_new_rotation_before_mutation_but_can_resume(self):
        store = self.initialize()
        raw_key = self.key_file.read_bytes()
        store.close()
        ring = [raw_key.decode("ascii")]
        ring.extend(Fernet.generate_key().decode("ascii") for _ in range(31))
        full = json.dumps(ring, separators=(",", ":")).encode()
        self.key_file.write_bytes(full)
        self.store = WorkflowStore(self.database, self.key_file)

        with self.assertRaisesRegex(WorkflowStoreError, "keyring_full"):
            self.store.rotate_key()
        self.assertEqual(self.key_file.read_bytes(), full)
        result = self.store.rotate_key(resume=True)
        self.assertEqual(result["key_count"], 32)
        self.assertEqual(self.key_file.read_bytes(), full)

    @unittest.skipUnless(os.name == "posix", "POSIX private-path enforcement")
    def test_public_key_file_and_symlink_are_rejected(self):
        for unsafe in ("public", "symlink"):
            with self.subTest(unsafe=unsafe):
                root = self.root / unsafe
                database = root / "data.sqlite3"
                key_file = root / "workflow.key"
                store = WorkflowStore.initialize(database, key_file)
                store.close()
                if unsafe == "public":
                    key_file.chmod(0o644)
                else:
                    target = root / "target.key"
                    target.write_bytes(key_file.read_bytes())
                    target.chmod(0o600)
                    key_file.unlink()
                    key_file.symlink_to(target)
                with self.assertRaises(WorkflowStoreError):
                    WorkflowStore(database, key_file)

    def test_stale_handle_rejects_load_save_and_rotation_without_db_mutation(self):
        store = self.initialize()
        before_records = _records(self.database)
        old_key = self.key_file.read_bytes()
        marker = "snapshot-sensitive-marker"
        self.key_file.write_bytes(Fernet.generate_key())
        operations = (
            store.load,
            lambda: store.save({"version": 1, "marker": marker}),
            store.rotate_key,
        )
        for operation in operations:
            with self.assertRaises(WorkflowStoreError) as raised:
                operation()
            self.assertNotIn(marker, str(raised.exception))
            self.assertNotIn(str(self.key_file), str(raised.exception))
        self.assertEqual(_records(self.database), before_records)
        self.key_file.write_bytes(old_key)

    def test_rotation_serializes_same_object_load_save_and_attach(self):
        store = self.initialize()
        replacement = store.load()
        replacement["unknown_outcome"] = {"preserve": True}
        entered = threading.Event()
        release = threading.Event()
        real_publish = workflow_store._atomic_private_write

        def blocking_publish(path, data):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test publication timeout")
            real_publish(path, data)

        results = []
        errors = []

        def run(name, operation):
            try:
                results.append((name, operation()))
            except Exception as error:  # pragma: no cover - asserted below
                errors.append((name, error))

        with mock.patch.object(workflow_store, "_atomic_private_write",
                               side_effect=blocking_publish):
            rotation = threading.Thread(
                target=run, args=("rotate", store.rotate_key), daemon=True)
            rotation.start()
            self.assertTrue(entered.wait(5))
            contenders = [
                threading.Thread(target=run, args=("load", store.load), daemon=True),
                threading.Thread(target=run, args=("save", lambda: store.save(replacement)),
                                 daemon=True),
                threading.Thread(target=run, args=("attach", store.attach), daemon=True),
            ]
            for contender in contenders:
                contender.start()
            self.assertFalse(any(not contender.is_alive() for contender in contenders))
            release.set()
            rotation.join(5)
            for contender in contenders:
                contender.join(5)

        self.assertFalse(rotation.is_alive())
        self.assertTrue(all(not contender.is_alive() for contender in contenders))
        self.assertEqual(errors, [])
        self.assertEqual({name for name, _ in results}, {"rotate", "load", "save", "attach"})
        self.assertEqual(store.load(), replacement)


if __name__ == "__main__":
    unittest.main()
