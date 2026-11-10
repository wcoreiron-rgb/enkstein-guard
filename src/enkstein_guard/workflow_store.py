"""Encrypted, exclusively owned single-host workflow snapshots.

Creation is explicit.  Opening a missing, corrupt, differently keyed, or
already owned store fails closed.  The lock is deliberately host-local; this
module makes no active-active or multi-host coordination claim.
"""
from __future__ import annotations

import base64
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading

from cryptography.fernet import Fernet, MultiFernet

from .vault import _check_private


IDENTITY = b"enkstein-guard-workflows-v1"
EMPTY = {"version": 1, "registry": None, "agents": [], "credentials": [],
         "workflows": [], "inflight": [], "interrupted": [], "clock_floor": None}
MAX_SNAPSHOT_BYTES = 16_777_216
MAX_ENCRYPTED_BYTES = 22_500_000
MAX_WORKFLOW_KEYS = 32
MAX_KEY_FILE_BYTES = 8192
_STORAGE_ERRORS = (OSError, sqlite3.Error)


class WorkflowStoreError(Exception):
    """Stable, fail-closed durable workflow error."""


def _keyring(data):
    """Load one legacy raw Fernet key or a strict ordered JSON keyring."""
    try:
        if not isinstance(data, bytes) or not data or len(data) > MAX_KEY_FILE_BYTES:
            raise ValueError()
        encoded = data.strip()
        if encoded.startswith(b"["):
            values = json.loads(encoded.decode("ascii"))
            if (type(values) is not list or not 1 <= len(values) <= MAX_WORKFLOW_KEYS
                    or any(type(value) is not str for value in values)
                    or len(set(values)) != len(values)):
                raise ValueError()
            keys = tuple(value.encode("ascii") for value in values)
            materials = tuple(base64.b64decode(key, altchars=b"-_", validate=True)
                              for key in keys)
            if (any(len(key) != 44 or len(material) != 32
                    or base64.urlsafe_b64encode(material) != key
                    for key, material in zip(keys, materials))
                    or len(set(materials)) != len(materials)):
                raise ValueError()
        else:
            # Legacy readers accepted any Fernet-compatible raw bytes. Keep
            # that compatibility, but normalize the retained representation
            # when an explicit rotation later publishes a strict JSON ring.
            Fernet(encoded)
            material = base64.urlsafe_b64decode(encoded)
            if len(material) != 32:
                raise ValueError()
            keys = (base64.urlsafe_b64encode(material),)
        ciphers = tuple(Fernet(key) for key in keys)
        return keys, MultiFernet(ciphers)
    except Exception:
        raise WorkflowStoreError("workflow_store_key_unavailable") from None


def _atomic_private_write(path, data):
    """Durably replace a private file, preserving the old file before replace."""
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


class WorkflowStore:
    """Encrypted snapshot store with one exclusive coordinator owner."""

    @classmethod
    def initialize(cls, database, key_file):
        database, key_file = Path(database), Path(key_file)
        lock_file = database.with_name(database.name + ".lock")
        if (database == key_file or key_file == lock_file
                or database.exists() or key_file.exists()):
            raise WorkflowStoreError("workflow_store_paths_already_exist")
        try:
            for parent in (database.parent, key_file.parent):
                parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _check_private(parent, directory=True)
            key = Fernet.generate_key()
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
            fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            cipher = Fernet(key)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
                connection.execute("INSERT INTO identity VALUES (?)", (cipher.encrypt(IDENTITY),))
                connection.execute("CREATE TABLE snapshot (id INTEGER PRIMARY KEY CHECK (id=1), record BLOB NOT NULL)")
                connection.execute("INSERT INTO snapshot VALUES (1, ?)",
                                   (cipher.encrypt(cls._encode_json(EMPTY)),))
                connection.commit()
        except WorkflowStoreError:
            raise
        except Exception:
            # Never regenerate either half after partial creation.
            raise WorkflowStoreError("workflow_store_initialization_failed") from None
        return cls(database, key_file)

    def __init__(self, database, key_file):
        self.database, self.key_file = Path(database), Path(key_file)
        self.lock_file = self.database.with_name(self.database.name + ".lock")
        if self.database == self.key_file or self.key_file == self.lock_file:
            raise WorkflowStoreError("workflow_store_paths_conflict")
        self._lock_fd = None
        self._closed = False
        self._attached = False
        # Every operation that depends on the cached keyring shares this lock.
        # In particular, attach/save/load cannot observe a half-completed
        # same-object administrative rotation.
        self._operation_lock = threading.RLock()
        try:
            self._check_paths(require_lock=False)
            self._key_bytes = self.key_file.read_bytes()
            self._keys, self._cipher = _keyring(self._key_bytes)
            self._claim()
            self.verify()
        except WorkflowStoreError:
            self._release()
            raise
        except Exception:
            self._release()
            raise WorkflowStoreError("workflow_store_unreadable") from None

    @staticmethod
    def _encode_json(value):
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            raise WorkflowStoreError("workflow_store_capacity_reached")
        return encoded

    def _claim(self):
        try:
            fd = os.open(self.lock_file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            _check_private(self.lock_file)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_fd = fd
        except Exception:
            if "fd" in locals():
                os.close(fd)
            raise WorkflowStoreError("workflow_store_already_owned") from None

    def _release(self):
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None

    def _check_paths(self, *, require_lock=True):
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)
        if require_lock:
            _check_private(self.lock_file)
        if (hasattr(self, "_key_bytes")
                and self.key_file.read_bytes() != self._key_bytes):
            raise WorkflowStoreError("workflow_store_key_changed")

    def _identity_record(self, connection):
        sizes = connection.execute("SELECT length(record) FROM identity").fetchall()
        if len(sizes) != 1 or sizes[0][0] is None or sizes[0][0] > 1024:
            raise WorkflowStoreError("workflow_store_integrity_failed")
        rows = connection.execute("SELECT record FROM identity").fetchall()
        if len(rows) != 1 or self._cipher.decrypt(rows[0][0]) != IDENTITY:
            raise WorkflowStoreError("workflow_store_integrity_failed")
        return rows[0][0]

    def _snapshot_record(self, connection):
        sizes = connection.execute("SELECT id,length(record) FROM snapshot").fetchall()
        if (len(sizes) != 1 or sizes[0][0] != 1 or sizes[0][1] is None
                or sizes[0][1] > MAX_ENCRYPTED_BYTES):
            raise WorkflowStoreError("workflow_store_integrity_failed")
        rows = connection.execute("SELECT id,record FROM snapshot").fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise WorkflowStoreError("workflow_store_integrity_failed")
        snapshot = self._decode(rows[0][1])
        return rows[0][1], snapshot

    def _connect(self):
        if self._closed or self._lock_fd is None:
            raise WorkflowStoreError("workflow_store_closed")
        try:
            self._check_paths()
            connection = sqlite3.connect(self.database, timeout=5)
            connection.execute("PRAGMA synchronous=FULL")
            self._identity_record(connection)
            return connection
        except WorkflowStoreError:
            if "connection" in locals():
                connection.close()
            raise
        except _STORAGE_ERRORS:
            if "connection" in locals():
                connection.close()
            raise WorkflowStoreError("workflow_storage_unavailable") from None
        except Exception:
            if "connection" in locals():
                connection.close()
            raise WorkflowStoreError("workflow_store_integrity_failed") from None

    def _decode(self, encrypted):
        try:
            if not isinstance(encrypted, bytes) or len(encrypted) > MAX_ENCRYPTED_BYTES:
                raise ValueError()
            plaintext = self._cipher.decrypt(encrypted)
            if len(plaintext) > MAX_SNAPSHOT_BYTES:
                raise ValueError()
            value = json.loads(plaintext)
            if type(value) is not dict or value.get("version") != 1:
                raise ValueError()
            # Re-encoding rejects non-finite numbers and non-JSON values.
            self._encode_json(value)
            return value
        except Exception:
            raise WorkflowStoreError("workflow_store_integrity_failed") from None

    def load(self):
        with self._operation_lock:
            try:
                with closing(self._connect()) as connection:
                    _, snapshot = self._snapshot_record(connection)
                    return snapshot
            except WorkflowStoreError:
                raise
            except _STORAGE_ERRORS:
                raise WorkflowStoreError("workflow_storage_unavailable") from None
            except Exception:
                raise WorkflowStoreError("workflow_store_integrity_failed") from None

    def save(self, snapshot):
        with self._operation_lock:
            try:
                encrypted = self._cipher.encrypt(self._encode_json(snapshot))
                # Verify the exact encrypted value before allowing it into the store.
                self._decode(encrypted)
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._check_paths()
                    changed = connection.execute(
                        "UPDATE snapshot SET record=? WHERE id=1", (encrypted,)).rowcount
                    if changed != 1:
                        raise WorkflowStoreError("workflow_store_integrity_failed")
                    connection.commit()
            except WorkflowStoreError:
                raise
            except _STORAGE_ERRORS:
                raise WorkflowStoreError("workflow_storage_unavailable") from None
            except Exception:
                raise WorkflowStoreError("workflow_store_integrity_failed") from None

    def verify(self):
        self.load()
        return {"status": "verified"}

    def attach(self):
        """Bind this store object to exactly one coordinator."""
        with self._operation_lock:
            if self._closed or self._attached:
                raise WorkflowStoreError("workflow_store_already_attached")
            self._attached = True

    def close(self):
        with self._operation_lock:
            if not self._closed:
                self._closed = True
                self._attached = False
                self._release()

    def rotate_key(self, *, resume=False):
        """Rotate the offline snapshot key with recoverable key publication.

        A newly generated primary and all retained decrypt keys are durably
        published before identity and snapshot ciphertext are rewritten in one
        SQLite transaction. A failed post-publication rewrite can therefore be
        opened safely and completed with ``resume=True`` without another key.
        """
        if type(resume) is not bool:
            raise WorkflowStoreError("workflow_key_rotation_invalid_resume")
        with self._operation_lock:
            if self._closed:
                raise WorkflowStoreError("workflow_store_closed")
            if self._lock_fd is None:
                raise WorkflowStoreError("workflow_key_rotation_requires_ownership")
            if self._attached:
                raise WorkflowStoreError("workflow_key_rotation_attached")
            try:
                self._check_paths()
                current_bytes = self.key_file.read_bytes()
                current_keys, current_cipher = _keyring(current_bytes)
                if current_bytes != self._key_bytes:
                    raise WorkflowStoreError("workflow_store_key_changed")
                if not resume and len(current_keys) >= MAX_WORKFLOW_KEYS:
                    raise WorkflowStoreError("workflow_keyring_full")

                with closing(sqlite3.connect(self.database, timeout=0)) as connection:
                    connection.execute("PRAGMA synchronous=FULL")
                    connection.execute("BEGIN IMMEDIATE")
                    # Authenticate the exact key bytes and all durable state
                    # again while holding SQLite's writer lock. Publication is
                    # forbidden until both records are known complete.
                    self._check_paths()
                    if self.key_file.read_bytes() != current_bytes:
                        raise WorkflowStoreError("workflow_store_key_changed")
                    self._keys, self._cipher = current_keys, current_cipher
                    identity = self._identity_record(connection)
                    snapshot, _ = self._snapshot_record(connection)

                    if not resume:
                        new_key = Fernet.generate_key()
                        while new_key in current_keys:
                            new_key = Fernet.generate_key()
                        keys = (new_key, *current_keys)
                        data = json.dumps(
                            [key.decode("ascii") for key in keys],
                            separators=(",", ":"),
                        ).encode()
                        _atomic_private_write(self.key_file, data)
                        # Publication is the recovery boundary: even if the DB
                        # transaction rolls back, this handle follows the new
                        # ring and legacy ciphertext stays decryptable.
                        self._key_bytes = data
                        self._keys = keys
                        self._cipher = MultiFernet(tuple(Fernet(key) for key in keys))

                    identity_changed = connection.execute(
                        "UPDATE identity SET record=?",
                        (self._cipher.rotate(identity),),
                    ).rowcount
                    snapshot_changed = connection.execute(
                        "UPDATE snapshot SET record=? WHERE id=1",
                        (self._cipher.rotate(snapshot),),
                    ).rowcount
                    if identity_changed != 1 or snapshot_changed != 1:
                        raise WorkflowStoreError("workflow_store_integrity_failed")
                    connection.commit()

                self.verify()
                return {
                    "current_key_fingerprint": hashlib.sha256(self._keys[0]).hexdigest(),
                    "key_count": len(self._keys),
                    "records_reencrypted": 1,
                    "resumed": resume,
                }
            except WorkflowStoreError:
                raise
            except Exception:
                raise WorkflowStoreError("workflow_key_rotation_failed") from None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
