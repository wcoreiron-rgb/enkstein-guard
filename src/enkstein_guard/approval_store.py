"""Encrypted SQLite persistence for exact-action approval tickets.

The database exposes only a SHA-256 ticket reference.  Bindings, review views,
decisions, approver identity and credential digests are authenticated and
encrypted together with Fernet.  Creation is explicit: opening a missing,
corrupt or differently keyed store always fails closed.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat

from cryptography.fernet import Fernet, MultiFernet

from .vault import _check_private


IDENTITY = b"enkstein-guard-approvals-v1"
STATUSES = frozenset({"pending", "approved", "denied", "consumed"})
_DIGEST = re.compile(r"[a-f0-9]{64}")
_TICKET = re.compile(r"[A-Za-z0-9_-]{32,64}")
_STORAGE_ERRORS = (OSError, sqlite3.Error)
MAX_APPROVAL_KEYS = 32


class ApprovalStoreError(Exception):
    """Stable, fail-closed durable approval error."""


def _keyring(data):
    """Load one legacy raw Fernet key or a strict ordered JSON keyring."""
    try:
        encoded = data.strip()
        if encoded.startswith(b"["):
            values = json.loads(encoded)
            if (type(values) is not list or not 1 <= len(values) <= MAX_APPROVAL_KEYS
                    or any(type(value) is not str for value in values)
                    or len(set(values)) != len(values)):
                raise ValueError()
            keys = tuple(value.encode("ascii") for value in values)
        else:
            keys = (encoded,)
        ciphers = tuple(Fernet(key) for key in keys)
        return keys, MultiFernet(ciphers)
    except Exception:
        raise ApprovalStoreError("approval_store_key_unavailable") from None


def _atomic_private_write(path, data):
    """Publish a private file durably; pre-replace failure keeps the old file."""
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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


class ApprovalStore:
    """One-host encrypted approval store safe for concurrent local processes."""

    @classmethod
    def initialize(cls, database, key_file):
        database, key_file = Path(database), Path(key_file)
        if database == key_file or database.exists() or key_file.exists():
            raise ApprovalStoreError("approval_store_paths_already_exist")
        try:
            for parent in (database.parent, key_file.parent):
                parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _check_private(parent, directory=True)
            key = Fernet.generate_key()
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                # Preserve the legacy one-key format until an operator
                # explicitly rotates this store.
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
            fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
                connection.execute("INSERT INTO identity VALUES (?)", (Fernet(key).encrypt(IDENTITY),))
                connection.execute("CREATE TABLE approvals (id TEXT PRIMARY KEY, record BLOB NOT NULL)")
                connection.commit()
        except ApprovalStoreError:
            raise
        except Exception:
            # Never regenerate either half after partial creation.  An operator
            # must inspect and remove the explicitly selected new paths.
            raise ApprovalStoreError("approval_store_initialization_failed") from None
        return cls(database, key_file)

    def __init__(self, database, key_file):
        self.database, self.key_file = Path(database), Path(key_file)
        try:
            self._check_paths()
            self._key_bytes = self.key_file.read_bytes()
            self._keys, self._cipher = _keyring(self._key_bytes)
            self.verify()
        except ApprovalStoreError:
            raise
        except Exception:
            raise ApprovalStoreError("approval_store_unreadable") from None

    # -- storage helpers -------------------------------------------------
    def _check_paths(self):
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)
        if hasattr(self, "_key_bytes") and self.key_file.read_bytes() != self._key_bytes:
            raise ApprovalStoreError("approval_store_key_changed")

    @property
    def _rotation_lock_path(self):
        return self.key_file.with_name(self.key_file.name + ".rotation.lock")

    @contextmanager
    def _rotation_lock(self):
        """Acquire the stable per-store administrative rotation lock."""
        descriptor = None
        try:
            _check_private(self.key_file.parent, directory=True)
            descriptor = os.open(
                self._rotation_lock_path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            information = os.fstat(descriptor)
            if (not stat.S_ISREG(information.st_mode) or information.st_uid != os.getuid()
                    or information.st_mode & 0o077):
                raise ApprovalStoreError("approval_key_rotation_lock_unavailable")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ApprovalStoreError("approval_key_rotation_in_progress") from None
        except ApprovalStoreError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise ApprovalStoreError("approval_key_rotation_lock_unavailable") from None
        try:
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)

    def _identity(self, connection):
        rows = connection.execute("SELECT record FROM identity").fetchall()
        if len(rows) != 1 or self._cipher.decrypt(rows[0][0]) != IDENTITY:
            raise ApprovalStoreError("approval_store_integrity_failed")

    def _connect(self):
        try:
            self._check_paths()
            connection = sqlite3.connect(self.database, timeout=5)
            connection.execute("PRAGMA synchronous=FULL")
            self._identity(connection)
            return connection
        except ApprovalStoreError:
            if "connection" in locals():
                connection.close()
            raise
        except _STORAGE_ERRORS:
            if "connection" in locals():
                connection.close()
            raise ApprovalStoreError("approval_storage_unavailable") from None
        except Exception:
            if "connection" in locals():
                connection.close()
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    @staticmethod
    def _id(ticket):
        if not isinstance(ticket, str) or _TICKET.fullmatch(ticket) is None:
            raise ApprovalStoreError("approval_forbidden")
        return hashlib.sha256(ticket.encode()).hexdigest()

    def _encode(self, record):
        return self._cipher.encrypt(json.dumps(record, sort_keys=True, separators=(",", ":"),
                                               allow_nan=False).encode())

    def _decode(self, name, encrypted):
        try:
            record = json.loads(self._cipher.decrypt(encrypted))
            binding = record["binding"]
            required = {"tenant", "principal", "agent", "route", "operation", "resource", "destination",
                        "policy_version", "payload_sha256"}
            if (type(record) is not dict or set(binding) != required or
                    any(not isinstance(binding[key], str) for key in required) or
                    _DIGEST.fullmatch(binding["payload_sha256"]) is None or
                    _DIGEST.fullmatch(record["digest"]) is None or
                    record["status"] not in STATUSES or
                    type(record["expires"]) not in (int, float) or
                    type(record["created"]) not in (int, float) or
                    hashlib.sha256(record["ticket"].encode()).hexdigest() != name or
                    _TICKET.fullmatch(record["ticket"]) is None):
                raise ValueError()
            approver = record.get("approver")
            approver_digest = record.get("approver_digest")
            if record["status"] in {"approved", "consumed"} and (
                    not isinstance(approver, str) or not approver or
                    not isinstance(approver_digest, str) or _DIGEST.fullmatch(approver_digest) is None):
                raise ValueError()
            return record
        except Exception:
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    def _records(self, connection):
        return [(name, self._decode(name, encrypted))
                for name, encrypted in connection.execute("SELECT id, record FROM approvals")]

    def verify(self):
        """Authenticate the store identity and every ticket without mutation."""
        try:
            with closing(self._connect()) as connection:
                records = self._records(connection)
            return {"tickets": len(records), "status": "verified"}
        except ApprovalStoreError:
            raise
        except _STORAGE_ERRORS:
            raise self._storage_failure() from None
        except Exception:
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    @staticmethod
    def _purge(connection, records, now):
        remove = [name for name, item in records
                  if item["expires"] <= now or item["status"] == "consumed"]
        connection.executemany("DELETE FROM approvals WHERE id=?", ((name,) for name in remove))
        return [(name, item) for name, item in records if name not in set(remove)]

    @staticmethod
    def _storage_failure():
        return ApprovalStoreError("approval_storage_unavailable")

    # -- ticket lifecycle -----------------------------------------------
    def request(self, binding, digest, view, *, expires, created, max_pending, max_per_tenant):
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._check_paths()
                records = self._purge(connection, self._records(connection), created)
                for _, item in records:
                    if item["digest"] == digest and item["status"] in {"pending", "approved"}:
                        connection.commit()
                        return item
                tenant_count = sum(item["binding"]["tenant"] == binding["tenant"] for _, item in records)
                if len(records) >= max_pending or tenant_count >= max_per_tenant:
                    raise ApprovalStoreError("approval_capacity_reached")
                ticket = secrets.token_urlsafe(32)
                record = {"ticket": ticket, "binding": dict(binding), "digest": digest, "view": view,
                          "status": "pending", "expires": expires, "created": created}
                name = self._id(ticket)
                encrypted = self._encode(record)
                self._decode(name, encrypted)  # Reject malformed caller input before it can poison the store.
                connection.execute("INSERT INTO approvals VALUES (?, ?)",
                                   (name, encrypted))
                connection.commit()
                return record
        except ApprovalStoreError:
            raise
        except _STORAGE_ERRORS:
            raise self._storage_failure() from None
        except Exception:
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    def pending(self, tenants, now):
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._check_paths()
                records = self._purge(connection, self._records(connection), now)
                connection.commit()
            return [item for _, item in sorted(records, key=lambda pair: pair[1]["created"])
                    if tenants is None or item["binding"]["tenant"] in tenants]
        except ApprovalStoreError:
            raise
        except _STORAGE_ERRORS:
            raise self._storage_failure() from None
        except Exception:
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    def get(self, ticket):
        name = self._id(ticket)
        try:
            with closing(self._connect()) as connection:
                row = connection.execute("SELECT record FROM approvals WHERE id=?", (name,)).fetchone()
                return None if row is None else self._decode(name, row[0])
        except ApprovalStoreError:
            raise
        except _STORAGE_ERRORS:
            raise self._storage_failure() from None
        except Exception:
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    def decide(self, ticket, action_digest, status, approver, approver_digest, now):
        name = self._id(ticket)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._check_paths()
                row = connection.execute("SELECT record FROM approvals WHERE id=?", (name,)).fetchone()
                if row is None:
                    raise ApprovalStoreError("approval_forbidden")
                item = self._decode(name, row[0])
                if item["expires"] <= now:
                    raise ApprovalStoreError("approval_forbidden")
                if not secrets.compare_digest(action_digest, item["digest"]):
                    raise ApprovalStoreError("action_digest_mismatch")
                if item["status"] != "pending":
                    raise ApprovalStoreError("approval_not_pending")
                item.update(status=status, approver=approver, approver_digest=approver_digest)
                connection.execute("UPDATE approvals SET record=? WHERE id=?", (self._encode(item), name))
                connection.commit()
                return item
        except ApprovalStoreError:
            raise
        except _STORAGE_ERRORS:
            raise self._storage_failure() from None
        except Exception:
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    def consume(self, ticket, action_digest, now, approver, approver_digest):
        """Atomically change one approved ticket to consumed.

        Binding equality is checked by ``ApprovalBook`` immediately before
        this call.  The binding is immutable inside the authenticated record;
        this transaction rechecks every mutable authorization input.
        """
        name = self._id(ticket)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._check_paths()
                row = connection.execute("SELECT record FROM approvals WHERE id=?", (name,)).fetchone()
                if row is None:
                    raise ApprovalStoreError("approval_not_consumable")
                item = self._decode(name, row[0])
                valid = (item["status"] == "approved" and item["expires"] > now and
                         secrets.compare_digest(item["digest"], action_digest) and
                         item.get("approver") == approver and
                         secrets.compare_digest(item.get("approver_digest", ""), approver_digest))
                if not valid:
                    raise ApprovalStoreError("approval_not_consumable")
                item["status"] = "consumed"
                connection.execute("UPDATE approvals SET record=? WHERE id=?", (self._encode(item), name))
                connection.commit()
                return item
        except ApprovalStoreError:
            raise
        except _STORAGE_ERRORS:
            raise self._storage_failure() from None
        except Exception:
            raise ApprovalStoreError("approval_store_integrity_failed") from None

    def rotate_key(self, *, resume=False):
        """Rotate all approval ciphertext offline with recoverable key publish.

        The new primary is durably published while retaining every old decrypt
        key before the SQLite transaction rewrites ciphertext. If that rewrite
        fails, a fresh opener can read the unchanged logical state and
        ``resume=True`` reuses the published ring without adding another key.
        """
        if type(resume) is not bool:
            raise ApprovalStoreError("approval_key_rotation_invalid_resume")
        try:
            with self._rotation_lock():
                self._check_paths()
                current_bytes = self.key_file.read_bytes()
                current_keys, current_cipher = _keyring(current_bytes)
                if current_bytes != self._key_bytes:
                    raise ApprovalStoreError("approval_store_key_changed")
                if not resume and len(current_keys) >= MAX_APPROVAL_KEYS:
                    raise ApprovalStoreError("approval_keyring_full")

                with closing(sqlite3.connect(self.database, timeout=0)) as connection:
                    connection.execute("PRAGMA synchronous=FULL")
                    connection.execute("BEGIN IMMEDIATE")
                    # Rotation and ordinary writers can race for SQLite. The
                    # winner may have changed the key file while this caller
                    # waited, so authenticate the exact bytes again under the
                    # database write lock.
                    self._check_paths()
                    self._keys, self._cipher = current_keys, current_cipher
                    self._identity(connection)
                    records = self._records(connection)

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
                        # Once publication succeeds this object must follow the
                        # recoverable new ring even if the DB rewrite rolls back.
                        self._key_bytes = data
                        self._keys, self._cipher = _keyring(data)

                    identity = connection.execute("SELECT record FROM identity").fetchone()[0]
                    connection.execute(
                        "UPDATE identity SET record=?", (self._cipher.rotate(identity),))
                    rows = connection.execute("SELECT id,record FROM approvals").fetchall()
                    connection.executemany(
                        "UPDATE approvals SET record=? WHERE id=?",
                        ((self._cipher.rotate(encrypted), name) for name, encrypted in rows),
                    )
                    connection.commit()

                # Verify the committed database through the same cached ring.
                self.verify()
                return {
                    "rotated": True,
                    "key_fingerprint": hashlib.sha256(self._keys[0]).hexdigest(),
                    "key_count": len(self._keys),
                    "records": len(records),
                    "resumed": resume,
                }
        except ApprovalStoreError:
            raise
        except Exception:
            raise ApprovalStoreError("approval_key_rotation_failed") from None


# Descriptive compatibility name for direct library callers.
DurableApprovalStore = ApprovalStore
