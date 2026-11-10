"""Guard-issued agent/approver credentials and encrypted connector secrets.

Identity and permissions are configuration; this module stores only what must
stay secret or must survive restarts: credential digests (never plaintext),
revocations and connector secret values (encrypted). Credentials are written
once to an exclusive 0600 file chosen by the operator and are never printed.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time

from cryptography.fernet import Fernet, MultiFernet

from .vault import _atomic_private_write, _check_private

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
KINDS = ("agent", "approver")


class IdentityError(Exception):
    pass


def new_credential(kind):
    return ("ega_" if kind == "agent" else "egh_") + secrets.token_urlsafe(32)


def write_secret_file(path, value):
    """Exclusive 0600 creation; never overwrites. Returns the absolute path."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise IdentityError("credential_output_exists")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise IdentityError("credential_output_unavailable") from None
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(value + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return str(path.resolve())


def read_secret_input(source, *, stdin=None, limit=65536):
    """Read a secret from a private file or '-' (stdin); strips one newline."""
    if source == "-":
        import sys
        data = (stdin or sys.stdin).read(limit + 1)
    else:
        path = Path(source)
        try:
            info = path.lstat()
        except OSError:
            raise IdentityError("secret_input_unavailable") from None
        if path.is_symlink() or not path.is_file() or (os.name == "posix" and info.st_mode & 0o077):
            raise IdentityError("secret_input_must_be_private_file")
        data = path.read_text(encoding="utf-8")[:limit + 1]
    if len(data) > limit:
        raise IdentityError("secret_input_too_large")
    value = data[:-1] if data.endswith("\n") else data
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise IdentityError("secret_input_invalid")
    return value


def _identity_atomic_private_write(path, data):
    """Atomically publish and durably sync one identity-owned private file."""
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


def _identity_read_private_regular(path, *, limit=None):
    """Read an owner-private regular file without following its final link."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        information = os.fstat(descriptor)
        if (not stat.S_ISREG(information.st_mode)
                or (os.name == "posix" and (information.st_uid != os.getuid()
                                             or information.st_mode & 0o077))):
            raise OSError("unsafe identity path")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            data = stream.read() if limit is None else stream.read(limit + 1)
            if limit is not None and len(data) > limit:
                raise OSError("identity file too large")
            return data
    finally:
        if descriptor is not None:
            os.close(descriptor)


class IdentityStore:
    """HMAC-authenticated JSON store of credential digests and revocations."""

    _MAX_KEYS = 32
    _MAX_KEY_FILE_BYTES = 8192
    _HEX_KEY = re.compile(r"[a-f0-9]{64}")
    _HEX_DIGEST = re.compile(r"[a-f0-9]{64}")

    @classmethod
    def initialize(cls, path, key_file):
        path, key_file = Path(path), Path(key_file)
        lock = path.with_name(path.name + ".lock")
        if (path.exists() or key_file.exists() or path == key_file
                or os.path.abspath(key_file) == os.path.abspath(lock)):
            raise IdentityError("identity_store_exists")
        for parent in (path.parent, key_file.parent):
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _check_private(parent, directory=True)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32).hex().encode())
            stream.flush()
            os.fsync(stream.fileno())
        store = cls.__new__(cls)
        store.path, store.key_file = path, key_file
        store._object_lock = threading.RLock()
        store._rotation_guard = threading.Lock()
        store._key_file_bytes, store._keys = store._read_keyring()
        body = {"schema": "enkstein-guard-identities-v1", "agent": {}, "approver": {}, "serial": 0}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        store._write(body)
        return cls(path, key_file)

    def __init__(self, path, key_file):
        self.path, self.key_file = Path(path), Path(key_file)
        self._object_lock = threading.RLock()
        self._rotation_guard = threading.Lock()
        if (os.path.abspath(self.path) == os.path.abspath(self.key_file)
                or os.path.abspath(self.key_file) == os.path.abspath(self._lock_path)):
            raise IdentityError("identity_store_path_unsafe")
        try:
            for item in (self.path, self.key_file):
                _check_private(item.parent, directory=True)
            _identity_read_private_regular(self.path)
        except Exception:
            raise IdentityError("identity_store_path_unsafe") from None
        self._key_file_bytes, self._keys = self._read_keyring()
        self._read()

    @property
    def _lock_path(self):
        return self.path.with_name(self.path.name + ".lock")

    def _read_keyring(self):
        """Read one legacy raw hex key or a canonical ordered JSON ring."""
        try:
            _check_private(self.key_file.parent, directory=True)
            data = _identity_read_private_regular(
                self.key_file, limit=self._MAX_KEY_FILE_BYTES)
            if data.startswith(b"["):
                values = json.loads(data.decode("ascii"))
                canonical = json.dumps(values, separators=(",", ":")).encode("ascii")
                if (data != canonical or type(values) is not list
                        or not 1 <= len(values) <= self._MAX_KEYS
                        or any(type(value) is not str or self._HEX_KEY.fullmatch(value) is None
                               for value in values)):
                    raise ValueError()
                keys = tuple(bytes.fromhex(value) for value in values)
            else:
                key = bytes.fromhex(data.decode("ascii").strip())
                if len(key) != 32:
                    raise ValueError()
                keys = (key,)
            if len(set(keys)) != len(keys) or any(len(key) != 32 for key in keys):
                raise ValueError()
            return data, keys
        except Exception:
            raise IdentityError("identity_key_unavailable") from None

    def _assert_key_current(self):
        try:
            data = _identity_read_private_regular(
                self.key_file, limit=self._MAX_KEY_FILE_BYTES)
        except Exception:
            raise IdentityError("identity_store_path_unsafe") from None
        if data != self._key_file_bytes:
            raise IdentityError("identity_store_key_changed")

    @staticmethod
    def _strict_json(data):
        def strict_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result

        def reject_constant(value):
            raise ValueError()

        return json.loads(data, object_pairs_hook=strict_object, parse_constant=reject_constant)

    @classmethod
    def _validate_body(cls, body):
        if (type(body) is not dict
                or body.get("schema") != "enkstein-guard-identities-v1"
                or type(body.get("agent")) is not dict
                or type(body.get("approver")) is not dict
                or type(body.get("serial")) is not int
                or body["serial"] < 0):
            raise ValueError()
        for kind in KINDS:
            for name, record in body[kind].items():
                if (type(name) is not str or _ID.fullmatch(name) is None
                        or type(record) is not dict
                        or not {"digest", "generation", "issued_at", "revoked_at"}.issubset(record)
                        or type(record["digest"]) is not str
                        or cls._HEX_DIGEST.fullmatch(record["digest"]) is None
                        or type(record["generation"]) is not int or record["generation"] < 1
                        or type(record["issued_at"]) is not int or record["issued_at"] < 0
                        or (record["revoked_at"] is not None
                            and (type(record["revoked_at"]) is not int
                                 or record["revoked_at"] < 0))):
                    raise ValueError()

    def _mac(self, body, key=None):
        serialized = json.dumps(
            body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(key or self._keys[0], serialized, hashlib.sha256).hexdigest()

    def _read(self):
        try:
            data = self._strict_json(_identity_read_private_regular(self.path))
            if type(data) is not dict or set(data) != {"body", "mac"}:
                raise ValueError()
            body, mac = data["body"], data["mac"]
            self._validate_body(body)
            if (type(mac) is not str or self._HEX_DIGEST.fullmatch(mac) is None
                    or not any(hmac.compare_digest(mac, self._mac(body, key))
                               for key in self._keys)):
                raise ValueError()
            return body
        except Exception:
            raise IdentityError("identity_store_integrity_failed") from None

    def _write_authenticated_body(self, body):
        self._validate_body(body)
        envelope = json.dumps(
            {"body": body, "mac": self._mac(body)},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        _identity_atomic_private_write(self.path, envelope)

    def _write(self, body):
        body["serial"] = body.get("serial", 0) + 1
        self._write_authenticated_body(body)

    @contextmanager
    def _file_locked(self, *, nonblocking=False):
        if os.path.abspath(self.key_file) == os.path.abspath(self._lock_path):
            raise IdentityError("identity_store_lock_unavailable")
        descriptor = None
        locked = False
        try:
            _check_private(self._lock_path.parent, directory=True)
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            information = os.fstat(descriptor)
            if (not stat.S_ISREG(information.st_mode)
                    or (os.name == "posix" and (information.st_uid != os.getuid()
                                                 or information.st_mode & 0o077))):
                raise OSError("unsafe identity lock")
            flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
            try:
                fcntl.flock(descriptor, flags)
                locked = True
            except BlockingIOError:
                raise IdentityError("identity_key_rotation_busy") from None
        except IdentityError:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        except Exception:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise IdentityError("identity_store_lock_unavailable") from None
        try:
            yield
        except BaseException:
            try:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        else:
            cleanup_failed = False
            try:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                cleanup_failed = True
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    cleanup_failed = True
            if cleanup_failed:
                raise IdentityError("identity_store_lock_unavailable")

    @contextmanager
    def _locked(self):
        with self._object_lock:
            with self._file_locked():
                self._assert_key_current()
                body = self._read()
                yield body
                self._write(body)

    def issue(self, kind, name, output):
        """Create or rotate a credential; the old one stops working on reload."""
        with self._object_lock:
            if kind not in KINDS or not isinstance(name, str) or not _ID.fullmatch(name):
                raise IdentityError("invalid_identity")
            credential = new_credential(kind)
            written = write_secret_file(output, credential)
            try:
                with self._locked() as body:
                    previous = body[kind].get(name, {})
                    body[kind][name] = {"digest": hashlib.sha256(credential.encode()).hexdigest(),
                                        "generation": previous.get("generation", 0) + 1,
                                        "issued_at": int(time.time()), "revoked_at": None}
                    generation = body[kind][name]["generation"]
            except Exception:
                Path(written).unlink(missing_ok=True)
                raise
            return {"kind": kind, "id": name, "generation": generation,
                    "credential_file": written}

    def revoke(self, kind, name):
        with self._object_lock:
            if kind not in KINDS:
                raise IdentityError("invalid_identity")
            with self._locked() as body:
                record = body[kind].get(name)
                if record is None:
                    raise IdentityError("unknown_identity")
                already = record["revoked_at"] is not None
                record["revoked_at"] = record["revoked_at"] or int(time.time())
            return {"kind": kind, "id": name, "revoked": True,
                    "already_revoked": already}

    def digests(self, kind):
        """Active credential digests (bytes) by identity name."""
        with self._object_lock:
            self._assert_key_current()
            body = self._read()
            return {name: bytes.fromhex(record["digest"]) for name, record in body[kind].items()
                    if record["revoked_at"] is None}

    def listing(self):
        with self._object_lock:
            self._assert_key_current()
            body = self._read()
            return {kind: {name: {"generation": record["generation"], "issued_at": record["issued_at"],
                                  "revoked": record["revoked_at"] is not None}
                           for name, record in sorted(body[kind].items())}
                    for kind in KINDS} | {"serial": body["serial"]}

    @property
    def serial(self):
        with self._object_lock:
            self._assert_key_current()
            return self._read()["serial"]

    def verify(self):
        """Authenticate and validate the complete store without exposing digests."""
        with self._object_lock:
            self._assert_key_current()
            body = self._read()
            return {"records": sum(len(body[kind]) for kind in KINDS), "serial": body["serial"]}

    def _publish_keyring(self, keys):
        data = json.dumps([key.hex() for key in keys], separators=(",", ":")).encode()
        _identity_atomic_private_write(self.key_file, data)
        self._key_file_bytes, self._keys = data, keys

    def rotate_key(self, *, resume=False):
        """Rotate the HMAC primary while retaining keys needed for recovery."""
        if type(resume) is not bool:
            raise IdentityError("identity_store_rotation_failed")
        if not self._rotation_guard.acquire(blocking=False):
            raise IdentityError("identity_key_rotation_busy")
        try:
            try:
                with self._object_lock:
                    with self._file_locked(nonblocking=True):
                        self._assert_key_current()
                        body = self._read()
                        records = sum(len(body[kind]) for kind in KINDS)
                        if not resume:
                            if len(self._keys) >= self._MAX_KEYS:
                                raise IdentityError("identity_keyring_full")
                            new_key = secrets.token_bytes(32)
                            while new_key in self._keys:
                                new_key = secrets.token_bytes(32)
                            self._publish_keyring((new_key, *self._keys))

                        # Reauthenticate the exact parsed body under the current
                        # primary. Rotation never advances its serial.
                        self._write_authenticated_body(body)
                        if self._read() != body:
                            raise IdentityError("identity_store_integrity_failed")
                        return {
                            "current_key_fingerprint": hashlib.sha256(self._keys[0]).hexdigest(),
                            "key_count": len(self._keys),
                            "records_reauthenticated": records,
                            "resumed": resume,
                        }
            except IdentityError as error:
                if str(error) in {
                    "identity_key_rotation_busy",
                    "identity_keyring_full",
                    "identity_store_key_changed",
                }:
                    raise
                raise IdentityError("identity_store_rotation_failed") from None
            except Exception:
                raise IdentityError("identity_store_rotation_failed") from None
        finally:
            self._rotation_guard.release()


class SecretStore:
    """Encrypted connector secrets bound to tenant, routes and destination."""

    _MAX_KEYS = 32
    _MAX_KEY_FILE_BYTES = 8192
    _IDENTITY = b"guard-secrets-v1"

    @classmethod
    def initialize(cls, database, key_file):
        database, key_file = Path(database), Path(key_file)
        if database.exists() or key_file.exists() or database == key_file:
            raise IdentityError("secret_store_exists")
        for parent in (database.parent, key_file.parent):
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _check_private(parent, directory=True)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        key = Fernet.generate_key()
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
            connection.execute("INSERT INTO identity VALUES (?)", (Fernet(key).encrypt(b"guard-secrets-v1"),))
            connection.execute("CREATE TABLE secrets (name TEXT PRIMARY KEY, record BLOB NOT NULL)")
            connection.commit()
        return cls(database, key_file)

    def __init__(self, database, key_file):
        self.database, self.key_file = Path(database), Path(key_file)
        self._refresh_keyring()
        with closing(self._connect()):
            pass

    def _check_paths(self):
        try:
            for item in (self.database, self.key_file):
                _check_private(item.parent, directory=True)
                _check_private(item)
        except Exception:
            raise IdentityError("secret_store_path_unsafe") from None

    def _read_keyring(self):
        """Load a legacy raw Fernet key or a strict ordered JSON keyring."""
        self._check_paths()
        try:
            data = self.key_file.read_bytes()
            if not data or len(data) > self._MAX_KEY_FILE_BYTES:
                raise ValueError()
            encoded = data.strip()
            if encoded.startswith(b"["):
                values = json.loads(encoded.decode("ascii"))
                if (type(values) is not list or not 1 <= len(values) <= self._MAX_KEYS
                        or any(type(value) is not str for value in values)
                        or len(set(values)) != len(values)):
                    raise ValueError()
                keys = tuple(value.encode("ascii") for value in values)
            else:
                keys = (encoded,)
            if len(set(keys)) != len(keys):
                raise ValueError()
            cipher = MultiFernet([Fernet(key) for key in keys])
            return data, keys, cipher
        except IdentityError:
            raise
        except Exception:
            raise IdentityError("secret_store_key_unavailable") from None

    def _refresh_keyring(self):
        data, keys, cipher = self._read_keyring()
        self._key_file_bytes = data
        self._key_file_fingerprint = hashlib.sha256(data).hexdigest()
        self._keys, self._cipher = keys, cipher

    def _assert_key_current(self):
        data, _, _ = self._read_keyring()
        if data != self._key_file_bytes:
            raise IdentityError("secret_store_key_changed")

    def _publish_keyring(self, keys):
        data = json.dumps([key.decode("ascii") for key in keys], separators=(",", ":")).encode()
        _atomic_private_write(self.key_file, data)
        descriptor = os.open(self.key_file.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._key_file_bytes = data
        self._key_file_fingerprint = hashlib.sha256(data).hexdigest()
        self._keys, self._cipher = keys, MultiFernet([Fernet(key) for key in keys])

    @contextmanager
    def _rotation_locked(self):
        lock = self.database.with_name(self.database.name + ".rotation.lock")
        fd = None
        try:
            fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            _check_private(lock)
        except Exception:
            if fd is not None:
                os.close(fd)
            raise IdentityError("secret_store_rotation_failed") from None
        locked = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except BlockingIOError:
                raise IdentityError("secret_store_rotation_busy") from None
            yield
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _connect(self):
        connection = None
        try:
            self._assert_key_current()
            connection = sqlite3.connect(self.database, timeout=5)
            connection.execute("PRAGMA synchronous=FULL")
            row = connection.execute("SELECT record FROM identity").fetchall()
            if len(row) != 1 or self._cipher.decrypt(row[0][0]) != self._IDENTITY:
                raise ValueError()
            return connection
        except IdentityError:
            if connection is not None:
                connection.close()
            raise
        except Exception:
            if connection is not None:
                connection.close()
            raise IdentityError("secret_store_integrity_failed") from None

    def _decode(self, name, encrypted):
        try:
            def strict_object(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError()
                    value[key] = item
                return value

            def reject_constant(value):
                raise ValueError()

            record = json.loads(self._cipher.decrypt(encrypted), object_pairs_hook=strict_object,
                                parse_constant=reject_constant)
            expected = {"name", "value", "tenant", "destination", "routes", "updated_at"}
            if (type(record) is not dict or set(record) != expected
                    or type(record["name"]) is not str or record["name"] != name
                    or not _ID.fullmatch(record["name"])
                    or type(record["value"]) is not str or not record["value"]
                    or type(record["tenant"]) is not str or not record["tenant"]
                    or type(record["destination"]) is not str or not record["destination"]
                    or type(record["routes"]) is not list or not record["routes"]
                    or any(type(route) is not str or not route for route in record["routes"])
                    or len(set(record["routes"])) != len(record["routes"])
                    or record["routes"] != sorted(record["routes"])
                    or type(record["updated_at"]) is not int or record["updated_at"] < 0):
                raise ValueError()
            return record
        except Exception:
            raise IdentityError("secret_store_integrity_failed") from None

    def set(self, name, value, *, tenant, destination, routes, replace=False):
        if not isinstance(name, str) or not _ID.fullmatch(name) or not isinstance(value, str) or not value:
            raise IdentityError("invalid_secret")
        if (type(tenant) is not str or not tenant or type(destination) is not str or not destination
                or type(routes) not in (list, tuple) or not routes
                or any(type(r) is not str or not r for r in routes)):
            raise IdentityError("invalid_secret_binding")
        record = {"name": name, "value": value, "tenant": tenant, "destination": destination,
                  "routes": sorted(set(routes)), "updated_at": int(time.time())}
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_key_current()
            exists = connection.execute("SELECT 1 FROM secrets WHERE name=?", (name,)).fetchone()
            if exists and not replace:
                raise IdentityError("secret_exists")
            connection.execute("INSERT INTO secrets VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET record=excluded.record",
                               (name, self._cipher.encrypt(json.dumps(record).encode())))
            connection.commit()
        return {"name": name, "tenant": tenant, "destination": destination, "routes": record["routes"],
                "replaced": bool(exists)}

    def remove(self, name):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_key_current()
            removed = connection.execute("DELETE FROM secrets WHERE name=?", (name,)).rowcount
            connection.commit()
        return bool(removed)

    def _validate_records(self, connection):
        identity = connection.execute("SELECT record FROM identity").fetchall()
        if len(identity) != 1 or self._cipher.decrypt(identity[0][0]) != self._IDENTITY:
            raise IdentityError("secret_store_integrity_failed")
        rows = connection.execute("SELECT name, record FROM secrets ORDER BY name").fetchall()
        for name, record in rows:
            self._decode(name, record)
        return identity[0][0], rows

    def rotate_key(self, *, resume=False):
        """Rotate offline, retaining old decrypt keys for restart and resume."""
        if type(resume) is not bool:
            raise IdentityError("secret_store_rotation_failed")
        connection = None
        try:
            with self._rotation_locked():
                try:
                    # Rotation alone may refresh a stale in-memory handle, and
                    # only after winning the stable administrative lock.
                    self._refresh_keyring()
                    connection = self._connect()
                    connection.execute("BEGIN IMMEDIATE")
                    self._assert_key_current()
                    identity, rows = self._validate_records(connection)
                    if not resume:
                        if len(self._keys) >= self._MAX_KEYS:
                            raise IdentityError("secret_store_keyring_full")
                        new_key = Fernet.generate_key()
                        while new_key in self._keys:
                            new_key = Fernet.generate_key()
                        keys = (new_key, *self._keys)
                    else:
                        keys = self._keys

                    # Publish every retained decrypt key before any ciphertext
                    # is rewritten. A rollback remains reopenable.
                    self._publish_keyring(keys)
                    connection.execute("UPDATE identity SET record=?", (self._cipher.rotate(identity),))
                    for name, record in rows:
                        connection.execute("UPDATE secrets SET record=? WHERE name=?",
                                           (self._cipher.rotate(record), name))
                    connection.commit()
                    connection.close()
                    connection = None
                    return {"current_key_fingerprint": hashlib.sha256(self._keys[0]).hexdigest(),
                            "key_count": len(self._keys), "records_reencrypted": len(rows),
                            "resumed": resume}
                finally:
                    # Release the SQLite writer before the administrative lock.
                    if connection is not None:
                        connection.rollback()
                        connection.close()
                        connection = None
        except IdentityError as error:
            if str(error) in {"secret_store_rotation_busy", "secret_store_keyring_full"}:
                raise
            raise IdentityError("secret_store_rotation_failed") from None
        except Exception:
            raise IdentityError("secret_store_rotation_failed") from None

    def listing(self):
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT name, record FROM secrets ORDER BY name").fetchall()
        return [{key: value for key, value in self._decode(name, record).items() if key != "value"}
                for name, record in rows]

    def _values(self):
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT name, record FROM secrets ORDER BY name").fetchall()
        return [self._decode(name, record) for name, record in rows]

    def other_tenants_with_value(self, value, tenant):
        """Tenants other than ``tenant`` holding a secret with this exact value.

        A provider account shared by tenants shares any provider-side state, so
        production refuses it. Values are compared in memory and never returned.
        """
        return sorted({record["tenant"] for record in self._values()
                       if record["tenant"] != tenant and hmac.compare_digest(record["value"], value)})

    def shared_value_groups(self):
        """Count of distinct secret values bound to more than one tenant."""
        tenants = {}
        for record in self._values():
            tenants.setdefault(hashlib.sha256(record["value"].encode()).digest(), set()).add(record["tenant"])
        return sum(len(group) > 1 for group in tenants.values())

    def resolve(self, name, *, tenant, route, destination):
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT record FROM secrets WHERE name=?", (name,)).fetchone()
        if row is None:
            raise IdentityError("credential_forbidden")
        record = self._decode(name, row[0])
        if record["tenant"] != tenant or record["destination"] != destination or route not in record["routes"]:
            raise IdentityError("credential_forbidden")
        return record["value"]


class SecretBroker:
    """CredentialBroker-compatible ``invoke`` over SecretStore for connectors."""

    def __init__(self, store: SecretStore):
        self._store = store

    async def invoke(self, name, operation, connector):
        import inspect
        from .runtime import AccessDenied, RejectedBeforeDispatch, UnavailableBeforeDispatch
        if not inspect.iscoroutinefunction(connector):
            raise RejectedBeforeDispatch("credential_forbidden")
        try:
            credential = self._store.resolve(name, tenant=operation.context.tenant_id, route=operation.route,
                                             destination=operation.destination)
        except IdentityError:
            raise RejectedBeforeDispatch("credential_forbidden") from None
        try:
            return await connector(credential, operation.payload())
        except (AccessDenied, UnavailableBeforeDispatch):
            raise
        except Exception:
            raise AccessDenied("connector_failed_outcome_unknown") from None
