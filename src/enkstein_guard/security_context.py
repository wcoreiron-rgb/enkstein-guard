"""Encrypted, actor-isolated history for contextual AI security decisions."""
from __future__ import annotations

import base64
from collections import OrderedDict
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .contracts import Action, SecurityContext
from .runtime import Operation
from .security_assessment import SecurityAssessment, parse_assessment
from .vault import _check_private


IDENTITY = "enkstein-guard-security-history-v1"
MAX_RECORD_BYTES = 16_384
_ACTIONS = frozenset({Action.ALLOW, Action.DENY, Action.REQUIRE_APPROVAL})
_STORAGE_ERRORS = (OSError, sqlite3.Error)
MAX_HISTORY_KEYS = 32
MAX_KEY_FILE_BYTES = 8192
_HISTORY_CACHE_MAX_ENTRIES = 4096
_HISTORY_CACHE_MAX_BYTES = 8 * 1024 * 1024
_HISTORY_CACHE_ENTRY_OVERHEAD = 256


class SecurityHistoryError(Exception):
    """Fixed fail-closed history-store error."""


def _keyring(data):
    """Load a legacy raw Fernet key or a strict ordered JSON keyring."""
    try:
        if not data or len(data) > MAX_KEY_FILE_BYTES:
            raise ValueError()
        encoded = data.strip()
        if encoded.startswith(b"["):
            values = json.loads(encoded.decode("ascii"))
            if (type(values) is not list or not 1 <= len(values) <= MAX_HISTORY_KEYS
                    or any(type(value) is not str for value in values)
                    or len(set(values)) != len(values)):
                raise ValueError()
            keys = tuple(value.encode("ascii") for value in values)
        else:
            # The original history selector HMAC used the exact raw key-file
            # bytes. Preserve legacy trailing whitespace rather than silently
            # normalizing it even though Fernet itself accepts that whitespace.
            keys = (data,)
        if len(set(keys)) != len(keys):
            raise ValueError()
        ciphers = tuple(Fernet(key) for key in keys)
        decoded_keys = tuple(base64.urlsafe_b64decode(key) for key in keys)
        if len(set(decoded_keys)) != len(decoded_keys):
            raise ValueError()
        return keys, ciphers, MultiFernet(ciphers)
    except Exception:
        raise SecurityHistoryError("security_history_key_unavailable") from None


def _atomic_private_write(path, data):
    """Durably replace a private key file and its containing directory."""
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


@dataclass(frozen=True)
class HistoryRecord:
    created: float
    tenant_id: str
    principal_id: str
    agent_id: str
    workflow_id: str
    operation_id: str
    policy_version: str
    route: str
    action_digest: str
    decision: str
    risk: str
    confidence: int | float
    signals: tuple[str, ...]
    action: str


@dataclass(frozen=True)
class _HistoryCacheEntry:
    key_epoch: bytes
    row: tuple
    decoded: tuple[int, float, HistoryRecord]
    accounted_bytes: int


def _assessment_dict(assessment):
    if type(assessment) is not SecurityAssessment:
        raise SecurityHistoryError("security_history_invalid_record")
    # Reparse even a constructed dataclass so this boundary owns validation.
    parsed = parse_assessment({
        "schema_version": assessment.schema_version,
        "action_digest": assessment.action_digest,
        "decision": assessment.decision,
        "risk": assessment.risk,
        "confidence": assessment.confidence,
        "signals": list(assessment.signals),
    }, action_digest=assessment.action_digest)
    return parsed, {
        "action_digest": parsed.action_digest,
        "decision": parsed.decision,
        "risk": parsed.risk,
        "confidence": parsed.confidence,
        "signals": list(parsed.signals),
    }


class SecurityHistoryStore:
    """Encrypted local history bounded globally, per tenant, and per actor."""

    @classmethod
    def initialize(cls, database, key_file, *, capacity=10_000,
                   ttl_seconds=3600, per_actor_capacity=64, clock=time.time):
        database, key_file = Path(database), Path(key_file)
        cls._validate_options(capacity, ttl_seconds, per_actor_capacity, clock)
        if database == key_file or database.exists() or key_file.exists():
            raise SecurityHistoryError("security_history_paths_already_exist")
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
            identity = cls._identity_record(capacity, ttl_seconds, per_actor_capacity)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
                connection.execute("INSERT INTO identity VALUES (?)",
                                   (Fernet(key).encrypt(cls._encode(identity)),))
                connection.execute(
                    "CREATE TABLE history ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, actor BLOB NOT NULL, tenant BLOB NOT NULL, "
                    "created REAL NOT NULL, expires REAL NOT NULL, record BLOB NOT NULL)")
                connection.execute("CREATE INDEX history_actor ON history(actor, created DESC)")
                connection.execute("CREATE INDEX history_expiry ON history(expires)")
                connection.commit()
        except SecurityHistoryError:
            raise
        except Exception:
            raise SecurityHistoryError("security_history_initialization_failed") from None
        return cls(database, key_file, capacity=capacity,
                   ttl_seconds=ttl_seconds, per_actor_capacity=per_actor_capacity,
                   clock=clock)

    def __init__(self, database, key_file, *, capacity=10_000,
                 ttl_seconds=3600, per_actor_capacity=64, clock=time.time):
        self._validate_options(capacity, ttl_seconds, per_actor_capacity, clock)
        self.database, self.key_file = Path(database), Path(key_file)
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self.per_actor_capacity = per_actor_capacity
        self._clock = clock
        self._operation_lock = threading.RLock()
        self._rotation_guard = threading.Lock()
        self._history_cache = OrderedDict()
        self._history_cache_bytes = 0
        self._history_cache_key_epoch = None
        try:
            self._check_paths()
            self._key_bytes = self.key_file.read_bytes()
            self._keys, self._ciphers, self._cipher = _keyring(self._key_bytes)
            self._history_cache_key_epoch = self._key_bytes
            self.verify()
        except SecurityHistoryError:
            raise
        except Exception:
            raise SecurityHistoryError("security_history_unreadable") from None

    @staticmethod
    def _validate_options(capacity, ttl_seconds, per_actor_capacity, clock):
        if (type(capacity) is not int or not 1 <= capacity <= 100_000
                or type(ttl_seconds) not in (int, float)
                or not math.isfinite(ttl_seconds) or not 0 < ttl_seconds <= 86_400
                or type(per_actor_capacity) is not int
                or not 16 <= per_actor_capacity <= capacity
                or not callable(clock)):
            raise ValueError("invalid_security_history_options")

    @staticmethod
    def _identity_record(capacity, ttl_seconds, per_actor_capacity):
        return {"identity": IDENTITY, "capacity": capacity,
                "ttl_seconds": ttl_seconds,
                "per_actor_capacity": per_actor_capacity}

    @staticmethod
    def _encode(value):
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()
        if len(encoded) > MAX_RECORD_BYTES:
            raise SecurityHistoryError("security_history_record_too_large")
        return encoded

    def _now(self):
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now <= 0:
            raise SecurityHistoryError("security_history_clock_invalid")
        return now

    def _check_paths(self):
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)
        if hasattr(self, "_key_bytes") and self.key_file.read_bytes() != self._key_bytes:
            self._clear_history_cache()
            raise SecurityHistoryError("security_history_key_changed")

    def _clear_history_cache(self, *, key_epoch=None):
        self._history_cache.clear()
        self._history_cache_bytes = 0
        if key_epoch is not None:
            self._history_cache_key_epoch = key_epoch

    def _drop_history_cache_id(self, identifier):
        cached = self._history_cache.pop(identifier, None)
        if cached is not None:
            self._history_cache_bytes -= cached.accounted_bytes

    @staticmethod
    def _history_cache_entry_bytes(row, decoded):
        _, actor, tenant, _, _, encrypted = row
        record = decoded[2]
        strings = (
            record.tenant_id,
            record.principal_id,
            record.agent_id,
            record.workflow_id,
            record.operation_id,
            record.policy_version,
            record.route,
            record.action_digest,
            record.decision,
            record.risk,
            record.action,
            *record.signals,
        )
        return (
            _HISTORY_CACHE_ENTRY_OVERHEAD
            + len(actor)
            + len(tenant)
            + len(encrypted)
            + sum(len(value.encode("utf-8", "surrogatepass")) for value in strings)
        )

    def _cache_decoded_record(self, row, decoded):
        identifier = row[0]
        self._drop_history_cache_id(identifier)
        accounted_bytes = self._history_cache_entry_bytes(row, decoded)
        if accounted_bytes > _HISTORY_CACHE_MAX_BYTES:
            return
        cached = _HistoryCacheEntry(
            self._key_bytes, row, decoded, accounted_bytes,
        )
        self._history_cache[identifier] = cached
        self._history_cache_bytes += accounted_bytes
        while (len(self._history_cache) > _HISTORY_CACHE_MAX_ENTRIES
               or self._history_cache_bytes > _HISTORY_CACHE_MAX_BYTES):
            _, evicted = self._history_cache.popitem(last=False)
            self._history_cache_bytes -= evicted.accounted_bytes

    def _cached_decode_record(self, row):
        identifier = row[0]
        cached = self._history_cache.get(identifier)
        if (cached is not None
                and cached.key_epoch == self._key_bytes
                and cached.row == row):
            self._history_cache.move_to_end(identifier)
            return cached.decoded
        self._drop_history_cache_id(identifier)
        decoded = self._decode_record(row)
        self._cache_decoded_record(row, decoded)
        return decoded

    @property
    def _rotation_lock_path(self):
        return self.key_file.with_name(self.key_file.name + ".rotation.lock")

    @contextmanager
    def _rotation_lock(self):
        """Acquire the stable per-store nonblocking administrative lock."""
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
                raise SecurityHistoryError("security_history_key_rotation_lock_unavailable")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SecurityHistoryError("security_history_key_rotation_busy") from None
        except SecurityHistoryError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise SecurityHistoryError("security_history_key_rotation_lock_unavailable") from None
        try:
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)

    def _connect(self):
        try:
            self._check_paths()
            connection = sqlite3.connect(self.database, timeout=5)
            connection.execute("PRAGMA synchronous=FULL")
            sizes = connection.execute("SELECT length(record) FROM identity").fetchall()
            if len(sizes) != 1 or sizes[0][0] is None or sizes[0][0] > MAX_RECORD_BYTES * 2:
                raise SecurityHistoryError("security_history_integrity_failed")
            rows = connection.execute("SELECT record FROM identity").fetchall()
            if len(rows) != 1:
                raise SecurityHistoryError("security_history_integrity_failed")
            identity = self._decrypt(rows[0][0])
            if identity != self._identity_record(
                    self.capacity, self.ttl_seconds, self.per_actor_capacity):
                raise SecurityHistoryError("security_history_configuration_mismatch")
            return connection
        except SecurityHistoryError as error:
            if "connection" in locals():
                connection.close()
            if str(error) == "security_history_integrity_failed":
                self._clear_history_cache()
            raise
        except _STORAGE_ERRORS:
            if "connection" in locals():
                connection.close()
            raise SecurityHistoryError("security_history_storage_unavailable") from None
        except Exception:
            if "connection" in locals():
                connection.close()
            self._clear_history_cache()
            raise SecurityHistoryError("security_history_integrity_failed") from None

    def _decrypt_with_key(self, encrypted):
        try:
            if not isinstance(encrypted, bytes) or len(encrypted) > MAX_RECORD_BYTES * 2:
                raise ValueError()
            plaintext = None
            decrypt_key = None
            for key, cipher in zip(self._keys, self._ciphers):
                try:
                    plaintext = cipher.decrypt(encrypted)
                    decrypt_key = key
                    break
                except InvalidToken:
                    continue
            if plaintext is None:
                raise ValueError()
            if len(plaintext) > MAX_RECORD_BYTES:
                raise ValueError()
            value = json.loads(plaintext)
            self._encode(value)
            if type(value) is not dict:
                raise ValueError()
            return value, decrypt_key
        except SecurityHistoryError:
            raise
        except Exception:
            raise SecurityHistoryError("security_history_integrity_failed") from None

    def _decrypt(self, encrypted):
        return self._decrypt_with_key(encrypted)[0]

    @staticmethod
    def _digest_with_key(key, *parts):
        encoded = json.dumps(parts, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(key, encoded, hashlib.sha256).digest()

    def _digest(self, *parts):
        return self._digest_with_key(self._keys[0], *parts)

    @staticmethod
    def _operation(operation):
        if type(operation) is not Operation or type(operation.context) is not SecurityContext:
            raise SecurityHistoryError("security_history_invalid_operation")
        return operation.context

    def _actor(self, operation):
        context = self._operation(operation)
        return self._digest(context.tenant_id, context.principal_id, context.agent_id)

    def _tenant(self, operation):
        return self._digest(self._operation(operation).tenant_id)

    def _decode_record(self, row):
        identifier, actor, tenant, created, expires, encrypted = row
        try:
            value, decrypt_key = self._decrypt_with_key(encrypted)
            expected = {"created", "tenant_id", "principal_id", "agent_id", "workflow_id",
                        "operation_id", "policy_version", "route", "action_digest", "decision",
                        "risk", "confidence", "signals", "action"}
            if (set(value) != expected or type(created) not in (int, float)
                    or type(expires) not in (int, float) or value["created"] != created
                    or expires != created + self.ttl_seconds):
                raise ValueError()
            context = SecurityContext(value["tenant_id"], value["principal_id"], value["agent_id"],
                                      value["workflow_id"], value["operation_id"],
                                      value["route"], value["policy_version"])
            assessment = parse_assessment({
                "schema_version": 1,
                "action_digest": value["action_digest"],
                "decision": value["decision"],
                "risk": value["risk"],
                "confidence": value["confidence"],
                "signals": value["signals"],
            }, action_digest=value["action_digest"])
            action = Action(value["action"])
            if (action not in _ACTIONS
                    or not hmac.compare_digest(actor, self._digest_with_key(
                        decrypt_key,
                        context.tenant_id, context.principal_id, context.agent_id))
                    or not hmac.compare_digest(tenant, self._digest_with_key(
                        decrypt_key, context.tenant_id))):
                raise ValueError()
            return identifier, expires, HistoryRecord(
                created, context.tenant_id, context.principal_id, context.agent_id,
                context.workflow_id, context.operation_id, context.policy_version,
                value["route"], assessment.action_digest, assessment.decision,
                assessment.risk, assessment.confidence, assessment.signals, action.value)
        except SecurityHistoryError:
            raise
        except Exception:
            raise SecurityHistoryError("security_history_integrity_failed") from None

    def _records(self, connection):
        try:
            if self._history_cache_key_epoch != self._key_bytes:
                self._clear_history_cache(key_epoch=self._key_bytes)
            metadata = connection.execute(
                "SELECT COUNT(*), MAX(CASE WHEN "
                "length(actor) IS NULL OR length(actor) != 32 OR "
                "length(tenant) IS NULL OR length(tenant) != 32 OR "
                "length(record) IS NULL OR length(record) > ? "
                "THEN 1 ELSE 0 END) FROM history",
                (MAX_RECORD_BYTES * 2,),
            ).fetchone()
            if (type(metadata) is not tuple or len(metadata) != 2
                    or type(metadata[0]) is not int or metadata[0] < 0
                    or metadata[0] > self.capacity
                    or (metadata[0] == 0 and metadata[1] is not None)
                    or (metadata[0] > 0
                        and (type(metadata[1]) is not int or metadata[1] != 0))):
                raise SecurityHistoryError("security_history_integrity_failed")
            rows = connection.execute(
                "SELECT id, actor, tenant, created, expires, record FROM history").fetchall()
            present = {row[0] for row in rows}
            for identifier in tuple(self._history_cache):
                if identifier not in present:
                    self._drop_history_cache_id(identifier)
            records = [self._cached_decode_record(tuple(row)) for row in rows]
            counts = {}
            for _, _, record in records:
                actor = (record.tenant_id, record.principal_id, record.agent_id)
                counts[actor] = counts.get(actor, 0) + 1
            if any(count > self.per_actor_capacity for count in counts.values()):
                raise SecurityHistoryError("security_history_integrity_failed")
            return records
        except SecurityHistoryError:
            self._clear_history_cache()
            raise
        except Exception:
            self._clear_history_cache()
            raise

    def _purge(self, connection, records, now):
        expired = [identifier for identifier, expires, _ in records if expires <= now]
        connection.executemany("DELETE FROM history WHERE id=?", ((item,) for item in expired))
        for identifier in expired:
            self._drop_history_cache_id(identifier)
        expired = set(expired)
        return [item for item in records if item[0] not in expired]

    def verify(self):
        with self._operation_lock:
            try:
                now = self._now()
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._check_paths()
                    records = self._purge(connection, self._records(connection), now)
                    connection.commit()
                return {"status": "verified", "records": len(records)}
            except SecurityHistoryError:
                raise
            except _STORAGE_ERRORS:
                raise SecurityHistoryError("security_history_storage_unavailable") from None
            except Exception:
                raise SecurityHistoryError("security_history_integrity_failed") from None

    def recent(self, operation, limit=16):
        if type(limit) is not int or not 1 <= limit <= 64:
            raise SecurityHistoryError("security_history_invalid_limit")
        with self._operation_lock:
            actor = self._actor(operation)
            context = operation.context
            try:
                now = self._now()
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._check_paths()
                    records = self._purge(connection, self._records(connection), now)
                    connection.commit()
                items = [record for _, _, record in records
                         if (record.tenant_id, record.principal_id, record.agent_id)
                         == (context.tenant_id, context.principal_id, context.agent_id)]
                # Recheck the HMAC-derived selector even though encrypted records
                # were validated above; callers cannot supply an actor assertion.
                if actor != self._actor(operation):
                    raise SecurityHistoryError("security_history_actor_mismatch")
                return tuple(sorted(items, key=lambda item: item.created, reverse=True)[:limit])
            except SecurityHistoryError:
                raise
            except _STORAGE_ERRORS:
                raise SecurityHistoryError("security_history_storage_unavailable") from None
            except Exception:
                raise SecurityHistoryError("security_history_integrity_failed") from None

    def record(self, operation, assessment, action):
        context = self._operation(operation)
        if not isinstance(action, Action) or action not in _ACTIONS:
            raise SecurityHistoryError("security_history_invalid_action")
        _, metadata = _assessment_dict(assessment)
        now = self._now()
        value = {
            "created": now,
            "tenant_id": context.tenant_id,
            "principal_id": context.principal_id,
            "agent_id": context.agent_id,
            "workflow_id": context.workflow_id,
            "operation_id": context.operation_id,
            "policy_version": context.policy_version,
            "route": operation.route,
            **metadata,
            "action": action.value,
        }
        with self._operation_lock:
            try:
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    # A writer may have waited behind an external rotator. Do
                    # not publish selectors or ciphertext computed with stale
                    # in-memory key material after winning the SQLite lock.
                    self._check_paths()
                    records = self._purge(connection, self._records(connection), now)
                    actor, tenant = self._actor(operation), self._tenant(operation)
                    encrypted = self._cipher.encrypt(self._encode(value))
                    actor_records = sorted(
                        (item for item in records
                         if (item[2].tenant_id, item[2].principal_id, item[2].agent_id)
                         == (context.tenant_id, context.principal_id, context.agent_id)),
                        key=lambda item: item[2].created)
                    if len(actor_records) >= self.per_actor_capacity:
                        remove = actor_records[:len(actor_records) - self.per_actor_capacity + 1]
                        connection.executemany(
                            "DELETE FROM history WHERE id=?", ((item[0],) for item in remove))
                        removed = {item[0] for item in remove}
                        for identifier in removed:
                            self._drop_history_cache_id(identifier)
                        records = [item for item in records if item[0] not in removed]
                    # A noisy actor rolls only its own ring. A new actor cannot
                    # evict another actor's still-live context from a full store.
                    if len(records) >= self.capacity:
                        raise SecurityHistoryError("security_history_capacity_reached")
                    connection.execute(
                        "INSERT INTO history(actor,tenant,created,expires,record) VALUES (?,?,?,?,?)",
                        (actor, tenant, now, now + self.ttl_seconds, encrypted))
                    connection.commit()
            except SecurityHistoryError:
                raise
            except _STORAGE_ERRORS:
                raise SecurityHistoryError("security_history_storage_unavailable") from None
            except Exception:
                raise SecurityHistoryError("security_history_integrity_failed") from None

    def rotate_key(self, *, resume=False):
        """Rekey every history row offline while retaining old decrypt keys."""
        if type(resume) is not bool:
            raise SecurityHistoryError("security_history_key_rotation_invalid_resume")
        if not self._rotation_guard.acquire(blocking=False):
            raise SecurityHistoryError("security_history_key_rotation_busy")
        connection = None
        try:
            with self._rotation_lock(), self._operation_lock:
                try:
                    self._check_paths()
                    current_bytes = self.key_file.read_bytes()
                    current_keys, current_ciphers, current_cipher = _keyring(current_bytes)
                    if current_bytes != self._key_bytes:
                        raise SecurityHistoryError("security_history_key_changed")
                    if not resume and len(current_keys) >= MAX_HISTORY_KEYS:
                        raise SecurityHistoryError("security_history_keyring_full")

                    connection = sqlite3.connect(self.database, timeout=0)
                    connection.execute("PRAGMA synchronous=FULL")
                    connection.execute("BEGIN IMMEDIATE")
                    # Authenticate the exact file bytes again after acquiring the
                    # database writer. Every identity and history row is validated
                    # before the recoverable keyring is published.
                    self._check_paths()
                    self._keys = current_keys
                    self._ciphers = current_ciphers
                    self._cipher = current_cipher
                    identity_rows = connection.execute("SELECT record FROM identity").fetchall()
                    if len(identity_rows) != 1:
                        raise SecurityHistoryError("security_history_integrity_failed")
                    identity = self._decrypt(identity_rows[0][0])
                    if identity != self._identity_record(
                            self.capacity, self.ttl_seconds, self.per_actor_capacity):
                        raise SecurityHistoryError("security_history_configuration_mismatch")
                    records = self._records(connection)
                    encrypted_rows = dict(connection.execute(
                        "SELECT id,record FROM history").fetchall())

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
                        self._key_bytes = data
                        self._keys, self._ciphers, self._cipher = _keyring(data)
                        self._clear_history_cache(key_epoch=data)

                    connection.execute(
                        "UPDATE identity SET record=?",
                        (self._cipher.encrypt(self._encode(identity)),),
                    )
                    for identifier, _, record in records:
                        connection.execute(
                            "UPDATE history SET actor=?,tenant=?,record=? WHERE id=?",
                            (
                                self._digest(
                                    record.tenant_id, record.principal_id, record.agent_id),
                                self._digest(record.tenant_id),
                                self._cipher.rotate(encrypted_rows[identifier]),
                                identifier,
                            ),
                        )
                    connection.commit()
                    connection.close()
                    connection = None
                    self._clear_history_cache(key_epoch=self._key_bytes)

                    return {
                        "current_key_fingerprint": hashlib.sha256(self._keys[0]).hexdigest(),
                        "key_count": len(self._keys),
                        "records_reencrypted": len(records),
                        "resumed": resume,
                    }
                except Exception:
                    self._clear_history_cache()
                    raise
                finally:
                    # Release the SQLite writer while both the stable
                    # administrative lock and same-object lock are still held.
                    # Cleanup errors never replace a known primary failure.
                    if connection is not None:
                        try:
                            connection.rollback()
                        except Exception:
                            pass
                        try:
                            connection.close()
                        except Exception:
                            pass
                        connection = None
        except SecurityHistoryError as error:
            if str(error) in {
                "security_history_key_changed",
                "security_history_key_rotation_busy",
                "security_history_key_rotation_lock_unavailable",
                "security_history_keyring_full",
            }:
                raise
            raise SecurityHistoryError("security_history_key_rotation_failed") from None
        except Exception:
            raise SecurityHistoryError("security_history_key_rotation_failed") from None
        finally:
            self._rotation_guard.release()
