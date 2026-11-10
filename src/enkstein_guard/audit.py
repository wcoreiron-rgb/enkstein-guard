"""Encrypted durable audit callback for trusted local application hosts.

The chain detects edits, insertion and interior deletion. Detecting rollback or
suffix deletion requires retaining verify()'s checkpoint outside this host.

Appends verify the stored head, row count and any rows added by another writer
(O(1) for a single writer). Full chain verification runs at open, every
``full_verify_every`` appends and on demand. Archival moves a verified prefix
into an encrypted segment file and records the segment digest and chain base,
so retention bounds append and verification cost without breaking continuity.
"""
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from cryptography.fernet import Fernet, MultiFernet
from .vault import _check_private


GENESIS = "0" * 64
ARCHIVE_FORMAT = "enkstein-guard-audit-archive-v1"
MAX_AUDIT_KEYS = 32
# Exported events keep only these trusted metadata fields. Runtime events never
# carry payloads; the allowlist also protects against careless custom events.
EXPORT_FIELDS = frozenset({
    "event", "outcome", "operation_id", "diagnostic_id", "tenant_id", "principal_id", "agent_id",
    "route", "operation", "policy_version", "action_digest", "decision", "reason_codes", "controls",
    "workflow_id", "parent_agent_id", "labels", "uid", "status", "level", "previous_level",
    "ticket_digest", "approver_id", "count", "returned", "withheld", "profile", "version",
    "destination", "port", "reason", "cutoff", "archived", "sequence_range", "generation",
    "store", "duration_ms",
})


class AuditError(Exception):
    pass


def _keyring(data):
    """Load a legacy raw Fernet key or an ordered JSON keyring."""
    try:
        encoded = data.strip()
        if encoded.startswith(b"["):
            values = json.loads(encoded)
            if (type(values) is not list or not 1 <= len(values) <= MAX_AUDIT_KEYS
                    or any(type(value) is not str for value in values)
                    or len(set(values)) != len(values)):
                raise ValueError()
            keys = tuple(value.encode("ascii") for value in values)
        else:
            keys = (encoded,)
        ciphers = [Fernet(key) for key in keys]
        return keys, MultiFernet(ciphers)
    except Exception:
        raise AuditError("audit_key_unavailable") from None


def _atomic_private_write(path, data):
    """Durably publish a private file; the previous file survives pre-replace failures."""
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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


def _scalar(value):
    return value is None or type(value) in (bool, int) or (type(value) is str and len(value) <= 512)


def _safe_value(value):
    if _scalar(value):
        return True
    if type(value) is list and len(value) <= 64:
        return all(_scalar(item) or (type(item) is dict and len(item) <= 8 and all(
            type(k) is str and _scalar(v) for k, v in item.items())) for item in value)
    return False


def safe_event(event):
    """Return (allowlisted event, number of dropped fields)."""
    kept, dropped = {}, 0
    for key, value in event.items():
        if key in EXPORT_FIELDS and _safe_value(value):
            kept[key] = value
        else:
            dropped += 1
    return kept, dropped


class DurableAudit:
    """Pass an instance as the synchronous runtime/orchestrator audit callback.

    Use trusted private parent directories. This is not protection against an
    administrator with the key, and is not a distributed audit service.
    """
    @classmethod
    def initialize(cls, database, key_file, **options):
        database, key_file = Path(database), Path(key_file)
        if database == key_file:
            raise AuditError("distinct_audit_paths_required")
        for parent in (database.parent, key_file.parent):
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _check_private(parent, directory=True)
        # Exclusive creation: never regenerate a key for an existing ledger.
        if database.exists() or key_file.exists():
            raise AuditError("audit_already_exists")
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(Fernet.generate_key())
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
            cipher = Fernet(key_file.read_bytes())
            connection.execute("INSERT INTO identity VALUES (?)", (cipher.encrypt(b"enkstein-guard-audit-v1"),))
            connection.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, record BLOB NOT NULL)")
            connection.commit()
        return cls(database, key_file, **options)

    def __init__(self, database, key_file, *, full_verify_every=1000):
        if type(full_verify_every) is not int or not 0 <= full_verify_every <= 10_000_000:
            raise AuditError("invalid_audit_verification_interval")
        self.database, self.key_file = Path(database), Path(key_file)
        self._check_paths()
        self._key_bytes = self.key_file.read_bytes()
        self._keys, self._cipher = _keyring(self._key_bytes)
        self._full_every = full_verify_every
        self._lock = threading.RLock()
        self._verified = None
        self._since_full = 0
        self.verify()

    # -- storage helpers -------------------------------------------------
    def _check_paths(self):
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)

        if hasattr(self, "_key_bytes") and self.key_file.read_bytes() != self._key_bytes:
            raise AuditError("audit_key_changed")

    @staticmethod
    def _has_meta(connection):
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone() is not None

    def _meta(self, connection, name, default):
        if not self._has_meta(connection):
            return default
        row = connection.execute("SELECT value FROM meta WHERE name=?", (name,)).fetchone()
        if row is None:
            return default
        record = json.loads(self._cipher.decrypt(row[0]))
        if type(record) is not dict or record.get("name") != name:
            raise AuditError("audit_metadata_failed")
        return record["value"]

    def _set_meta(self, connection, name, value):
        connection.execute("CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
        data = self._cipher.encrypt(json.dumps({"name": name, "value": value}, sort_keys=True).encode())
        connection.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                           (name, data))

    def _identity(self, connection):
        identities = connection.execute("SELECT record FROM identity").fetchall()
        if len(identities) != 1 or self._cipher.decrypt(identities[0][0]) != b"enkstein-guard-audit-v1":
            raise AuditError("audit_identity_failed")

    def _base(self, connection):
        base = self._meta(connection, "base", {"sequence": 0, "head": GENESIS})
        if (type(base) is not dict or type(base.get("sequence")) is not int or base["sequence"] < 0
                or type(base.get("head")) is not str or len(base["head"]) != 64):
            raise AuditError("audit_metadata_failed")
        return base

    def _chain(self, rows, sequence, previous):
        for row_sequence, encrypted in rows:
            record = json.loads(self._cipher.decrypt(encrypted))
            if row_sequence != sequence + 1 or record["sequence"] != row_sequence or record["previous"] != previous:
                raise AuditError("audit_integrity_failed")
            previous = hashlib.sha256(encrypted).hexdigest()
            sequence = row_sequence
        return sequence, previous

    def _records(self, connection):
        self._identity(connection)
        base = self._base(connection)
        rows = connection.execute("SELECT sequence, record FROM events ORDER BY sequence")
        sequence, head = self._chain(rows, base["sequence"], base["head"])
        return {"sequence": sequence, "head": head}

    def _state(self, connection):
        """Cheap pre-write check; falls back to verifying new suffix rows."""
        if self._verified is None or (self._full_every and self._since_full >= self._full_every):
            state = self._records(connection)
            self._since_full = 0
            return state
        self._identity(connection)
        base = self._base(connection)
        top = connection.execute("SELECT max(sequence) FROM events").fetchone()[0]
        top = base["sequence"] if top is None else top
        # Interior-deletion check (an O(n) count) runs every 64 appends and at
        # every full verification, bounding append cost on large ledgers.
        if self._since_full % 64 == 0:
            count = connection.execute("SELECT count(*) FROM events").fetchone()[0]
            if count != top - base["sequence"]:
                raise AuditError("audit_integrity_failed")
        cached = self._verified
        if top == cached["sequence"]:
            if top == base["sequence"]:
                if base["head"] != cached["head"]:
                    raise AuditError("audit_integrity_failed")
                return cached
            row = connection.execute("SELECT record FROM events WHERE sequence=?", (top,)).fetchone()
            if row is None or hashlib.sha256(row[0]).hexdigest() != cached["head"]:
                return self._records(connection)
            return cached
        if top < cached["sequence"]:
            # Rows disappeared without an archive base covering them.
            raise AuditError("audit_integrity_failed")
        if cached["sequence"] < base["sequence"]:
            # Another owner archived past our cached state; verify active rows.
            return self._records(connection)
        anchor = connection.execute("SELECT record FROM events WHERE sequence=?", (cached["sequence"],)).fetchone()
        if cached["sequence"] > base["sequence"]:
            if anchor is None or hashlib.sha256(anchor[0]).hexdigest() != cached["head"]:
                return self._records(connection)
        elif base["head"] != cached["head"]:
            return self._records(connection)
        rows = connection.execute("SELECT sequence, record FROM events WHERE sequence>? ORDER BY sequence",
                                  (cached["sequence"],))
        sequence, head = self._chain(rows, cached["sequence"], cached["head"])
        return {"sequence": sequence, "head": head}

    # -- public API ------------------------------------------------------
    def verify(self, checkpoint=None, *, archives=None):
        """Return a checkpoint; optionally verify an exact external checkpoint.

        Exact comparison is intended for quiescent backups/recovery. A newer
        ledger also differs and must be checked against its own checkpoint.
        ``archives`` names the directory holding archived segments; when given,
        the complete chain from genesis through every recorded segment is checked.
        """
        try:
            with self._lock:
                self._check_paths()
                with closing(sqlite3.connect(self.database)) as connection:
                    if archives is not None:
                        self._verify_archives(connection, Path(archives))
                    result = self._records(connection)
                self._verified = result
                self._since_full = 0
            if checkpoint is not None and result != checkpoint:
                raise AuditError("audit_checkpoint_mismatch")
            return dict(result)
        except Exception:
            raise AuditError("audit_verification_failed") from None

    def __call__(self, event):
        # Deliberately retain no exception text in public errors. Runtime audit
        # events contain identifiers and decisions; custom hosts must redact.
        try:
            if type(event) is not dict:
                raise ValueError()
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
            if len(encoded.encode()) > 16384:
                raise ValueError()
            snapshot = json.loads(encoded)
            with self._lock:
                self._check_paths()
                with closing(sqlite3.connect(self.database, timeout=5)) as connection:
                    connection.execute("PRAGMA synchronous=FULL")
                    connection.execute("BEGIN IMMEDIATE")
                    # A rotation can publish a new keyring while this process
                    # waits for SQLite. Recheck after obtaining the write lock
                    # so a stale process cannot append with the retired primary.
                    self._check_paths()
                    checkpoint = self._state(connection)
                    sequence = checkpoint["sequence"] + 1
                    record = {"sequence": sequence, "previous": checkpoint["head"],
                              "time_ns": time.time_ns(), "event": snapshot}
                    encrypted = self._cipher.encrypt(json.dumps(record, sort_keys=True, allow_nan=False).encode())
                    connection.execute("INSERT INTO events VALUES (?, ?)", (sequence, encrypted))
                    connection.commit()
                    self._verified = {"sequence": sequence, "head": hashlib.sha256(encrypted).hexdigest()}
                    self._since_full += 1
        except Exception:
            self._verified = None
            raise AuditError("audit_write_failed") from None

    def events(self, *, since=0, archives=None):
        """Yield (sequence, time_ns, event) after a full verification.

        Archived segments are included when ``archives`` is supplied.
        """
        self.verify(archives=archives)
        try:
            with self._lock, closing(sqlite3.connect(self.database)) as connection:
                segments = [item for item in (self._meta(connection, "archives", []) if archives is not None else [])
                            if item["last_sequence"] > since]
                rows = connection.execute("SELECT sequence, record FROM events WHERE sequence>? ORDER BY sequence",
                                          (since,)).fetchall()
        except Exception:
            raise AuditError("audit_read_failed") from None
        # Segment files are immutable and digest-checked by verify() above.
        def decoded(items):
            for sequence, encrypted in items:
                if sequence > since:
                    record = json.loads(self._cipher.decrypt(encrypted))
                    yield sequence, record["time_ns"], record["event"]
        try:
            for item in segments:
                yield from decoded(self._archive_rows(Path(archives) / item["file"]))
            yield from decoded(rows)
        except AuditError:
            raise
        except Exception:
            raise AuditError("audit_read_failed") from None

    def export(self, output, *, since=0, archives=None):
        """Write allowlisted event metadata as JSON lines to a new private file."""
        output = Path(output)
        exported = dropped = 0
        try:
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            raise AuditError("audit_export_path_unavailable") from None
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                for sequence, time_ns, event in self.events(since=since, archives=archives):
                    kept, removed = safe_event(event if type(event) is dict else {})
                    dropped += removed
                    stream.write(json.dumps({"sequence": sequence, "time_ns": time_ns, "event": kept},
                                            sort_keys=True, separators=(",", ":")) + "\n")
                    exported += 1
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            output.unlink(missing_ok=True)
            raise AuditError("audit_export_failed") from None
        return {"exported": exported, "dropped_fields": dropped, "checkpoint": self.verify()}

    # -- retention -------------------------------------------------------
    def archive(self, directory, *, keep=0, batch=5000, pause=0.05):
        """Move all but the newest ``keep`` events into encrypted segment files.

        Segments keep original ciphertext, so they are as protected as the
        ledger. Work proceeds in chunks of at most ``batch`` events, each in its
        own transaction: the chunk's rows are verified as a chain continuing the
        current base, its segment is made durable, then the segment digest and
        the new base are recorded and the rows deleted. Appends wait at most one
        chunk, and the lock is released for ``pause`` seconds between chunks.
        Segment files and their directory entries are fsynced before the
        transaction that deletes the rows. A chunk that fails leaves no segment
        file behind.
        """
        directory = Path(directory)
        if type(keep) is not int or keep < 0:
            raise AuditError("invalid_archive_keep")
        if type(batch) is not int or not 1 <= batch <= 1_000_000:
            raise AuditError("invalid_archive_batch")
        archived, files, last_file, last_digest = 0, 0, None, None
        try:
            _check_private(directory, directory=True)
            while True:
                chunk = self._archive_chunk(directory, keep, batch)
                if chunk is None:
                    break
                archived += chunk[0]
                files += 1
                last_file, last_digest = chunk[1], chunk[2]
                time.sleep(pause)
            with self._lock:
                checkpoint = dict(self._verified) if self._verified else None
            if checkpoint is None:
                checkpoint = self.verify()
            return {"archived": archived, "files": files, "file": last_file, "sha256": last_digest,
                    "checkpoint": checkpoint}
        except AuditError:
            raise
        except Exception:
            self._verified = None
            raise AuditError("audit_archive_failed") from None

    def _archive_chunk(self, directory, keep, batch):
        path = None
        with self._lock:
            self._check_paths()
            with closing(sqlite3.connect(self.database, timeout=5)) as connection:
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                self._check_paths()
                # Same pre-write check as an append: the active head is verified
                # (incrementally, or fully when due); the archived rows are
                # re-verified below as they are copied.
                state = self._state(connection)
                base = self._base(connection)
                last = min(state["sequence"] - keep, base["sequence"] + batch)
                if last <= base["sequence"]:
                    connection.rollback()
                    self._verified = state
                    return None
                rows = connection.execute(
                    "SELECT sequence, record FROM events WHERE sequence<=? ORDER BY sequence", (last,)).fetchall()
                sequence, head = self._chain(rows, base["sequence"], base["head"])
                if sequence != last:
                    raise AuditError("audit_integrity_failed")
                name = "audit-%020d-%020d.jsonl" % (base["sequence"] + 1, last)
                path = directory / name
                header = {"format": ARCHIVE_FORMAT, "first_sequence": base["sequence"] + 1,
                          "last_sequence": last, "previous_head": base["head"], "last_head": head,
                          "created_at_ns": time.time_ns()}
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    digest = hashlib.sha256()
                    with os.fdopen(fd, "wb") as stream:
                        for line in [json.dumps(header, sort_keys=True)] + [
                                json.dumps({"sequence": s, "record": base64.b64encode(r).decode()}) for s, r in rows]:
                            data = (line + "\n").encode()
                            digest.update(data)
                            stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    descriptor = os.open(directory, os.O_RDONLY)
                    try:
                        os.fsync(descriptor)  # the new segment's directory entry is durable
                    finally:
                        os.close(descriptor)
                    archives = self._meta(connection, "archives", [])
                    archives.append({"file": name, "first_sequence": header["first_sequence"],
                                     "last_sequence": last, "last_head": head, "sha256": digest.hexdigest()})
                    self._set_meta(connection, "archives", archives)
                    self._set_meta(connection, "base", {"sequence": last, "head": head})
                    connection.execute("DELETE FROM events WHERE sequence<=?", (last,))
                    connection.commit()
                except BaseException:
                    path.unlink(missing_ok=True)
                    raise
                # Archiving a prefix leaves the active head unchanged.
                self._verified = state
                return len(rows), name, digest.hexdigest()

    def rotate_key(self, *, archives=None):
        """Offline, recoverable key rotation without rewriting chain ciphertext.

        The new primary and every retained decrypt key are published atomically
        before this instance starts using the new primary. Existing ciphertext
        is intentionally unchanged: its bytes are part of the audit hash chain.
        Stop the host and all maintenance writers before calling this method.
        """
        try:
            with self._lock:
                self._check_paths()
                if len(self._keys) >= MAX_AUDIT_KEYS:
                    raise AuditError("audit_keyring_full")
                with closing(sqlite3.connect(self.database, timeout=0)) as connection:
                    connection.execute("PRAGMA synchronous=FULL")
                    connection.execute("BEGIN EXCLUSIVE")
                    # Reject a second rotation that won the SQLite lock while
                    # this instance was waiting to acquire it.
                    self._check_paths()
                    recorded_archives = self._meta(connection, "archives", [])
                    if recorded_archives and archives is None:
                        raise AuditError("audit_archives_required")
                    if archives is not None:
                        self._verify_archives(connection, Path(archives))
                    state = self._records(connection)
                    new_key = Fernet.generate_key()
                    while new_key in self._keys:
                        new_key = Fernet.generate_key()
                    keys = (new_key, *self._keys)
                    data = json.dumps([key.decode("ascii") for key in keys],
                                      separators=(",", ":")).encode()
                    _atomic_private_write(self.key_file, data)
                    self._key_bytes = data
                    self._keys, self._cipher = _keyring(data)
                    self._verified = state
                    self._since_full = 0
                    connection.rollback()
                return {"rotated": True, "retained_keys": len(self._keys) - 1,
                        "checkpoint": dict(state)}
        except Exception:
            self._verified = None
            raise AuditError("audit_key_rotation_failed") from None

    @staticmethod
    def _archive_rows(path):
        lines = Path(path).read_bytes().splitlines()
        header = json.loads(lines[0])
        if header.get("format") != ARCHIVE_FORMAT:
            raise AuditError("audit_archive_invalid")
        rows = []
        for line in lines[1:]:
            item = json.loads(line)
            rows.append((item["sequence"], base64.b64decode(item["record"], validate=True)))
        return rows

    def _verify_archives(self, connection, directory):
        sequence, head = 0, GENESIS
        for item in self._meta(connection, "archives", []):
            path = directory / item["file"]
            _check_private(path)
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise AuditError("audit_archive_digest_mismatch")
            header = json.loads(data.splitlines()[0])
            if (header["first_sequence"] != sequence + 1 or header["previous_head"] != head
                    or header["last_sequence"] != item["last_sequence"]):
                raise AuditError("audit_archive_chain_broken")
            sequence, head = self._chain(self._archive_rows(path), sequence, head)
            if sequence != item["last_sequence"] or head != item["last_head"] or head != header["last_head"]:
                raise AuditError("audit_archive_chain_broken")
        base = self._base(connection)
        if base["sequence"] != sequence or base["head"] != head:
            raise AuditError("audit_archive_chain_broken")

    def summary(self):
        """Counts only; no event content."""
        with self._lock, closing(sqlite3.connect(self.database)) as connection:
            base = self._base(connection)
            archives = self._meta(connection, "archives", [])
            active = connection.execute("SELECT count(*) FROM events").fetchone()[0]
        return {"active_events": active, "archived_segments": len(archives),
                "archived_events": base["sequence"], "base_sequence": base["sequence"]}
