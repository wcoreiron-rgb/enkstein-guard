"""Durable duplicate suppression and explicit uncertain outcomes, not a retry queue.

One trusted service owns a ledger. Completed actions are never automatically
replayed. Original response bodies and credentials are not persisted.

Retention: with ``time_bound`` request IDs (``<unix-seconds>-<random>``) every
record carries its issuance time. Archival removes terminal records issued
before a cutoff and persists that cutoff; any request ID issued at or before
the cutoff is rejected forever, so archived requests can never execute again,
even after clock rollback. Once enabled, time-bound mode cannot be disabled.

Schema 3 (0.5.0rc2): the issuance time and tenant hash of each encrypted record
are also stored in indexed columns, so archival and accounting read only due
records and run in bounded chunks; archive segments are listed in their own
table so the per-request policy read stays constant-size. Opening an older
ledger migrates it once; older releases refuse a schema-3 ledger (fail closed).
Storage failures surface as ``tracking_unavailable`` so callers can report a
request that was never dispatched distinctly from an unknown outcome.
"""
from contextlib import closing
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

from cryptography.fernet import Fernet
from .vault import _check_private

IDENTITY_V1 = b"guard-outcomes-v1"
IDENTITY_V2 = b"guard-outcomes-v2"
IDENTITY_V3 = b"guard-outcomes-v3"
LEGACY = (IDENTITY_V1, IDENTITY_V2)
STATES = frozenset({"executing", "completed", "denied", "uncertain", "approval_pending"})
TERMINAL = frozenset({"completed", "denied"})
TIME_BOUND_ID = re.compile(r"(\d{10})-[A-Za-z0-9_-]{16,100}")
ARCHIVE_FORMAT = "enkstein-guard-outcome-archive-v1"
STORAGE_ERRORS = (sqlite3.Error, OSError)


class OutcomeError(Exception):
    pass


def _fsync_directory(directory):
    """Make a newly created file's directory entry durable."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def new_request_id(now=None):
    """Client helper for time-bound request identifiers."""
    return "%010d-%s" % (int(time.time() if now is None else now), secrets.token_urlsafe(24))


def _create_schema(connection):
    connection.execute("CREATE TABLE IF NOT EXISTS outcomes (id TEXT PRIMARY KEY, record BLOB NOT NULL, "
                       "issued_at INTEGER, tenant_hash TEXT)")
    connection.execute("CREATE INDEX IF NOT EXISTS outcomes_issued ON outcomes(issued_at)")
    connection.execute("CREATE TABLE IF NOT EXISTS tenant_counts (tenant_hash TEXT PRIMARY KEY, used INTEGER NOT NULL)")
    connection.execute("CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
    connection.execute("CREATE TABLE IF NOT EXISTS archives (sequence INTEGER PRIMARY KEY, record BLOB NOT NULL)")


class OutcomeLedger:
    @classmethod
    def initialize(cls, database, key_file, *, maximum=10000, **options):
        database, key_file = Path(database), Path(key_file)
        if database == key_file or database.exists() or key_file.exists():
            raise OutcomeError("outcome_paths_already_exist")
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
        cipher = Fernet(key)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
            connection.execute("INSERT INTO identity VALUES (?)", (cipher.encrypt(IDENTITY_V3),))
            _create_schema(connection)
            policy = {"name": "policy", "value": {"time_bound": False, "cutoff": 0, "archives": 0}}
            connection.execute("INSERT INTO meta VALUES ('policy', ?)",
                               (cipher.encrypt(json.dumps(policy, sort_keys=True).encode()),))
            connection.commit()
        return cls(database, key_file, maximum=maximum, **options)

    def __init__(self, database, key_file, *, maximum=10000, time_bound=False,
                 max_request_age=86400, clock_skew=300, clock=time.time):
        if type(maximum) is not int or not 1 <= maximum <= 1000000:
            raise ValueError("invalid_outcome_limit")
        if type(time_bound) is not bool:
            raise ValueError("invalid_request_id_policy")
        for value in (max_request_age, clock_skew):
            if type(value) is not int or not 1 <= value <= 31_536_000:
                raise ValueError("invalid_request_id_window")
        self.database, self.key_file = Path(database), Path(key_file)
        self.maximum = maximum
        self.time_bound = time_bound
        self.max_request_age = max_request_age
        self.clock_skew = clock_skew
        self._clock = clock
        self._tenant_limits = None
        self.generation = secrets.token_hex(32)
        self._check()
        self._key = self.key_file.read_bytes()
        self._cipher = Fernet(self._key)
        with closing(self._connect(allow_legacy=True)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            identity = self._identity(connection, allow_legacy=True)
            if identity in LEGACY:
                self._migrate(connection, identity)
            policy = self._policy(connection)
            if policy["time_bound"] and not time_bound:
                raise OutcomeError("ledger_requires_time_bound_ids")
            if time_bound and not policy["time_bound"]:
                policy["time_bound"] = True
                self._save_policy(connection, policy)
            self._cutoff = policy["cutoff"]
            for name, encrypted in connection.execute("SELECT id, record FROM outcomes").fetchall():
                record = self._decode(name, encrypted)
                if record["state"] == "executing":
                    record["state"] = "uncertain"
                    connection.execute("UPDATE outcomes SET record=? WHERE id=?", (self._encode(record), name))
            connection.commit()

    # -- storage helpers -------------------------------------------------
    def _check(self):
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)
        if hasattr(self, "_key") and self.key_file.read_bytes() != self._key:
            raise OutcomeError("outcome_key_changed")

    def _identity(self, connection, *, allow_legacy=False):
        rows = connection.execute("SELECT record FROM identity").fetchall()
        if len(rows) != 1:
            raise OutcomeError("outcome_identity_failed")
        identity = self._cipher.decrypt(rows[0][0])
        if identity != IDENTITY_V3 and not (allow_legacy and identity in LEGACY):
            raise OutcomeError("outcome_identity_failed")
        return identity

    def _connect(self, *, allow_legacy=False):
        self._check()
        connection = sqlite3.connect(self.database, timeout=5)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            self._identity(connection, allow_legacy=allow_legacy)
            return connection
        except Exception:
            connection.close()
            raise OutcomeError("outcome_integrity_failed") from None

    def _migrate(self, connection, identity):
        """One-time upgrade of a schema 1/2 ledger to schema 3."""
        connection.execute("CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
        row = connection.execute("SELECT value FROM meta WHERE name='policy'").fetchone()
        if row is None:
            if identity != IDENTITY_V1:
                raise OutcomeError("outcome_integrity_failed")
            legacy = {"time_bound": False, "cutoff": 0, "archives": []}
        else:
            legacy = self._policy_record(row[0], legacy=True)
            if legacy["time_bound"] != (identity == IDENTITY_V2):
                raise OutcomeError("outcome_integrity_failed")
        columns = {item[1] for item in connection.execute("PRAGMA table_info(outcomes)")}
        for column, kind in (("issued_at", "INTEGER"), ("tenant_hash", "TEXT")):
            if column not in columns:
                connection.execute("ALTER TABLE outcomes ADD COLUMN %s %s" % (column, kind))
        _create_schema(connection)
        for name, encrypted in connection.execute("SELECT id, record FROM outcomes").fetchall():
            record = self._decode(name, encrypted)
            connection.execute("UPDATE outcomes SET issued_at=?, tenant_hash=? WHERE id=?",
                               (record.get("issued_at"), record.get("tenant_hash"), name))
        for item in legacy["archives"]:
            connection.execute("INSERT INTO archives (record) VALUES (?)", (self._encode_value(item),))
        self._save_policy(connection, {"time_bound": legacy["time_bound"], "cutoff": legacy["cutoff"],
                                       "archives": len(legacy["archives"])})
        connection.execute("UPDATE identity SET record=?", (self._cipher.encrypt(IDENTITY_V3),))

    def _policy_record(self, encrypted, *, legacy=False):
        try:
            record = json.loads(self._cipher.decrypt(encrypted))
            value = record["value"]
            archives = value["archives"]
            if (record["name"] != "policy" or type(value["time_bound"]) is not bool or type(value["cutoff"]) is not int
                    or (type(archives) is not list if legacy else type(archives) is not int)):
                raise ValueError()
            return value
        except Exception:
            raise OutcomeError("outcome_integrity_failed") from None

    def _policy(self, connection):
        row = connection.execute("SELECT value FROM meta WHERE name='policy'").fetchone()
        if row is None:
            raise OutcomeError("outcome_integrity_failed")
        return self._policy_record(row[0])

    def _save_policy(self, connection, policy):
        data = self._cipher.encrypt(json.dumps({"name": "policy", "value": policy}, sort_keys=True).encode())
        connection.execute("INSERT INTO meta VALUES ('policy', ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                           (data,))

    def _encode(self, record):
        return self._cipher.encrypt(json.dumps(record, sort_keys=True).encode())

    def _encode_value(self, value):
        return self._cipher.encrypt(json.dumps(value, sort_keys=True).encode())

    def _decode(self, name, encrypted):
        try:
            record = json.loads(self._cipher.decrypt(encrypted))
            if record["id"] != name or record["state"] not in STATES:
                raise ValueError()
            return record
        except Exception:
            raise OutcomeError("outcome_integrity_failed") from None

    # -- capacity --------------------------------------------------------
    def configure_tenants(self, tenants):
        """Reserve equal capacity for identities registered by the trusted host.

        Existing legacy/removed-tenant records consume capacity before reservation.
        This prevents a tenant from consuming another registered tenant's share.
        """
        hashes={hashlib.sha256(tenant.encode()).hexdigest() for tenant in tenants}
        if not hashes:
            raise OutcomeError("registered_tenants_required")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            total=connection.execute("SELECT count(*) FROM outcomes").fetchone()[0]
            counts=dict(connection.execute("SELECT tenant_hash, used FROM tenant_counts"))
            reserved_records=sum(counts.get(name,0) for name in hashes)
            available=self.maximum-(total-reserved_records)
            share=available//len(hashes)
            if share < 1:
                raise OutcomeError("insufficient_reserved_capacity")
            self._tenant_limits={name:share for name in hashes}

    def usage(self):
        """Counts only: records, capacity, per-tenant share use, cutoff, archives,
        and records kept below the archive cutoff (unreconciled)."""
        try:
            with closing(self._connect()) as connection:
                total = connection.execute("SELECT count(*) FROM outcomes").fetchone()[0]
                policy = self._policy(connection)
                used = dict(connection.execute("SELECT tenant_hash, used FROM tenant_counts"))
                oldest = connection.execute("SELECT min(issued_at) FROM outcomes").fetchone()[0]
                # Records at or below the archive cutoff are still here only
                # because they were not archivable (unreconciled uncertain, or in
                # flight at archival time); they outlive the sizing horizon.
                retained = connection.execute(
                    "SELECT count(*) FROM outcomes WHERE issued_at IS NOT NULL AND issued_at <= ?",
                    (policy["cutoff"],)).fetchone()[0] if policy["cutoff"] else 0
        except OutcomeError:
            raise
        except STORAGE_ERRORS:
            raise OutcomeError("tracking_unavailable") from None
        limits = self._tenant_limits or {}
        fullest = max((used.get(tenant, 0) / limit for tenant, limit in limits.items() if limit), default=None)
        return {"records": total, "maximum": self.maximum, "time_bound": policy["time_bound"],
                "cutoff": policy["cutoff"], "archives": policy["archives"],
                "tenant_shares": len(limits), "tenant_share_records": min(limits.values()) if limits else None,
                "fullest_tenant_share_used": round(fullest, 4) if fullest is not None else None,
                "oldest_issued_at": oldest, "retained_below_cutoff": retained}

    def now(self):
        """The ledger's clock (wall time in production; injectable in tests)."""
        return self._clock()

    # -- request identifiers -------------------------------------------
    def _issued_at(self, request_id):
        if not self.time_bound:
            return None
        match = TIME_BOUND_ID.fullmatch(request_id)
        if match is None:
            raise OutcomeError("invalid_request_id")
        issued = int(match[1])
        now = int(self._clock())
        if issued <= self._cutoff:
            raise OutcomeError("request_id_expired")
        if issued < now - self.max_request_age or issued > now + self.clock_skew:
            raise OutcomeError("request_id_outside_window")
        return issued

    @staticmethod
    def binding(principal, request_id, route, payload):
        if not isinstance(request_id, str) or not 16 <= len(request_id) <= 128 or not request_id.isascii():
            raise OutcomeError("invalid_request_id")
        scope = [principal.tenant_id, principal.principal_id, principal.agent_id, request_id]
        name = hashlib.sha256(json.dumps(scope).encode()).hexdigest()
        body = json.dumps([route, payload], sort_keys=True, separators=(",", ":"), allow_nan=False)
        return name, hashlib.sha256(body.encode()).hexdigest()

    # -- lifecycle -------------------------------------------------------
    def begin(self, principal, request_id, route, payload):
        name, digest = self.binding(principal, request_id, route, payload)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                # Re-read the persisted cutoff: another owner may have archived.
                self._cutoff = self._policy(connection)["cutoff"]
                row = connection.execute("SELECT record FROM outcomes WHERE id=?", (name,)).fetchone()
                if row:
                    record = self._decode(name, row[0])
                    if record["digest"] != digest:
                        raise OutcomeError("request_id_conflict")
                    state = record["state"]
                    if state == "approval_pending":
                        # Nothing was dispatched; the same bound request may proceed
                        # once, now owned by this generation.
                        record["state"], record["generation"] = "executing", self.generation
                        connection.execute("UPDATE outcomes SET record=? WHERE id=?", (self._encode(record), name))
                        connection.commit()
                        return name, "new"
                    # A second owner must not silently continue the old execution.
                    if state == "executing" and record["generation"] != self.generation:
                        state = "uncertain"
                    return name, state
                issued = self._issued_at(request_id)
                if connection.execute("SELECT count(*) FROM outcomes").fetchone()[0] >= self.maximum:
                    raise OutcomeError("outcome_capacity_reached")
                tenant_hash=hashlib.sha256(principal.tenant_id.encode()).hexdigest()
                if self._tenant_limits is None or tenant_hash not in self._tenant_limits:
                    raise OutcomeError("tenant_capacity_not_configured")
                used=connection.execute("SELECT used FROM tenant_counts WHERE tenant_hash=?",(tenant_hash,)).fetchone()
                if (used[0] if used else 0) >= self._tenant_limits[tenant_hash]:
                    raise OutcomeError("tenant_outcome_capacity_reached")
                record = {"id": name, "digest": digest, "state": "executing", "generation": self.generation,
                          "tenant_hash": tenant_hash, "issued_at": issued}
                connection.execute("INSERT INTO outcomes (id, record, issued_at, tenant_hash) VALUES (?,?,?,?)",
                                   (name, self._encode(record), issued, tenant_hash))
                connection.execute("INSERT INTO tenant_counts VALUES (?,1) ON CONFLICT(tenant_hash) DO UPDATE SET used=used+1",(tenant_hash,))
                connection.commit()
                return name, "new"
        except OutcomeError:
            raise
        except STORAGE_ERRORS:
            raise OutcomeError("tracking_unavailable") from None

    def finish(self, name, state):
        if state not in {"completed", "denied", "uncertain", "approval_pending"}:
            raise OutcomeError("invalid_outcome_state")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT record FROM outcomes WHERE id=?", (name,)).fetchone()
                if not row:
                    raise OutcomeError("unknown_request")
                record = self._decode(name, row[0])
                if record["generation"] != self.generation or record["state"] != "executing":
                    raise OutcomeError("outcome_ownership_lost")
                record["state"] = state
                connection.execute("UPDATE outcomes SET record=? WHERE id=?", (self._encode(record), name))
                connection.commit()
        except OutcomeError:
            raise
        except STORAGE_ERRORS:
            raise OutcomeError("tracking_unavailable") from None

    def abandon(self, name):
        """Remove this owner's record for a request that was never dispatched,
        so the same request ID may be submitted again. Never use after any
        dispatch was attempted."""
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT record, tenant_hash FROM outcomes WHERE id=?", (name,)).fetchone()
                if not row:
                    return False
                record = self._decode(name, row[0])
                if record["generation"] != self.generation or record["state"] != "executing":
                    raise OutcomeError("outcome_ownership_lost")
                connection.execute("DELETE FROM outcomes WHERE id=?", (name,))
                if row[1]:
                    connection.execute("UPDATE tenant_counts SET used=max(used-1, 0) WHERE tenant_hash=?", (row[1],))
                connection.commit()
                return True
        except OutcomeError:
            raise
        except STORAGE_ERRORS:
            raise OutcomeError("tracking_unavailable") from None

    def state(self, name):
        """Current state of one record, or None."""
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT record FROM outcomes WHERE id=?", (name,)).fetchone()
        return self._decode(name, row[0])["state"] if row else None

    def records(self, *, state=None):
        """Secret-free listing: hashed IDs, states and issuance times only."""
        if state is not None and state not in STATES:
            raise OutcomeError("invalid_outcome_state")
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute("SELECT id, record FROM outcomes ORDER BY id").fetchall()
        except STORAGE_ERRORS:
            raise OutcomeError("tracking_unavailable") from None
        result = []
        for name, encrypted in rows:
            record = self._decode(name, encrypted)
            if state is None or record["state"] == state:
                result.append({"id": name, "state": record["state"], "issued_at": record.get("issued_at"),
                               "reconciled": record.get("reconciled")})
        return result

    def resolve(self, name, reconciled, *, note_digest=None):
        """Record an operator reconciliation for an uncertain action.

        The request ID still never replays; a new action needs a new ID.
        """
        if reconciled not in {"executed", "not_executed"}:
            raise OutcomeError("invalid_reconciliation")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT record FROM outcomes WHERE id=?", (name,)).fetchone()
                if not row:
                    raise OutcomeError("unknown_request")
                record = self._decode(name, row[0])
                if record["state"] != "uncertain":
                    raise OutcomeError("not_uncertain")
                record["reconciled"] = reconciled
                record["reconciled_at"] = int(self._clock())
                connection.execute("UPDATE outcomes SET record=? WHERE id=?", (self._encode(record), name))
                connection.commit()
        except OutcomeError:
            raise
        except STORAGE_ERRORS:
            raise OutcomeError("tracking_unavailable") from None
        return {"id": name, "reconciled": reconciled}

    # -- retention -------------------------------------------------------
    def archive(self, directory, *, before, include_uncertain=False, batch=5000, include_retained=True,
                pause=0.05):
        """Archive terminal records issued before ``before`` (unix seconds).

        Only available in time-bound mode. Due records are processed oldest
        first in chunks of about ``batch`` records, each in its own short
        transaction: the chunk's segment file and its directory entry are made
        durable, then its records are deleted, per-tenant counts decremented
        and the cutoff advanced in one transaction. Between chunks the write
        lock is released for ``pause`` seconds so requests are not starved.
        Uncertain records stay unless reconciled or explicitly included; a
        record still in flight in this process is never archived. With
        ``include_retained`` a second chunked pass archives retained records
        (at or below the cutoff) reconciled since. A failed chunk leaves no
        segment file behind.
        """
        if not self.time_bound:
            raise OutcomeError("archival_requires_time_bound_ids")
        if type(before) is not int or before <= 0:
            raise OutcomeError("invalid_archive_cutoff")
        if type(batch) is not int or not 1 <= batch <= 100_000:
            raise OutcomeError("invalid_archive_batch")
        directory = Path(directory)
        _check_private(directory, directory=True)
        totals = {"archived": 0, "retained_unreconciled": 0, "files": 0, "file": None, "sha256": None, "chunks": 0}
        try:
            for retained_pass in ((False, True) if include_retained else (False,)):
                position = None
                retained = 0
                while True:
                    chunk = self._archive_chunk(directory, before, include_uncertain, batch, retained_pass, position)
                    totals["chunks"] += 1
                    totals["archived"] += chunk["archived"]
                    retained += chunk["retained"]
                    if chunk["file"]:
                        totals["files"] += 1
                        totals["file"], totals["sha256"] = chunk["file"], chunk["sha256"]
                    if chunk["complete"]:
                        break
                    position = chunk["position"]
                    time.sleep(pause)
                if retained_pass or not include_retained:
                    # The retained pass sees every record kept at or below the cutoff.
                    totals["retained_unreconciled"] = retained
        except OutcomeError:
            raise
        except STORAGE_ERRORS:
            raise OutcomeError("outcome_archive_failed") from None
        totals["cutoff"] = self._cutoff
        return totals

    def _archive_chunk(self, directory, before, include_uncertain, batch, retained_pass, position):
        path = None
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            policy = self._policy(connection)
            if before > int(self._clock()) - self.max_request_age:
                # Requests issued after this point may still legitimately arrive.
                raise OutcomeError("archive_cutoff_inside_request_window")
            low = policy["cutoff"]
            if retained_pass:
                # Records at or below the cutoff were retained (uncertain); archive
                # the ones reconciled since, or all when explicitly included.
                after = position or (-1, "")
                rows = connection.execute("SELECT id, record, issued_at FROM outcomes WHERE issued_at IS NOT NULL "
                                          "AND issued_at <= ? AND (issued_at > ? OR (issued_at = ? AND id > ?)) "
                                          "ORDER BY issued_at, id LIMIT ?",
                                          (low, after[0], after[0], after[1], batch))
            else:
                rows = connection.execute("SELECT id, record, issued_at FROM outcomes WHERE issued_at IS NOT NULL "
                                          "AND issued_at > ? AND issued_at <= ? ORDER BY issued_at, id", (low, before))
            selected, freed, retained, scanned, last, boundary, final = [], {}, 0, 0, None, None, None
            for name, encrypted, issued in rows:
                if not retained_pass and scanned >= batch and issued != last:
                    boundary = last  # every record issued at or before this time has been read
                    break
                scanned, last, final = scanned + 1, issued, (issued, name)
                record = self._decode(name, encrypted)
                if record.get("issued_at") != issued:
                    raise OutcomeError("outcome_integrity_failed")
                in_flight = record["state"] == "executing" and record.get("generation") == self.generation
                if not in_flight and (record["state"] in TERMINAL or record["state"] == "approval_pending" or (
                        record["state"] in ("uncertain", "executing")
                        and (include_uncertain or record.get("reconciled")))):
                    selected.append((name, encrypted))
                    tenant = record.get("tenant_hash")
                    if tenant:
                        freed[tenant] = freed.get(tenant, 0) + 1
                else:
                    retained += 1
            if retained_pass:
                complete, cutoff = scanned < batch, low
            else:
                complete = boundary is None
                cutoff = max(low, before if complete else boundary)
            if not selected and cutoff == low:
                connection.rollback()
                return {"archived": 0, "retained": retained, "file": None, "sha256": None, "complete": complete,
                        "position": final}
            name = digest_hex = None
            try:
                if selected:
                    name = "outcomes-%010d-%s.jsonl" % (cutoff, secrets.token_hex(4))
                    path = directory / name
                    digest = hashlib.sha256()
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        header = json.dumps({"format": ARCHIVE_FORMAT, "cutoff": cutoff, "records": len(selected),
                                             "created_at": int(self._clock())}, sort_keys=True)
                        for line in [header] + [json.dumps({"id": i, "record": base64.b64encode(r).decode()})
                                                for i, r in selected]:
                            data = (line + "\n").encode()
                            digest.update(data)
                            stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    _fsync_directory(directory)
                    digest_hex = digest.hexdigest()
                    connection.executemany("DELETE FROM outcomes WHERE id=?", [(i,) for i, _ in selected])
                    connection.execute("INSERT INTO archives (record) VALUES (?)", (self._encode_value(
                        {"file": name, "sha256": digest_hex, "records": len(selected), "cutoff": cutoff}),))
                    connection.executemany("UPDATE tenant_counts SET used=max(used-?, 0) WHERE tenant_hash=?",
                                           [(count, tenant) for tenant, count in sorted(freed.items())])
                    policy["archives"] += 1
                policy["cutoff"] = cutoff
                self._save_policy(connection, policy)
                connection.commit()
            except BaseException:
                if path is not None:
                    path.unlink(missing_ok=True)
                raise
            self._cutoff = cutoff
            return {"archived": len(selected), "retained": retained, "file": name, "sha256": digest_hex,
                    "complete": complete, "position": final}

    def verify_archives(self, directory):
        """Check every recorded segment file: present, digest, header and count,
        and that the segment list matches the authenticated policy counter."""
        directory = Path(directory)
        segments, problems, records = self.archives(), [], 0
        with closing(self._connect()) as connection:
            expected = self._policy(connection)["archives"]
        if len(segments) != expected:
            problems.append({"file": None, "problem": "segment_count_mismatch"})
        names = [item.get("file") for item in segments]
        if len(set(names)) != len(names):
            problems.append({"file": None, "problem": "duplicate_segment"})
        for item in segments:
            try:
                data = (directory / item["file"]).read_bytes()
            except OSError:
                problems.append({"file": item["file"], "problem": "missing"})
                continue
            lines = data.splitlines()
            try:
                header = json.loads(lines[0])
            except (ValueError, IndexError):
                header = {}
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                problems.append({"file": item["file"], "problem": "digest_mismatch"})
            elif (header.get("format") != ARCHIVE_FORMAT or header.get("records") != item["records"]
                  or len(lines) - 1 != item["records"]):
                problems.append({"file": item["file"], "problem": "content_mismatch"})
            records += item["records"]
        return {"segments": len(segments), "records": records, "problems": problems, "verified": not problems}

    def archives(self):
        """Segment records (file, digest, count, cutoff), oldest first."""
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT record FROM archives ORDER BY sequence").fetchall()
        return [json.loads(self._cipher.decrypt(row[0])) for row in rows]
