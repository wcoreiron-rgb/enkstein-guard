"""Encrypted local vault. Host owns authentication and destination authorization.

Fernet authenticates the complete record, including scope and expiry. SQLite
contains random references and encrypted records, never plaintext sensitive data.
"""

from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time

from cryptography.fernet import Fernet, MultiFernet

TOKEN = re.compile(r"\[\[EGV:[a-f0-9]{64}\]\]")
TENANT_RESERVATIONS = "tenant-reservations-v1"


class VaultError(Exception):
    pass


@dataclass(frozen=True)
class Scope:
    tenant: str
    principal: str
    workflow: str
    operation: str

    def __post_init__(self):
        if any(not isinstance(v, str) or not v or len(v) > 256 for v in asdict(self).values()):
            raise ValueError("invalid_vault_scope")


def _check_private(path: Path, *, directory=False):
    if path.is_symlink():
        raise VaultError("unsafe_vault_path")
    info = path.stat()
    if directory and not stat.S_ISDIR(info.st_mode):
        raise VaultError("unsafe_vault_path")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise VaultError("unsafe_vault_path")
    if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise VaultError("unsafe_vault_permissions")


def _atomic_private_write(path: Path, data: bytes):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class LocalVault:
    def __init__(self, database: str | Path, key_file: str | Path, *, clock=time.time, max_bytes=67_108_864, tenant_bytes=None, tenant_limits=None,
                 max_entries=10000):
        self.database, self.key_file = Path(database), Path(key_file)
        if type(max_bytes) is not int or not 1_048_576 <= max_bytes <= 1_073_741_824:
            raise ValueError("invalid_vault_capacity")
        if type(max_entries) is not int or not 1 <= max_entries <= 200_000:
            raise ValueError("invalid_vault_entry_limit")
        self._max_entries = max_entries
        if tenant_bytes is None:
            tenant_bytes = min(8_388_608, max_bytes//2)
        if type(tenant_bytes) is not int or not 1 <= tenant_bytes <= max_bytes:
            raise ValueError("invalid_tenant_capacity")
        if tenant_limits is not None:
            self._validate_tenant_reservations(tenant_limits, max_bytes)
        self._max_bytes, self._tenant_bytes = max_bytes, tenant_bytes
        self._tenant_limits = dict(tenant_limits) if tenant_limits is not None else None
        self._clock = clock
        self._lock = threading.RLock()
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)
        self._load_keys()
        try:
            with self._connection() as db:
                marker = db.execute("SELECT value FROM metadata WHERE name='identity'").fetchone()
                if marker is None or self._cipher.decrypt(marker[0]) != b"enkstein-vault-v1":
                    raise ValueError()
                reservations = self._load_tenant_reservations(db)
                if reservations is not None:
                    if self._tenant_limits is not None and self._tenant_limits != reservations:
                        raise VaultError("tenant_reservation_mismatch")
                    self._tenant_limits = reservations
                else:
                    tenants = self._legacy_tenants(db)
                    if self._tenant_limits is not None:
                        if not tenants.issubset(self._tenant_limits):
                            raise VaultError("tenant_reservations_required")
                        self._save_tenant_reservations(db, self._tenant_limits)
                    elif len(tenants) == 1:
                        tenant = next(iter(tenants))
                        self._tenant_limits = {tenant: self._default_tenant_reservation()}
                        self._save_tenant_reservations(db, self._tenant_limits)
                    elif tenants:
                        raise VaultError("tenant_reservations_required")
                # Accounting index: rebuilt from authenticated records at every
                # open, then maintained transactionally by this owner.
                self._rebuild_index(db)
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_unreadable") from None

    @staticmethod
    def _tenant_key(tenant):
        return hashlib.sha256(tenant.encode()).hexdigest()

    def _rebuild_index(self, db):
        db.execute("CREATE TABLE IF NOT EXISTS entry_index (token TEXT PRIMARY KEY, tenant_hash TEXT NOT NULL, "
                   "bytes INTEGER NOT NULL, expires REAL NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS entry_index_expires ON entry_index(expires)")
        db.execute("CREATE INDEX IF NOT EXISTS entry_index_tenant ON entry_index(tenant_hash)")
        db.execute("DELETE FROM entry_index")
        rows = []
        for token, ciphertext in db.execute("SELECT token,ciphertext FROM entries"):
            record = json.loads(self._cipher.decrypt(ciphertext))
            if record["token"] != token:
                raise VaultError("vault_integrity_failed")
            rows.append((token, self._tenant_key(record["scope"]["tenant"]), len(ciphertext), float(record["expires"])))
        db.executemany("INSERT INTO entry_index VALUES (?,?,?,?)", rows)

    @staticmethod
    def _index_consistent(db):
        entries = db.execute("SELECT count(*) FROM entries").fetchone()[0]
        indexed = db.execute("SELECT count(*) FROM entry_index").fetchone()[0]
        return entries == indexed

    def _delete_tokens(self, db, tokens):
        db.executemany("DELETE FROM entries WHERE token=?", tokens)
        db.executemany("DELETE FROM entry_index WHERE token=?", tokens)

    def usage(self):
        """Counts only: live entries and bytes per hashed tenant."""
        try:
            with self._lock:
                self._load_keys()
                with self._connection() as db:
                    if not self._index_consistent(db):
                        self._rebuild_index(db)
                    now = self._clock()
                    live = db.execute("SELECT count(*), coalesce(sum(bytes),0) FROM entry_index WHERE expires>?",
                                      (now,)).fetchone()
                    expired = db.execute("SELECT count(*) FROM entry_index WHERE expires<=?", (now,)).fetchone()[0]
                    return {"live_entries": live[0], "live_bytes": live[1], "expired_entries": expired,
                            "max_entries": self._max_entries, "max_bytes": self._max_bytes,
                            "tenants": len(self._tenant_limits or {})}
        except VaultError:
            raise
        except Exception:
            raise VaultError("vault_unreadable") from None

    @staticmethod
    def _validate_tenant_name(tenant):
        if not isinstance(tenant, str) or not tenant or len(tenant) > 256:
            raise ValueError("invalid_tenant_reservations")

    @classmethod
    def _validate_tenant_reservations(cls, reservations, max_bytes):
        if not isinstance(reservations, dict) or not reservations:
            raise ValueError("invalid_tenant_reservations")
        for tenant, limit in reservations.items():
            cls._validate_tenant_name(tenant)
            if type(limit) is not int or limit < 1:
                raise ValueError("invalid_tenant_reservations")
        if sum(reservations.values()) > max_bytes // 2:
            raise ValueError("invalid_tenant_reservations")

    def _default_tenant_reservation(self, tenant_count=1):
        reservation = min(self._tenant_bytes, (self._max_bytes // 2) // tenant_count)
        if reservation < 1:
            raise VaultError("tenant_reservations_unavailable")
        return reservation

    def _load_tenant_reservations(self, db):
        row = db.execute("SELECT value FROM metadata WHERE name=?", (TENANT_RESERVATIONS,)).fetchone()
        if row is None:
            return None
        try:
            record = json.loads(self._cipher.decrypt(row[0]))
            if (not isinstance(record, dict) or set(record) != {"alias", "limits"}
                    or record["alias"] != TENANT_RESERVATIONS):
                raise ValueError()
            self._validate_tenant_reservations(record["limits"], self._max_bytes)
            return dict(record["limits"])
        except Exception:
            raise VaultError("vault_integrity_failed") from None

    def _save_tenant_reservations(self, db, reservations):
        data = self._cipher.encrypt(json.dumps(
            {"alias": TENANT_RESERVATIONS, "limits": reservations},
            sort_keys=True, separators=(",", ":"),
        ).encode())
        db.execute("INSERT INTO metadata VALUES (?, ?)", (TENANT_RESERVATIONS, data))

    def _legacy_tenants(self, db):
        tenants = set()
        try:
            for token, ciphertext in db.execute("SELECT token,ciphertext FROM entries"):
                record = json.loads(self._cipher.decrypt(ciphertext))
                if record["token"] != token:
                    raise ValueError()
                tenants.add(Scope(**record["scope"]).tenant)
            return tenants
        except Exception:
            raise VaultError("vault_integrity_failed") from None

    def configure_tenants(self, tenants):
        """Bootstrap fixed tenant reservations before the vault accepts data."""
        if type(tenants) not in (tuple, list) or not tenants:
            raise ValueError("invalid_tenant_reservations")
        for tenant in tenants:
            self._validate_tenant_name(tenant)
        if len(set(tenants)) != len(tenants):
            raise ValueError("invalid_tenant_reservations")
        try:
            with self._lock:
                self._load_keys()
                selected = None
                with self._connection() as db:
                    reservations = self._load_tenant_reservations(db)
                    if reservations is not None:
                        if not set(tenants).issubset(reservations):
                            raise VaultError("tenant_reservation_mismatch")
                        selected = reservations
                    else:
                        if db.execute("SELECT 1 FROM entries LIMIT 1").fetchone() is not None:
                            raise VaultError("tenant_reservations_required")
                        share = self._default_tenant_reservation(len(tenants))
                        selected = {tenant: share for tenant in tenants}
                        self._save_tenant_reservations(db, selected)
                self._tenant_limits = selected
        except (VaultError, ValueError):
            raise
        except Exception:
            raise VaultError("tenant_reservation_write_failed") from None

    @classmethod
    def initialize(cls, database: str | Path, key_file: str | Path, **limits):
        database, key_file = Path(database), Path(key_file)
        if database.exists() or key_file.exists() or database.is_symlink() or key_file.is_symlink():
            raise VaultError("vault_already_exists")
        if database.absolute() == key_file.absolute():
            raise VaultError("invalid_key_location")
        for parent in {database.parent, key_file.parent}:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _check_private(parent, directory=True)
        key = Fernet.generate_key()
        # Exclusive creation: initialization never replaces an existing key.
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps([key.decode()]).encode())
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("CREATE TABLE metadata (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
            db.execute("CREATE TABLE entries (token TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)")
            db.execute("INSERT INTO metadata VALUES ('identity', ?)", (Fernet(key).encrypt(b"enkstein-vault-v1"),))
        return cls(database, key_file, **limits)

    def _load_keys(self):
        try:
            _check_private(self.key_file)
            keys = json.loads(self.key_file.read_bytes())
            if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
                raise ValueError()
            self._keys = keys
            self._cipher = MultiFernet([Fernet(key.encode()) for key in keys])
        except Exception:
            raise VaultError("vault_key_unavailable") from None

    @contextmanager
    def _connection(self):
        _check_private(self.database)
        db = sqlite3.connect(self.database, timeout=5)
        try:
            db.execute("PRAGMA secure_delete=ON")
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            cap = self._max_bytes // page_size
            if db.execute("PRAGMA page_count").fetchone()[0] > cap:
                raise VaultError("vault_capacity_exceeded")
            db.execute("PRAGMA max_page_count=" + str(cap))
            db.execute("BEGIN IMMEDIATE")
            marker = db.execute("SELECT value FROM metadata WHERE name='identity'").fetchone()
            if marker is None or self._cipher.decrypt(marker[0]) != b"enkstein-vault-v1":
                raise VaultError("vault_unreadable")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def put(self, value: str, scope: Scope, destinations: tuple[str, ...], *, ttl: float = 300) -> str:
        return self.put_many((value,), scope, destinations, ttl=ttl)[0]

    def put_many(self, values, scope: Scope, destinations: tuple[str, ...], *, ttl: float = 300):
        """Atomic bounded batch: one capacity/expiry scan, not one scan per value."""
        if (type(values) not in (tuple,list) or not 1 <= len(values) <= 128
                or any(not isinstance(value,str) for value in values)
                or sum(len(value.encode()) for value in values)>1_048_576):
            raise VaultError("invalid_vault_value")
        if not destinations or any(not isinstance(d,str) or not d or len(d)>256 for d in destinations):
            raise VaultError("invalid_vault_destination")
        if type(ttl) not in (float,int) or not math.isfinite(ttl) or not 0<ttl<=86400:
            raise VaultError("invalid_vault_expiry")
        tokens=["[[EGV:"+secrets.token_hex(32)+"]]" for _ in values]
        try:
            with self._lock:
                self._load_keys()
                selected = None
                rows=[]
                expires=self._clock()+ttl
                for token,value in zip(tokens,values):
                    record={"token":token,"scope":asdict(scope),"destinations":list(destinations),
                            "expires":expires,"value":value}
                    rows.append((token,self._cipher.encrypt(json.dumps(record).encode())))
                with self._connection() as db:
                    # Indexed accounting replaces the former full decrypting
                    # scan; a foreign writer that bypassed the index forces a
                    # rebuild from authenticated records.
                    if not self._index_consistent(db):
                        self._rebuild_index(db)
                    now=self._clock()
                    expired=[(token,) for (token,) in db.execute("SELECT token FROM entry_index WHERE expires<=?",(now,))]
                    count,total_used=db.execute("SELECT count(*),coalesce(sum(bytes),0) FROM entry_index WHERE expires>?",(now,)).fetchone()
                    tenant_used=db.execute("SELECT coalesce(sum(bytes),0) FROM entry_index WHERE expires>? AND tenant_hash=?",
                                           (now,self._tenant_key(scope.tenant))).fetchone()[0]
                    reservations = self._load_tenant_reservations(db)
                    if reservations is None:
                        if self._tenant_limits is not None or count or expired:
                            raise VaultError("vault_integrity_failed")
                        reservations = {scope.tenant: self._default_tenant_reservation()}
                        self._save_tenant_reservations(db, reservations)
                    elif self._tenant_limits is not None and self._tenant_limits != reservations:
                        raise VaultError("vault_integrity_failed")
                    if scope.tenant not in reservations:
                        raise VaultError("tenant_not_reserved")
                    limit=reservations[scope.tenant]
                    added=sum(len(ciphertext) for _,ciphertext in rows)
                    if count+len(rows)>self._max_entries or tenant_used+added>limit or total_used+added>self._max_bytes//2:
                        raise VaultError("vault_capacity_exceeded")
                    self._delete_tokens(db,expired)
                    db.executemany("INSERT INTO entries VALUES (?,?)",rows)
                    tenant_hash=self._tenant_key(scope.tenant)
                    db.executemany("INSERT INTO entry_index VALUES (?,?,?,?)",
                                   [(token,tenant_hash,len(ciphertext),expires) for token,ciphertext in rows])
                    selected = reservations
                self._tenant_limits = selected
        except VaultError:raise
        except Exception:raise VaultError("vault_write_failed") from None
        return tokens

    def restore(self, text: str, scope: Scope, destination: str, *, consume=True, json_encoded=False) -> str:
        """All-or-nothing restoration. Scope must come from trusted authentication."""
        if not isinstance(text, str) or len(text.encode()) > 1_048_576:
            raise VaultError("invalid_vault_value")
        references = set(TOKEN.findall(text))
        if "[[EGV:" in TOKEN.sub("", text):
            raise VaultError("invalid_vault_reference")
        try:
            with self._lock:
                self._load_keys()
                with self._connection() as db:
                    values = {}
                    for token in references:
                        row = db.execute("SELECT ciphertext FROM entries WHERE token=?", (token,)).fetchone()
                        if row is None:
                            raise ValueError()
                        record = json.loads(self._cipher.decrypt(row[0]))
                        if (record["token"] != token or record["scope"] != asdict(scope)
                                or destination not in record["destinations"] or record["expires"] <= self._clock()):
                            raise ValueError()
                        values[token] = (json.dumps(record["value"], ensure_ascii=True)[1:-1]
                                         if json_encoded else record["value"])
                    expanded_size = len(text.encode()) + sum(
                        len(values[match[0]].encode()) - len(match[0].encode()) for match in TOKEN.finditer(text))
                    if expanded_size > 1_048_576:
                        raise ValueError()
                    restored = TOKEN.sub(lambda m: values[m[0]], text)
                    if consume:
                        self._delete_tokens(db, [(t,) for t in references])
                    return restored
        except Exception:
            raise VaultError("vault_access_denied") from None

    def revoke_scope(self, scope: Scope) -> int:
        try:
            with self._lock:
                self._load_keys()
                with self._connection() as db:
                    tokens = [(token,) for token, data in db.execute("SELECT token,ciphertext FROM entries")
                              if json.loads(self._cipher.decrypt(data))["scope"] == asdict(scope)]
                    self._delete_tokens(db, tokens)
                    return len(tokens)
        except Exception:
            raise VaultError("vault_revoke_failed") from None

    def purge_expired(self) -> int:
        """Delete expired entries using the accounting index (rebuilt from
        authenticated records first if another writer bypassed it)."""
        try:
            with self._lock:
                self._load_keys()
                with self._connection() as db:
                    if not self._index_consistent(db):
                        self._rebuild_index(db)
                    expired = [(token,) for (token,) in db.execute("SELECT token FROM entry_index WHERE expires<=?",
                                                                   (self._clock(),))]
                    self._delete_tokens(db, expired)
                    return len(expired)
        except Exception:
            raise VaultError("vault_purge_failed") from None

    def save_binding(self, alias: str, value: dict):
        if not re.fullmatch(r"broker:[a-f0-9]{64}", alias):
            raise VaultError("invalid_binding")
        try:
            with self._lock:
                self._load_keys()
                data = self._cipher.encrypt(json.dumps({"alias": alias, "value": value}).encode())
                with self._connection() as db:
                    db.execute("INSERT INTO metadata VALUES (?, ?)", (alias, data))
        except Exception:
            raise VaultError("binding_write_failed") from None

    def load_binding(self, alias: str) -> dict:
        if not re.fullmatch(r"broker:[a-f0-9]{64}", alias):
            raise VaultError("invalid_binding")
        try:
            with self._lock:
                self._load_keys()
                with self._connection() as db:
                    row = db.execute("SELECT value FROM metadata WHERE name=?", (alias,)).fetchone()
                    record = json.loads(self._cipher.decrypt(row[0]))
                    if record["alias"] != alias:
                        raise ValueError()
                    return record["value"]
        except Exception:
            raise VaultError("binding_unavailable") from None

    def delete_binding(self, alias: str):
        if not re.fullmatch(r"broker:[a-f0-9]{64}", alias):
            raise VaultError("invalid_binding")
        try:
            with self._lock:
                self._load_keys()
                with self._connection() as db:
                    db.execute("DELETE FROM metadata WHERE name=?", (alias,))
        except Exception:
            raise VaultError("binding_delete_failed") from None

    def rotate(self):
        """Persist new+old keys first, then atomically re-encrypt; retain old keys.

        Exclusive administrative operation: stop other writers during rotation.
        Retaining old keys makes restart after interruption recoverable.
        """
        try:
            with self._lock:
                self._load_keys()
                if len(self._keys) >= 32:
                    raise ValueError()
                keys = [Fernet.generate_key().decode(), *self._keys]
                _atomic_private_write(self.key_file, json.dumps(keys).encode())
                self._load_keys()
                with self._connection() as db:
                    rows = list(db.execute("SELECT token,ciphertext FROM entries"))
                    db.executemany("UPDATE entries SET ciphertext=? WHERE token=?",
                                   [(self._cipher.rotate(value), token) for token, value in rows])
                    metadata = list(db.execute("SELECT name,value FROM metadata"))
                    db.executemany("UPDATE metadata SET value=? WHERE name=?",
                                   [(self._cipher.rotate(value), name) for name, value in metadata])
                    self._rebuild_index(db)
        except Exception:
            raise VaultError("vault_rotation_failed") from None
