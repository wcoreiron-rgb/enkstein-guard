from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from enkstein_guard.audit import AuditError, DurableAudit
from enkstein_guard.outcomes import OutcomeError, OutcomeLedger, new_request_id
from enkstein_guard.runtime import Principal
from enkstein_guard.vault import LocalVault, Scope


class AuditRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db, self.key = self.root / "audit/audit.sqlite3", self.root / "keys/audit.key"
        self.archive = self.root / "archive"
        self.archive.mkdir(mode=0o700)
        self.audit = DurableAudit.initialize(self.db, self.key, full_verify_every=0)
        for number in range(30):
            self.audit({"outcome": "authorized", "operation_id": "op-%d" % number, "tenant_id": "tenant-a"})

    def test_archive_preserves_chain_and_bounds_active_ledger(self):
        before = self.audit.verify()
        result = self.audit.archive(self.archive, keep=5)
        self.assertEqual(result["archived"], 25)
        self.assertEqual(self.audit.summary()["active_events"], 5)
        self.assertEqual(self.audit.verify(), before)
        self.assertEqual(self.audit.verify(archives=self.archive), before)
        self.audit({"outcome": "after_archive"})
        reopened = DurableAudit(self.db, self.key)
        self.assertEqual(reopened.verify(archives=self.archive)["sequence"], 31)
        self.assertEqual([s for s, _, _ in reopened.events(archives=self.archive)], list(range(1, 32)))
        second = self.audit.archive(self.archive, keep=0)
        self.assertEqual(second["archived"], 6)
        self.assertEqual(self.audit.verify(archives=self.archive)["sequence"], 31)

    def test_archive_tampering_and_deletion_detected(self):
        result = self.audit.archive(self.archive, keep=2)
        path = self.archive / result["file"]
        data = path.read_bytes()
        path.write_bytes(data.replace(b'"sequence": 3', b'"sequence": 4', 1))
        with self.assertRaises(AuditError):
            self.audit.verify(archives=self.archive)
        path.write_bytes(data)
        self.audit.verify(archives=self.archive)
        path.unlink()
        with self.assertRaises(AuditError):
            self.audit.verify(archives=self.archive)

    def test_interior_deletion_detected_on_next_append(self):
        self.audit.verify()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DELETE FROM events WHERE sequence=10")
        with self.assertRaises(AuditError):
            self.audit({"outcome": "x"})

    def test_rollback_of_active_ledger_against_external_checkpoint(self):
        checkpoint = self.audit.verify()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DELETE FROM events WHERE sequence=30")
        with self.assertRaises(AuditError):
            DurableAudit(self.db, self.key).verify(checkpoint)

    def test_export_allowlists_metadata(self):
        self.audit({"outcome": "custom", "payload": {"email": "jane@example.com"}, "detail": "secret detector text",
                    "tenant_id": "tenant-a"})
        output = self.root / "export.jsonl"
        result = self.audit.export(output)
        text = output.read_text()
        self.assertEqual(result["exported"], 31)
        self.assertEqual(result["dropped_fields"], 2)
        self.assertNotIn("jane@example.com", text)
        self.assertNotIn("secret detector text", text)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(AuditError):
            self.audit.export(output)

    def test_legacy_rc5_ledger_opens_and_rc5_reader_rejects_archived_ledger(self):
        # A newly archived ledger starts above sequence 1; a reader that assumes
        # genesis (as 0.4.0rc5 does) cannot validate it and must fail closed.
        self.audit.archive(self.archive, keep=3)
        with closing(sqlite3.connect(self.db)) as connection:
            first = connection.execute("SELECT min(sequence) FROM events").fetchone()[0]
        self.assertEqual(first, 28)


class OutcomeRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db, self.key = self.root / "o/outcomes.sqlite3", self.root / "keys/outcomes.key"
        self.archive = self.root / "archive"
        self.archive.mkdir(mode=0o700)
        self.now = 2_000_000_000
        OutcomeLedger.initialize(self.db, self.key, maximum=20)
        self.ledger = self.open()
        self.principal = Principal("tenant-a", "p", "a", frozenset({"r"}))

    def open(self, **kwargs):
        ledger = OutcomeLedger(self.db, self.key, maximum=20, time_bound=True, max_request_age=3600,
                               clock=lambda: self.now, **kwargs)
        ledger.configure_tenants(["tenant-a", "tenant-b"])
        return ledger

    def run_request(self, request_id, state="completed", payload=None):
        name, status = self.ledger.begin(self.principal, request_id, "r", payload or {"x": 1})
        if status == "new" and state:
            self.ledger.finish(name, state)
        return name, status

    def test_time_bound_format_and_window(self):
        for bad in ("legacy-request-id-123456", "%010d-short" % self.now, new_request_id(self.now - 7200),
                    new_request_id(self.now + 3600)):
            with self.subTest(request_id=bad):
                with self.assertRaises(OutcomeError):
                    self.run_request(bad)
        self.assertEqual(self.run_request(new_request_id(self.now))[1], "new")

    def test_archived_requests_never_execute_again_even_after_clock_rollback(self):
        old = new_request_id(self.now)
        name, _ = self.run_request(old)
        self.now += 7200
        result = self.ledger.archive(self.archive, before=self.now - 3600)
        self.assertEqual(result["archived"], 1)
        self.assertEqual(self.ledger.usage()["records"], 0)
        with self.assertRaises(OutcomeError) as caught:
            self.run_request(old)
        self.assertEqual(str(caught.exception), "request_id_expired")
        self.now -= 7200  # Clock rollback: the persisted cutoff still rejects it.
        reopened = self.open()
        self.ledger = reopened
        with self.assertRaises(OutcomeError):
            self.run_request(old)

    def test_cutoff_inside_window_refused_and_uncertain_retained(self):
        request = new_request_id(self.now)
        name, _ = self.ledger.begin(self.principal, request, "r", {})
        self.ledger.finish(name, "uncertain")
        with self.assertRaises(OutcomeError):
            self.ledger.archive(self.archive, before=self.now)
        self.now += 7200
        result = self.ledger.archive(self.archive, before=self.now - 3600)
        self.assertEqual((result["archived"], result["retained_unreconciled"]), (0, 1))
        self.assertEqual(self.ledger.begin(self.principal, request, "r", {})[1], "uncertain")
        self.ledger.resolve(name, "executed")
        result = self.ledger.archive(self.archive, before=self.now - 3600)
        self.assertEqual(result["archived"], 1)

    def test_approval_pending_reenters_once_and_binding_holds(self):
        request = new_request_id(self.now)
        name, state = self.ledger.begin(self.principal, request, "r", {"x": 1})
        self.ledger.finish(name, "approval_pending")
        self.assertEqual(self.ledger.begin(self.principal, request, "r", {"x": 1})[1], "new")
        with self.assertRaises(OutcomeError):
            self.ledger.begin(self.principal, request, "r", {"x": 2})

    def test_mode_cannot_be_downgraded(self):
        with self.assertRaises(OutcomeError):
            OutcomeLedger(self.db, self.key, maximum=20)

    def test_archive_frees_tenant_capacity(self):
        for _ in range(10):
            self.run_request(new_request_id(self.now))
        with self.assertRaises(OutcomeError):
            self.run_request(new_request_id(self.now))
        self.now += 7200
        self.ledger.archive(self.archive, before=self.now - 3600)
        self.ledger = self.open()
        self.assertEqual(self.run_request(new_request_id(self.now))[1], "new")

    def test_archive_file_private_and_secret_free(self):
        self.run_request(new_request_id(self.now), payload={"email": "jane@example.com"})
        self.now += 7200
        result = self.ledger.archive(self.archive, before=self.now - 3600)
        path = self.archive / result["file"]
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"jane@example.com", path.read_bytes())


class LegacyOutcomeUpgradeTests(unittest.TestCase):
    """Ledgers written by 0.4.0rc5 (schema 1) and 0.5.0rc1 (schema 2) migrate once."""

    def legacy(self, root, *, schema, records, policy=None):
        import os
        from cryptography.fernet import Fernet
        db, key = root / "o/outcomes.sqlite3", root / "k/key"
        for parent in (db.parent, key.parent):
            parent.mkdir(mode=0o700)
        raw = Fernet.generate_key()
        key.write_bytes(raw)
        os.chmod(key, 0o600)
        cipher = Fernet(raw)
        with closing(sqlite3.connect(db)) as connection:
            connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
            connection.execute("INSERT INTO identity VALUES (?)",
                               (cipher.encrypt(b"guard-outcomes-v1" if schema == 1 else b"guard-outcomes-v2"),))
            connection.execute("CREATE TABLE outcomes (id TEXT PRIMARY KEY, record BLOB NOT NULL)")
            for record in records:
                connection.execute("INSERT INTO outcomes VALUES (?, ?)",
                                   (record["id"], cipher.encrypt(json.dumps(record, sort_keys=True).encode())))
            if policy is not None:
                connection.execute("CREATE TABLE meta (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
                connection.execute("INSERT INTO meta VALUES ('policy', ?)", (cipher.encrypt(json.dumps(
                    {"name": "policy", "value": policy}, sort_keys=True).encode()),))
            connection.commit()
        os.chmod(db, 0o600)
        return db, key, cipher

    def identity(self, db, cipher):
        with closing(sqlite3.connect(db)) as connection:
            return cipher.decrypt(connection.execute("SELECT record FROM identity").fetchone()[0])

    def test_rc5_ledger_migrates_and_older_readers_fail_closed(self):
        principal = Principal("t", "p", "a", frozenset({"r"}))
        name, digest = OutcomeLedger.binding(principal, "legacy-request-0001", "r", {})
        with tempfile.TemporaryDirectory() as temp:
            db, key, cipher = self.legacy(Path(temp), schema=1, records=[
                {"id": name, "digest": digest, "state": "completed", "generation": "old",
                 "tenant_hash": hashlib.sha256(b"t").hexdigest()}])
            upgraded = OutcomeLedger(db, key, maximum=10, time_bound=True)
            upgraded.configure_tenants(["t"])
            self.assertEqual(upgraded.begin(principal, "legacy-request-0001", "r", {})[1], "completed")
            # 0.4.0rc5 accepts only v1 and 0.5.0rc1 only v1/v2: both refuse the migrated ledger.
            self.assertEqual(self.identity(db, cipher), b"guard-outcomes-v3")
            self.assertTrue(upgraded.usage()["time_bound"])

    def test_rc1_ledger_keeps_cutoff_archives_and_indexes_records(self):
        principal = Principal("t", "p", "a", frozenset({"r"}))
        issued = int(time.time()) - 10
        request_id = "%010d-%s" % (issued, "x" * 24)
        name, digest = OutcomeLedger.binding(principal, request_id, "r", {})
        tenant_hash = hashlib.sha256(b"t").hexdigest()
        archived = [{"file": "outcomes-0000001000-aaaa.jsonl", "sha256": "0" * 64, "records": 3, "cutoff": 1000}]
        with tempfile.TemporaryDirectory() as temp:
            db, key, cipher = self.legacy(Path(temp), schema=2, records=[
                {"id": name, "digest": digest, "state": "uncertain", "generation": "old", "tenant_hash": tenant_hash,
                 "issued_at": issued}], policy={"time_bound": True, "cutoff": 1000, "archives": archived})
            ledger = OutcomeLedger(db, key, maximum=10, time_bound=True)
            ledger.configure_tenants(["t"])
            self.assertEqual(ledger.usage()["cutoff"], 1000)
            self.assertEqual(ledger.archives(), archived)
            with closing(sqlite3.connect(db)) as connection:
                self.assertEqual(connection.execute("SELECT issued_at, tenant_hash FROM outcomes").fetchall(),
                                 [(issued, tenant_hash)])
            self.assertEqual(ledger.begin(principal, request_id, "r", {})[1], "uncertain")
            self.assertEqual(self.identity(db, cipher), b"guard-outcomes-v3")
            with self.assertRaises(OutcomeError):
                OutcomeLedger(db, key, maximum=10, time_bound=False)


class VaultIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db, self.key = root / "v/vault.sqlite3", root / "k/key"
        self.now = 1000.0
        LocalVault.initialize(self.db, self.key, tenant_limits={"a": 4_000_000, "b": 4_000_000})
        self.vault = LocalVault(self.db, self.key, clock=lambda: self.now, max_entries=50)

    def test_entry_limit_expiry_and_foreign_writer_rebuild(self):
        scope = Scope("a", "p", "w", "o")
        self.vault.put_many(tuple("v%d" % i for i in range(50)), scope, ("d",), ttl=10)
        with self.assertRaises(Exception):
            self.vault.put("over", scope, ("d",))
        self.now += 11
        self.vault.put("fresh", scope, ("d",))
        self.assertEqual(self.vault.usage()["live_entries"], 1)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DELETE FROM entry_index")
        self.assertEqual(self.vault.usage()["live_entries"], 1)

    def test_tenant_reservation_uses_index(self):
        scope = Scope("b", "p", "w", "o")
        token = self.vault.put("x" * 1000, scope, ("d",))
        self.assertEqual(self.vault.restore(token, scope, "d"), "x" * 1000)
        self.assertEqual(self.vault.usage()["live_entries"], 0)
