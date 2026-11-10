from contextlib import closing
import concurrent.futures
import sqlite3
import tempfile
import unittest
from pathlib import Path
from enkstein_guard.audit import DurableAudit, AuditError


class DurableAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db, self.key = self.root / "audit.sqlite3", self.root / "key"
        self.audit = DurableAudit.initialize(self.db, self.key)

    def test_restart_encryption_and_checkpoint(self):
        self.audit({"outcome": "allowed", "tenant_id": "private-tenant-example"})
        checkpoint = self.audit.verify()
        self.assertEqual(checkpoint["sequence"], 1)
        self.assertNotIn(b"private-tenant-example", self.db.read_bytes())
        self.assertEqual(DurableAudit(self.db, self.key).verify(checkpoint), checkpoint)
        with self.assertRaises(AuditError):
            DurableAudit.initialize(self.db, self.key)

    def test_corruption_blocks_new_records(self):
        self.audit({"outcome": "allow"})
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE events SET record = ?", (b"corrupt",))
        with self.assertRaises(AuditError):
            self.audit({"outcome": "allow"})
        with self.assertRaises(AuditError):
            DurableAudit(self.db, self.key)

    def test_checkpoint_detects_suffix_deletion(self):
        self.audit({"outcome": "first"})
        self.audit({"outcome": "second"})
        checkpoint = self.audit.verify()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DELETE FROM events WHERE sequence=2")
        with self.assertRaises(AuditError):
            self.audit.verify(checkpoint)

    def test_concurrent_writers_serialize(self):
        other = DurableAudit(self.db, self.key)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda n: (self.audit if n % 2 else other)({"outcome": str(n)}), range(20)))
        self.assertEqual(self.audit.verify()["sequence"], 20)

    def test_invalid_event_and_unsafe_permissions(self):
        for event in ({"value": float("nan")}, {"value": "x" * 17000}, []):
            with self.assertRaises(AuditError):
                self.audit(event)
        self.assertEqual(self.audit.verify()["sequence"], 0)
        self.key.chmod(0o644)
        with self.assertRaises(Exception):
            DurableAudit(self.db, self.key)

    def test_key_replacement_blocks_active_writer_and_wrong_key_restart(self):
        from cryptography.fernet import Fernet
        self.key.write_bytes(Fernet.generate_key())
        with self.assertRaises(AuditError):
            self.audit({"outcome": "allowed"})
        with self.assertRaises(AuditError):
            DurableAudit(self.db, self.key)
