from contextlib import closing
import asyncio
from pathlib import Path
import sqlite3
import tempfile
import unittest
from enkstein_guard.outcomes import OutcomeLedger, OutcomeError
from enkstein_guard.runtime import Principal


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name)/"outcomes.sqlite3"
        self.key = Path(self.temp.name)/"key"
        self.ledger = OutcomeLedger.initialize(self.db, self.key, maximum=2)
        self.ledger.configure_tenants(("tenant-a","tenant-b"))
        self.principal = Principal("tenant-a", "principal", "agent", frozenset({"read"}))
        self.request = "unique-request-123456789"

    def begin(self, **kwargs):
        return self.ledger.begin(kwargs.get("principal", self.principal), self.request, "read", kwargs.get("payload", {"email":"secret@example.com"}))

    def test_duplicate_completed_never_reexecutes(self):
        name, state = self.begin()
        self.assertEqual(state,"new")
        self.assertEqual(self.begin()[1],"executing")
        self.ledger.finish(name,"completed")
        self.assertEqual(self.begin()[1],"completed")
        restarted = OutcomeLedger(self.db,self.key)
        self.assertEqual(restarted.begin(self.principal,self.request,"read",{"email":"secret@example.com"})[1],"completed")
        self.assertNotIn(b"secret@example.com",self.db.read_bytes())

    def test_crash_during_execution_becomes_uncertain(self):
        self.begin()
        self.ledger = OutcomeLedger(self.db,self.key)
        self.assertEqual(self.begin()[1],"uncertain")

    def test_payload_substitution_denied(self):
        self.begin()
        with self.assertRaises(OutcomeError):
            self.begin(payload={"delete":True})

    def test_scope_and_capacity(self):
        self.begin()
        other = Principal("tenant-b","principal","agent",frozenset({"read"}))
        self.assertEqual(self.begin(principal=other)[1],"new")
        with self.assertRaises(OutcomeError):
            self.ledger.begin(self.principal,"another-unique-request","read",{})

    def test_tampered_record_and_wrong_key_fail_closed(self):
        self.begin()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE outcomes SET record=?",(b"tampered",))
        with self.assertRaises(OutcomeError):
            self.begin()
        from cryptography.fernet import Fernet
        self.key.write_bytes(Fernet.generate_key())
        with self.assertRaises(OutcomeError):
            OutcomeLedger(self.db,self.key)

    def test_no_reinitialization_or_unowned_completion(self):
        name,_ = self.begin()
        with self.assertRaises(OutcomeError):
            OutcomeLedger.initialize(self.db,self.key)
        newer = OutcomeLedger(self.db,self.key)
        with self.assertRaises(OutcomeError):
            self.ledger.finish(name,"completed")
