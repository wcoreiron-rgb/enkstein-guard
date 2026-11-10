from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from enkstein_guard.privacy import Tokenizer
from enkstein_guard.vault import LocalVault,Scope,VaultError


class PrivateBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.vault=LocalVault.initialize(root/"data/v.sqlite3",root/"keys/key")
        self.scope=Scope("t","p","w","o")

    def count(self):
        with closing(sqlite3.connect(self.vault.database)) as connection:
            return connection.execute("SELECT count(*) FROM entries").fetchone()[0]

    def test_many_sensitive_values_use_one_atomic_storage_batch(self):
        payload={"people":[{"email":f"person{n}@example.com"} for n in range(128)]}
        with patch.object(self.vault,"put_many",wraps=self.vault.put_many) as batches:
            result=Tokenizer(self.vault).tokenize(payload,self.scope,("sink",))
        self.assertEqual(batches.call_count,1)
        self.assertEqual(self.count(),128)
        for n,item in enumerate(result["people"]):
            self.assertEqual(self.vault.restore(item["email"],self.scope,"sink"),f"person{n}@example.com")

    def test_sensitive_value_count_limit_rejects_before_any_persistent_write(self):
        payload={"people":[{"email":f"person{n}@example.com"} for n in range(129)]}
        with self.assertRaises(VaultError):Tokenizer(self.vault).tokenize(payload,self.scope,("sink",))
        self.assertEqual(self.count(),0)

    def test_late_validation_failure_has_no_partial_token_writes(self):
        with self.assertRaises(VaultError):
            Tokenizer(self.vault).tokenize({"email":"synthetic@example.com","password":123},self.scope,("sink",))
        self.assertEqual(self.count(),0)
