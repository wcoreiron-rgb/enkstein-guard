import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing

from enkstein_guard.vault import LocalVault, Scope, VaultError


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db, self.key = self.root/'data/vault.db', self.root/'keys/keyring.json'
        self.vault = LocalVault.initialize(self.db, self.key)
        self.scope = Scope("tenant", "user", "workflow", "operation")

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, value="sensitive-value", ttl=300):
        return self.vault.put(value, self.scope, ("approved-sink",), ttl=ttl)

    def test_storage_contains_no_plaintext(self):
        token = self.put()
        self.assertNotIn(b"sensitive-value", self.db.read_bytes())
        self.assertEqual(self.vault.restore(token, self.scope, "approved-sink"), "sensitive-value")

    def test_restart_and_rotation_preserve_records(self):
        token = self.put()
        self.vault.rotate()
        reopened = LocalVault(self.db, self.key)
        self.assertEqual(reopened.restore(token, self.scope, "approved-sink"), "sensitive-value")
        self.assertEqual(len(json.loads(self.key.read_text())), 2)

    def test_missing_key_not_regenerated(self):
        self.key.unlink()
        with self.assertRaises((VaultError, FileNotFoundError)):
            LocalVault(self.db, self.key)
        self.assertFalse(self.key.exists())

    def test_wrong_key_rejected_without_overwrite(self):
        from cryptography.fernet import Fernet
        self.key.write_text(json.dumps([Fernet.generate_key().decode()]))
        before = self.key.read_bytes()
        with self.assertRaises(VaultError):
            LocalVault(self.db, self.key)
        self.assertEqual(self.key.read_bytes(), before)

    def test_active_vault_rejects_replaced_wrong_key_before_write(self):
        from cryptography.fernet import Fernet
        self.key.write_text(json.dumps([Fernet.generate_key().decode()]))
        with self.assertRaises(VaultError):
            self.put()

    def test_scope_and_destination_denial(self):
        token = self.put()
        for scope, destination in [(Scope("other", "user", "workflow", "operation"), "approved-sink"),
                                   (Scope("tenant", "other", "workflow", "operation"), "approved-sink"),
                                   (Scope("tenant", "user", "workflow", "other"), "approved-sink"),
                                   (self.scope, "model-provider")]:
            with self.assertRaises(VaultError):
                self.vault.restore(token, scope, destination)
        self.assertEqual(self.vault.restore(token, self.scope, "approved-sink"), "sensitive-value")

    def test_consumed_token_replay_denied(self):
        token = self.put()
        self.vault.restore(token, self.scope, "approved-sink")
        with self.assertRaises(VaultError):
            self.vault.restore(token, self.scope, "approved-sink")

    def test_expired_record_denied(self):
        self.vault._clock = lambda: 100
        token = self.put(ttl=1)
        self.vault._clock = lambda: 102
        with self.assertRaises(VaultError):
            self.vault.restore(token, self.scope, "approved-sink")

    def test_ciphertext_tampering_denied(self):
        token = self.put()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE entries SET ciphertext=?", (b"corrupt",))
        with self.assertRaises(VaultError):
            self.vault.restore(token, self.scope, "approved-sink")

    def test_record_swapping_denied(self):
        first, second = self.put("first"), self.put("second")
        with closing(sqlite3.connect(self.db)) as db, db:
            data = db.execute("SELECT ciphertext FROM entries WHERE token=?", (first,)).fetchone()[0]
            db.execute("UPDATE entries SET ciphertext=? WHERE token=?", (data, second))
        with self.assertRaises(VaultError):
            self.vault.restore(second, self.scope, "approved-sink")

    def test_atomic_restore_does_not_consume_on_partial_failure(self):
        token = self.put()
        with self.assertRaises(VaultError):
            self.vault.restore(token + " [[EGV:" + "a"*64 + "]]", self.scope, "approved-sink")
        self.assertEqual(self.vault.restore(token, self.scope, "approved-sink"), "sensitive-value")

    def test_scope_revocation(self):
        token = self.put()
        self.assertEqual(self.vault.revoke_scope(self.scope), 1)
        with self.assertRaises(VaultError):
            self.vault.restore(token, self.scope, "approved-sink")

    def test_reinitialize_rejected(self):
        with self.assertRaises(VaultError):
            LocalVault.initialize(self.db, self.key)

    def test_purge_expired(self):
        self.vault._clock = lambda: 100
        self.put(ttl=1)
        self.vault._clock = lambda: 102
        self.assertEqual(self.vault.purge_expired(), 1)

    def test_reference_expansion_bounded_without_consuming_token(self):
        token = self.put("s"*10000)
        with self.assertRaises(VaultError):
            self.vault.restore(token*200, self.scope, "approved-sink")
        self.assertEqual(self.vault.restore(token, self.scope, "approved-sink"), "s"*10000)

    @unittest.skipUnless(os.name == "posix", "POSIX mode test")
    def test_permissive_key_and_symlink_rejected(self):
        os.chmod(self.key, 0o644)
        with self.assertRaises(VaultError):
            LocalVault(self.db, self.key)
        os.chmod(self.key, 0o600)
        link = self.key.parent/'link'; link.symlink_to(self.key)
        with self.assertRaises(VaultError):
            LocalVault(self.db, link)

    def test_expired_entries_collected_on_write_and_tenant_storage_reserved(self):
        import sqlite3
        import tempfile
        from pathlib import Path
        from enkstein_guard.vault import LocalVault,Scope,VaultError
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            vault=LocalVault.initialize(root/"data/v.sqlite3",root/"keys/key",max_bytes=2_097_152,
                                        tenant_limits={"a":1000,"b":1000})
            now=[100.0]
            vault._clock=lambda:now[0]
            a=Scope("a","p","w","o")
            b=Scope("b","p","w","o")
            vault.put("x"*100,a,("sink",),ttl=1)
            with self.assertRaises(VaultError):vault.put("y"*500,a,("sink",))
            token=vault.put("safe",b,("sink",))
            self.assertEqual(vault.restore(token,b,"sink",consume=False),"safe")
            now[0]=102
            vault.put("replacement",a,("sink",))
            with closing(sqlite3.connect(vault.database)) as connection, connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM entries").fetchone()[0],2)
