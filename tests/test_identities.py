import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from enkstein_guard.contracts import SecurityContext
from enkstein_guard.identities import IdentityError, IdentityStore, SecretBroker, SecretStore, read_secret_input
from enkstein_guard.runtime import AccessDenied, Operation


class IdentityStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path, self.key = self.root / "state/identities.json", self.root / "keys/identities.key"
        self.store = IdentityStore.initialize(self.path, self.key)

    def test_issue_writes_private_file_and_stores_digest_only(self):
        result = self.store.issue("agent", "agent-a", self.root / "agent-a.token")
        token = (self.root / "agent-a.token").read_text().strip()
        self.assertEqual((self.root / "agent-a.token").stat().st_mode & 0o777, 0o600)
        self.assertGreaterEqual(len(token), 32)
        self.assertNotIn(token, self.path.read_text())
        self.assertNotIn(token, json.dumps(result))
        self.assertEqual(self.store.digests("agent")["agent-a"], hashlib.sha256(token.encode()).digest())

    def test_output_never_overwritten(self):
        target = self.root / "existing"
        target.write_text("keep")
        with self.assertRaises(IdentityError):
            self.store.issue("agent", "agent-a", target)
        self.assertEqual(target.read_text(), "keep")
        self.assertNotIn("agent-a", self.store.digests("agent"))

    def test_rotation_and_revocation(self):
        self.store.issue("agent", "agent-a", self.root / "one")
        first = self.store.digests("agent")["agent-a"]
        self.store.issue("agent", "agent-a", self.root / "two")
        self.assertNotEqual(self.store.digests("agent")["agent-a"], first)
        self.assertEqual(self.store.listing()["agent"]["agent-a"]["generation"], 2)
        self.store.revoke("agent", "agent-a")
        self.assertNotIn("agent-a", self.store.digests("agent"))
        self.assertTrue(self.store.listing()["agent"]["agent-a"]["revoked"])
        with self.assertRaises(IdentityError):
            self.store.revoke("approver", "nobody")

    def test_tampering_detected(self):
        self.store.issue("agent", "agent-a", self.root / "token")
        data = json.loads(self.path.read_text())
        data["body"]["agent"]["agent-a"]["revoked_at"] = None
        data["body"]["agent"]["intruder"] = dict(data["body"]["agent"]["agent-a"])
        self.path.write_text(json.dumps(data))
        os.chmod(self.path, 0o600)
        with self.assertRaises(IdentityError):
            IdentityStore(self.path, self.key)

    def test_invalid_names(self):
        for name in ("", "../x", "a" * 65, "spaced name"):
            with self.assertRaises(IdentityError):
                self.store.issue("agent", name, self.root / ("t" + str(len(name))))


class SecretInputTests(unittest.TestCase):
    def test_private_file_and_stdin_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secret"
            path.write_text("value-123\n")
            path.chmod(0o644)
            with self.assertRaises(IdentityError):
                read_secret_input(str(path))
            path.chmod(0o600)
            self.assertEqual(read_secret_input(str(path)), "value-123")
        self.assertEqual(read_secret_input("-", stdin=io.StringIO("from-stdin\n")), "from-stdin")
        for bad in ("", "\n", "two\nlines\n"):
            with self.assertRaises(IdentityError):
                read_secret_input("-", stdin=io.StringIO(bad))


class SecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db = root / "state/secrets.sqlite3"
        self.store = SecretStore.initialize(self.db, root / "keys/secrets.key")
        self.store.set("hatz-key", "synthetic-provider-secret-value", tenant="tenant-a", destination="api.example.test",
                       routes=["model.chat"])

    def test_encrypted_bound_and_listing_secret_free(self):
        self.assertNotIn(b"synthetic-provider-secret-value", self.db.read_bytes())
        self.assertNotIn("synthetic-provider-secret-value", json.dumps(self.store.listing()))
        self.assertEqual(self.store.resolve("hatz-key", tenant="tenant-a", route="model.chat",
                                            destination="api.example.test"), "synthetic-provider-secret-value")
        for kwargs in ({"tenant": "tenant-b", "route": "model.chat", "destination": "api.example.test"},
                       {"tenant": "tenant-a", "route": "other", "destination": "api.example.test"},
                       {"tenant": "tenant-a", "route": "model.chat", "destination": "evil.test"}):
            with self.assertRaises(IdentityError):
                self.store.resolve("hatz-key", **kwargs)
        with self.assertRaises(IdentityError):
            self.store.set("hatz-key", "x", tenant="tenant-a", destination="d", routes=["r"])

    def test_broker_maps_failures_without_detail(self):
        broker = SecretBroker(self.store)
        context = SecurityContext("tenant-a", "p", "a", "w", "o", "op", "v")
        operation = Operation(context, "model.chat", "m", "api.example.test", "{}", "d")

        async def connector(secret, payload):
            raise RuntimeError("upstream said " + secret)

        with self.assertRaises(AccessDenied) as caught:
            asyncio.run(broker.invoke("hatz-key", operation, connector))
        self.assertNotIn("synthetic", str(caught.exception))
        wrong = Operation(context, "model.chat", "m", "evil.test", "{}", "d")

        async def ok(secret, payload):
            return {"ok": True}

        with self.assertRaises(AccessDenied):
            asyncio.run(broker.invoke("hatz-key", wrong, ok))
        self.assertEqual(asyncio.run(broker.invoke("hatz-key", operation, ok)), {"ok": True})
