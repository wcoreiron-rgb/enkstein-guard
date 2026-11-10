from pathlib import Path
import tempfile
import unittest

from enkstein_guard.broker import CredentialBroker
from enkstein_guard.contracts import SecurityContext
from enkstein_guard.runtime import AccessDenied, Operation
from enkstein_guard.vault import LocalVault


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    async def test_scoped_delivery_and_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = LocalVault.initialize(root/'data/vault.db', root/'keys/key.json')
            broker = CredentialBroker(vault)
            broker.register("service", "connector-secret", tenant="t", principal="p", route="send", destination="approved")
            op = Operation(SecurityContext("t", "p", "a", "w", "o", "tool.call", "v"),
                           "send", "r", "approved", '{"value":"safe"}', "digest")
            captured = []
            async def connector(secret, payload):
                captured.append((secret, payload)); return "sent"
            self.assertEqual(await broker.invoke("service", op, connector), "sent")
            self.assertEqual(captured, [("connector-secret", {"value": "safe"})])
            self.assertNotIn(b"connector-secret", vault.database.read_bytes())
            vault.rotate()
            broker = CredentialBroker(LocalVault(vault.database, vault.key_file))
            broker.load("service", tenant="t", principal="p")
            self.assertEqual(await broker.invoke("service", op, connector), "sent")
            wrong = Operation(SecurityContext("other", "p", "a", "w", "o", "tool.call", "v"),
                              "send", "r", "approved", '{}', "digest")
            with self.assertRaises(AccessDenied):
                await broker.invoke("service", wrong, connector)
            broker.revoke("service")
            with self.assertRaises(AccessDenied):
                await broker.invoke("service", op, connector)
            self.assertEqual(len(captured), 2)
