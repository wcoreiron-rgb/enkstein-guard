"""Offline proof: fixture email is vaulted, then restored only at an approved sink."""

import asyncio
from pathlib import Path
import secrets
import tempfile

from enkstein_guard.engines import local_inspection
from enkstein_guard.private_ai import PrivateAI
from enkstein_guard.runtime import Principal
from enkstein_guard.vault import LocalVault


async def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        vault = LocalVault.initialize(root/'data/vault.db', root/'keys/keyring.json')
        calls, deliveries, events = [], [], []
        credential = secrets.token_urlsafe(32)
        async def fake_model(operation):
            calls.append(operation.payload_json)
            return operation.payload()
        async def approved_sink(content):
            deliveries.append(content)
            return "delivered"
        runtime = PrivateAI(
            vault=vault, tenant_id="demo",
            credentials={credential: Principal("demo", "user", "agent", frozenset({"model", "sink:human"}))},
            model=fake_model, sinks={"human": approved_sink},
            input_controls={"local": local_inspection}, output_controls={"local": local_inspection}, audit=events.append,
        )
        payload = {"messages": [{"role": "user", "content": "Email jane@example.com"}]}
        reply = await runtime.generate(credential, payload)
        assert "jane@example.com" not in str(calls) + str(events) + str(reply.content)
        await runtime.restore_to(credential, reply.receipt, "human")
        assert deliveries == [payload]
        print("Vault replacement, private model inspection and authorized restoration passed.")


if __name__ == "__main__":
    asyncio.run(main())
