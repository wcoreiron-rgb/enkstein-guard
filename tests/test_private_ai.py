from contextlib import closing
import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.engines import local_inspection
from enkstein_guard.private_ai import PrivateAI
from enkstein_guard.runtime import AccessDenied, GuardError, Principal
from enkstein_guard.vault import LocalVault

TOKEN = "private-test-" + "a"*40
OTHER = "private-test-" + "b"*40


class PrivateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.vault = LocalVault.initialize(root/'data/vault.db', root/'keys/key.json')
        self.captured, self.events, self.sinks, self.inspected = [], [], [], []

    def tearDown(self):
        self.tmp.cleanup()

    async def policy(self, op):
        self.inspected.append(op.payload_json)
        return ControlResult("policy", op.context.tenant_id, op.context.operation_id, Action.ALLOW)

    async def model(self, op):
        self.captured.append(op.payload_json)
        return op.payload()

    async def sink(self, content):
        self.sinks.append(content)
        return "delivered"

    def runtime(self, model=None, controls=None, output=None, grant=True, **kwargs):
        return PrivateAI(
            vault=self.vault, tenant_id="tenant", model=model or self.model,
            credentials={TOKEN: Principal("tenant", "user", "agent", frozenset({"model", "sink:human"}) if grant else frozenset({"model"})),
                         OTHER: Principal("tenant", "other-user", "agent", frozenset({"model", "sink:human"}))},
            sinks={"human": self.sink}, input_controls=controls or {"policy": self.policy, "local": local_inspection},
            output_controls=output or {"policy": self.policy}, audit=self.events.append, control_timeout=.02,
            **kwargs,
        )

    async def test_secrets_and_pii_never_reach_model_engines_or_audit(self):
        runtime = self.runtime()
        data = {"messages": [{"role": "user", "content": 'Email jane@example.com. SSN 123-45-6789. Key AKIA3ZK7QWERTYUIOPAS'}],
                "password": 'secret-quote"with\\slash', "name": "Jane Customer"}
        reply = await runtime.generate(TOKEN, data)
        for value in ["jane@example.com", "123-45-6789", "AKIA3ZK7QWERTYUIOPAS", data["password"], data["name"]]:
            self.assertNotIn(value, str(self.captured)+str(self.inspected)+str(self.events)+repr(reply))
            self.assertNotIn(value.encode(), self.vault.database.read_bytes())
        self.assertEqual(await runtime.restore_to(TOKEN, reply.receipt, "human"), "delivered")
        self.assertEqual(self.sinks, [data])

    async def test_provider_output_sensitive_data_tokenized_before_inspection(self):
        async def provider(op):
            return {"answer": "Contact newperson@example.com"}
        runtime = self.runtime(model=provider)
        reply = await runtime.generate(TOKEN, {"prompt": "hello"})
        self.assertNotIn("newperson@example.com", str(reply.content)+str(self.inspected))
        await runtime.restore_to(TOKEN, reply.receipt, "human")
        self.assertEqual(self.sinks[0]["answer"], "Contact newperson@example.com")

    async def test_wrong_principal_cannot_restore(self):
        runtime = self.runtime()
        reply = await runtime.generate(TOKEN, {"email": "jane@example.com"})
        with self.assertRaises(AccessDenied):
            await runtime.restore_to(OTHER, reply.receipt, "human")
        self.assertEqual(self.sinks, [])
        await runtime.restore_to(TOKEN, reply.receipt, "human")

    async def test_missing_sink_permission_denies(self):
        runtime = self.runtime(grant=False)
        reply = await runtime.generate(TOKEN, {"email": "jane@example.com"})
        with self.assertRaises(AccessDenied):
            await runtime.restore_to(TOKEN, reply.receipt, "human")
        self.assertEqual(self.sinks, [])

    async def test_unregistered_destination_denied(self):
        runtime = self.runtime()
        reply = await runtime.generate(TOKEN, {"prompt": "hello"})
        with self.assertRaises(AccessDenied):
            await runtime.restore_to(TOKEN, reply.receipt, "model-provider")

    async def test_input_engine_outage_blocks_model(self):
        async def failed(op):
            raise RuntimeError("private-error")
        with self.assertRaises(AccessDenied):
            await self.runtime(controls={"policy": failed}).generate(TOKEN, {"email": "jane@example.com"})
        self.assertEqual(self.captured, [])

    async def test_engine_timeout_blocks_model(self):
        async def slow(op):
            await asyncio.sleep(1)
        with self.assertRaises(AccessDenied):
            await self.runtime(controls={"policy": slow}).generate(TOKEN, {"prompt": "hello"})
        self.assertEqual(self.captured, [])

    async def test_output_denial_releases_no_reply(self):
        async def denied(op):
            return ControlResult("policy", op.context.tenant_id, op.context.operation_id, Action.DENY)
        with self.assertRaises(GuardError):
            await self.runtime(output={"policy": denied}).generate(TOKEN, {"email": "jane@example.com"})
        self.assertEqual(len(self.captured), 1)
        self.assertEqual(self.sinks, [])

    async def test_reserved_or_forged_reference_blocks(self):
        runtime = self.runtime()
        for value in ("[[EGV:bad]]", "[[EGV:"+"a"*64+"]]"):
            with self.assertRaises(AccessDenied):
                await runtime.generate(TOKEN, {"prompt": value})
        self.assertEqual(self.captured, [])

    async def test_forged_output_reference_is_not_released(self):
        async def provider(op):
            return {"answer": "[[EGV:"+"a"*64+"]]"}
        with self.assertRaises(GuardError):
            await self.runtime(model=provider).generate(TOKEN, {"prompt": "hi"})

    async def test_streaming_and_binary_parts_block(self):
        for payload in ({"stream": True}, {"messages": [{"image_url": "https://example.com/private"}]}):
            with self.assertRaises(AccessDenied):
                await self.runtime().generate(TOKEN, payload)
        self.assertEqual(self.captured, [])

    async def test_receipt_replay_and_concurrency(self):
        runtime = self.runtime()
        reply = await runtime.generate(TOKEN, {"email": "jane@example.com"})
        results = await asyncio.gather(*(runtime.restore_to(TOKEN, reply.receipt, "human") for _ in range(2)), return_exceptions=True)
        self.assertEqual(sum(value == "delivered" for value in results), 1)
        self.assertEqual(len(self.sinks), 1)

    async def test_caller_mutating_reply_cannot_change_sink_payload(self):
        runtime = self.runtime()
        reply = await runtime.generate(TOKEN, {"email": "jane@example.com"})
        reply.content["email"] = "attacker@example.com"
        await runtime.restore_to(TOKEN, reply.receipt, "human")
        self.assertEqual(self.sinks[0], {"email": "jane@example.com"})

    async def test_input_verdict_cannot_be_replayed_for_output(self):
        cached = []
        async def control(op):
            if not cached:
                cached.append(ControlResult("policy", op.context.tenant_id, op.context.operation_id, Action.ALLOW))
            return cached[0]
        with self.assertRaises(GuardError):
            await self.runtime(controls={"policy": control}, output={"policy": control}).generate(TOKEN, {"prompt": "hi"})

    async def test_complete_private_key_block_never_reaches_model(self):
        key = "-----BEGIN PRIVATE KEY-----\nMII" + "a"*60 + "\n-----END PRIVATE KEY-----"
        runtime = self.runtime()
        reply = await runtime.generate(TOKEN, {"prompt": key})
        self.assertNotIn("MII"+"a"*60, str(self.captured)+str(self.inspected))
        await runtime.restore_to(TOKEN, reply.receipt, "human")
        self.assertEqual(self.sinks, [{"prompt": key}])

    async def test_sensitive_numeric_field_blocks_instead_of_changing_type(self):
        with self.assertRaises(AccessDenied):
            await self.runtime().generate(TOKEN, {"ssn": 123456789})
        self.assertEqual(self.captured, [])

    async def test_vault_key_loss_blocks_before_model(self):
        self.vault.key_file.unlink()
        with self.assertRaises(AccessDenied):
            await self.runtime().generate(TOKEN, {"email": "jane@example.com"})
        self.assertEqual(self.captured, [])

    async def test_pending_reply_limit_blocks_then_releases_after_sink(self):
        runtime = self.runtime(max_pending_replies=1)
        reply = await runtime.generate(TOKEN, {"prompt": "hello"})
        with self.assertRaisesRegex(AccessDenied, "pending_reply_limit"):
            await runtime.generate(TOKEN, {"prompt": "second"})
        self.assertEqual(len(self.captured), 1)
        await runtime.restore_to(TOKEN, reply.receipt, "human")
        await runtime.generate(TOKEN, {"prompt": "third"})
        self.assertEqual(len(self.captured), 2)

    async def test_model_cannot_be_registered_as_restoration_destination(self):
        with self.assertRaisesRegex(ValueError, "restoration_to_model_forbidden"):
            self.runtime(model_destination="human")

    async def test_denied_private_requests_do_not_accumulate_vault_entries(self):
        import sqlite3
        async def deny(op):
            from enkstein_guard.contracts import ControlResult, Action
            return ControlResult("deny",op.context.tenant_id,op.context.operation_id,Action.DENY)
        runtime=self.runtime(controls={"deny":deny})
        for number in range(5):
            with self.assertRaises(GuardError):
                await runtime.generate(TOKEN,{"password":"synthetic-secret-"+str(number)})
        with closing(sqlite3.connect(self.vault.database)) as connection, connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM entries").fetchone()[0],0)
        self.assertEqual(self.captured,[])

    async def test_cleanup_failure_after_model_call_preserves_unknown_outcome(self):
        calls=[]
        async def model(op):
            calls.append(True)
            self.vault.key_file.unlink()
            return {"answer":"synthetic result"}
        async def deny(op):
            return ControlResult("deny",op.context.tenant_id,op.context.operation_id,Action.DENY)
        runtime=self.runtime(model=model,output={"deny":deny})
        with self.assertRaisesRegex(GuardError,"outcome_unknown") as raised:
            await runtime.generate(TOKEN,{"email":"synthetic@example.com"})
        self.assertNotIsInstance(raised.exception,AccessDenied)
        self.assertEqual(calls,[True])
        self.assertEqual(runtime._receipts,{})
