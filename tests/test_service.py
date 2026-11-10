import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.runtime import GuardRuntime, Principal, Route
from enkstein_guard.service import GuardService, guarded_request

TOKEN = "service-test-" + "a" * 40
OTHER = "service-test-" + "b" * 40


@unittest.skipUnless(os.name == "posix", "Unix service")
class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "guard.sock"
        self.calls = []
        self.events = []
        self.broken = False
        async def control(op):
            if self.broken:
                raise RuntimeError("private-error")
            return ControlResult("policy", op.context.tenant_id, op.context.operation_id, Action.ALLOW)
        async def transport(op):
            self.calls.append(op.context.tenant_id)
            return {"tenant": op.context.tenant_id}
        runtime = GuardRuntime(credentials={
            TOKEN: Principal("a", "user", "agent", frozenset({"read"})),
            OTHER: Principal("b", "user", "agent", frozenset({"read"}))},
            routes=(Route("read", "read", "records", "local", "a", ("policy",), transport),),
            controls={"policy": control}, audit=self.events.append)
        self.service = await GuardService(runtime, self.path).start()
        self.addAsyncCleanup(self.service.close)

    async def test_valid_call_and_private_socket(self):
        result = await guarded_request(self.path, TOKEN, "read", {})
        self.assertEqual(result, {"status": "ok", "result": {"tenant": "a"}})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    async def test_cross_tenant_and_invalid_identity_denied(self):
        for token in (OTHER, "forged"):
            self.assertEqual((await guarded_request(self.path, token, "read", {}))["status"], "denied")
        self.assertEqual(self.calls, [])

    async def test_inspector_outage_blocks_without_leaking(self):
        self.broken = True
        result = await guarded_request(self.path, TOKEN, "read", {})
        self.assertEqual(result["status"], "denied")
        self.assertNotIn("private-error", json.dumps(result))
        self.assertEqual(self.calls, [])

    async def test_concurrent_calls_are_checked_separately(self):
        results = await asyncio.gather(*(guarded_request(self.path, TOKEN, "read", {}) for _ in range(10)))
        self.assertTrue(all(x["status"] == "ok" for x in results))
        self.assertEqual(len(self.calls), 10)
        self.assertEqual(len({x["operation_id"] for x in self.events}), 10)

    async def test_forged_context_and_duplicate_fields_rejected(self):
        for body in (b'{"credential":"a","credential":"b","route":"read","payload":{}}\n',
                     json.dumps({"credential": TOKEN, "route": "read", "payload": {}, "tenant": "a"}).encode()+b"\n"):
            reader, writer = await asyncio.open_unix_connection(str(self.path))
            writer.write(body)
            await writer.drain()
            result = json.loads(await reader.readline())
            writer.close()
            await writer.wait_closed()
            self.assertEqual(result["status"], "invalid_request_or_response")
        self.assertEqual(self.calls, [])

    async def test_shutdown_removes_only_owned_socket(self):
        await self.service.close()
        self.assertFalse(self.path.exists())

    async def test_existing_path_not_overwritten(self):
        with self.assertRaises(ValueError):
            await GuardService(self.service.runtime, self.path).start()

    async def test_stalled_request_times_out_without_execution(self):
        self.service.timeout = 0.02
        reader, writer = await asyncio.open_unix_connection(str(self.path))
        result = json.loads(await reader.readline())
        self.assertEqual(result["status"], "timeout_outcome_unknown")
        writer.close()
        await writer.wait_closed()
        self.assertEqual(self.calls, [])

    async def test_overload_rejects_without_executing(self):
        self.service.maximum = 1
        reader, writer = await asyncio.open_unix_connection(str(self.path))
        for _ in range(20):
            if self.service._active == 1:
                break
            await asyncio.sleep(0)
        response = await guarded_request(self.path, TOKEN, "read", {})
        self.assertEqual(response["status"], "busy")
        self.assertEqual(self.calls, [])
        writer.close()
        await writer.wait_closed()
        await reader.read()

    async def test_oversized_frame_rejected(self):
        self.service.limit = 1024
        result = await guarded_request(self.path, TOKEN, "read", {"text": "x" * 2048})
        self.assertEqual(result["status"], "invalid_request_or_response")
        self.assertEqual(self.calls, [])

    async def test_durable_request_id_prevents_duplicate_execution(self):
        from enkstein_guard.outcomes import OutcomeLedger
        root = Path(self.temp.name)
        self.service.outcomes = OutcomeLedger.initialize(root/"requests.sqlite3",root/"request-key")
        kwargs = {"request_id":"service-unique-request-123"}
        first = await guarded_request(self.path,TOKEN,"read",{},**kwargs)
        second = await guarded_request(self.path,TOKEN,"read",{},**kwargs)
        self.assertEqual(first["status"],"ok")
        self.assertEqual(second["status"],"completed_no_replay")
        self.assertEqual(len(self.calls),1)
        changed = await guarded_request(self.path,TOKEN,"read",{"changed":True},**kwargs)
        self.assertEqual(changed["status"],"request_tracking_unavailable_or_conflict")
        self.assertEqual(len(self.calls),1)

    async def test_tracking_required_before_execution(self):
        from enkstein_guard.outcomes import OutcomeLedger
        root = Path(self.temp.name)
        self.service.outcomes = OutcomeLedger.initialize(root/"requests.sqlite3",root/"request-key")
        response = await guarded_request(self.path,TOKEN,"read",{})
        self.assertEqual(response["status"],"request_tracking_unavailable_or_conflict")
        self.assertEqual(self.calls,[])

    async def test_one_tenant_cannot_exhaust_another_tenants_reserved_ledger_capacity(self):
        from enkstein_guard.outcomes import OutcomeLedger
        from enkstein_guard.runtime import Principal
        root=Path(self.temp.name)
        ledger=OutcomeLedger.initialize(root/"quota.sqlite3",root/"quota-key",maximum=4)
        self.service.outcomes=ledger  # Host registers tenants a and b: two slots each.
        for number in range(2):
            result=await guarded_request(self.path,TOKEN,"read",{},request_id="tenant-a-request-"+str(number))
            self.assertEqual(result["status"],"ok")
        rejected=await guarded_request(self.path,TOKEN,"read",{},request_id="tenant-a-request-overflow")
        self.assertEqual(rejected["status"],"request_tracking_unavailable_or_conflict")
        # Tenant b is independently authorized by its trusted host; its reserved
        # ledger share remains available even though tenant a has exhausted its own.
        principal=Principal("b","other-user","other-agent",frozenset({"other-read"}))
        self.assertEqual(ledger.begin(principal,"tenant-b-request-1","other-read",{})[1],"new")

    async def test_short_read_deadline_reclaims_unauthenticated_slot(self):
        self.service.read_timeout=.02
        reader,writer=await asyncio.open_unix_connection(str(self.path))
        result=json.loads(await reader.readline())
        self.assertEqual(result["status"],"request_read_timeout_no_execution")
        writer.close();await writer.wait_closed()
        await asyncio.sleep(0)
        self.assertEqual((await guarded_request(self.path,TOKEN,"read",{}))["status"],"ok")
