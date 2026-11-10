import asyncio
import unittest

from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.runtime import (
    AccessDenied, GuardError, GuardRuntime, Principal, Route, local_prompt_control,
)

TOKEN = "test-only-credential-" + "a" * 32


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.calls = []
        self.events = []

    async def allow(self, op):
        return ControlResult("policy", op.context.tenant_id, op.context.operation_id, Action.ALLOW)

    async def transport(self, op):
        self.calls.append(op.payload())
        return {"ok": True}

    def runtime(self, control=None, audit=None, tenant="a", grant=True, extra=None):
        controls = {"policy": control or self.allow}
        controls.update(extra or {})
        return GuardRuntime(
            credentials={TOKEN: Principal(tenant, "user", "agent", frozenset({"model"}) if grant else frozenset())},
            routes=(Route("model", "model.call", "test-model", "fake", "a", tuple(controls), self.transport),),
            controls=controls, audit=self.events.append if audit is None else audit,
            control_timeout=0.02,
        )

    async def test_allowed_call_has_separate_decision_and_completion(self):
        self.assertEqual(await self.runtime().execute(TOKEN, "model", {"text": "hello"}), {"ok": True})
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([e["outcome"] for e in self.events], ["authorized", "transport_completed"])

    async def test_invalid_credentials_do_not_execute(self):
        with self.assertRaises(AccessDenied):
            await self.runtime().execute("invalid", "model", {})
        self.assertEqual(self.calls, [])

    async def test_cross_tenant_denied(self):
        with self.assertRaises(AccessDenied):
            await self.runtime(tenant="other").execute(TOKEN, "model", {})
        self.assertEqual(self.calls, [])

    async def test_missing_grant_and_unknown_route_denied(self):
        for runtime, name in ((self.runtime(grant=False), "model"), (self.runtime(), "other")):
            with self.assertRaises(AccessDenied):
                await runtime.execute(TOKEN, name, {})
        self.assertEqual(self.calls, [])

    async def test_deny_approval_and_mask_never_execute(self):
        for action in (Action.DENY, Action.REQUIRE_APPROVAL, Action.MASK):
            async def control(op):
                return ControlResult("policy", op.context.tenant_id, op.context.operation_id, action)
            with self.assertRaises(AccessDenied):
                await self.runtime(control).execute(TOKEN, "model", {})
        self.assertEqual(self.calls, [])

    async def test_control_exception_denied_without_leaking(self):
        async def broken(op):
            raise RuntimeError("sensitive-error-text")
        with self.assertRaises(AccessDenied) as caught:
            await self.runtime(broken).execute(TOKEN, "model", {})
        self.assertNotIn("sensitive-error-text", str(caught.exception) + str(self.events))
        self.assertEqual(self.calls, [])

    async def test_control_timeout_denied(self):
        async def slow(op):
            await asyncio.sleep(1)
        with self.assertRaises(AccessDenied):
            await self.runtime(slow).execute(TOKEN, "model", {})
        self.assertEqual(self.calls, [])

    async def test_control_cannot_impersonate_another_control(self):
        async def forged(op):
            return ControlResult("other", op.context.tenant_id, op.context.operation_id, Action.ALLOW)
        with self.assertRaises(AccessDenied):
            await self.runtime(forged).execute(TOKEN, "model", {})
        self.assertEqual(self.calls, [])

    async def test_cached_allow_cannot_replay(self):
        cache = []
        async def cached(op):
            if not cache:
                cache.append(await self.allow(op))
            return cache[0]
        runtime = self.runtime(cached)
        await runtime.execute(TOKEN, "model", {"text": "first"})
        with self.assertRaises(AccessDenied):
            await runtime.execute(TOKEN, "model", {"text": "changed"})
        self.assertEqual(len(self.calls), 1)

    async def test_inspector_cannot_modify_transport_payload(self):
        payload = {"nested": {"value": "original"}}
        async def mutate(op):
            op.payload()["nested"]["value"] = "changed"
            payload["nested"]["value"] = "caller-change"
            return await self.allow(op)
        await self.runtime(mutate).execute(TOKEN, "model", payload)
        self.assertEqual(self.calls, [{"nested": {"value": "original"}}])

    async def test_audit_outage_prevents_side_effect(self):
        def broken(event):
            raise OSError("secret-location")
        with self.assertRaisesRegex(GuardError, "audit_unavailable"):
            await self.runtime(audit=broken).execute(TOKEN, "model", {})
        self.assertEqual(self.calls, [])

    async def test_payload_is_not_in_audit(self):
        await self.runtime().execute(TOKEN, "model", {"text": "sensitive-content"})
        self.assertNotIn("sensitive-content", str(self.events))
        self.assertNotIn(TOKEN, str(self.events))

    async def test_transport_exception_has_unknown_outcome(self):
        async def broken(op):
            raise RuntimeError("private-provider-error")
        self.transport = broken
        with self.assertRaisesRegex(GuardError, "outcome_unknown") as caught:
            await self.runtime().execute(TOKEN, "model", {})
        self.assertNotIn("private-provider-error", str(caught.exception))
        self.assertEqual(self.events[-1]["outcome"], "execution_failed_outcome_unknown")

    async def test_local_scanner_blocks_before_model(self):
        with self.assertRaises(AccessDenied):
            await self.runtime(extra={"local_prompt": local_prompt_control}).execute(
                TOKEN, "model", {"text": "-----BEGIN PRIVATE KEY-----"})
        self.assertEqual(self.calls, [])

    async def test_missing_required_control_rejected_at_startup(self):
        with self.assertRaisesRegex(ValueError, "required_control_unavailable"):
            GuardRuntime(credentials={}, routes=(Route("model", "model.call", "r", "d", "a", ("missing",), self.transport),),
                         controls={}, audit=self.events.append)

    async def test_non_json_payload_rejected(self):
        for payload in ({"bad": float("nan")}, {"bad": object()}, ["not-object"]):
            with self.assertRaises(AccessDenied):
                await self.runtime().execute(TOKEN, "model", payload)
        self.assertEqual(self.calls, [])

    async def test_completion_audit_failure_does_not_imply_no_execution(self):
        count = 0
        def audit(event):
            nonlocal count
            count += 1
            if count > 1:
                raise OSError("audit failed")
        with self.assertRaisesRegex(GuardError, "execution_completed_audit_unavailable"):
            await self.runtime(audit=audit).execute(TOKEN, "model", {})
        self.assertEqual(len(self.calls), 1)

    async def test_changed_request_is_reinspected(self):
        async def policy(op):
            action = Action.ALLOW if op.payload().get("approved") is True else Action.DENY
            return ControlResult("policy", op.context.tenant_id, op.context.operation_id, action)
        runtime = self.runtime(policy)
        await runtime.execute(TOKEN, "model", {"approved": True})
        with self.assertRaises(AccessDenied):
            await runtime.execute(TOKEN, "model", {"approved": False})
        self.assertEqual(len(self.calls), 1)

    async def test_async_callable_audit_is_not_silently_accepted(self):
        class AsyncAudit:
            async def __call__(self,event):pass
        with self.assertRaises(GuardError):
            await self.runtime(audit=AsyncAudit()).execute(TOKEN,'model',{})
        self.assertEqual(self.calls,[])
