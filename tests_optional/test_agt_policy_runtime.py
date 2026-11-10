from contextlib import contextmanager
import importlib.metadata
import inspect
import json
import math
import socket
import unittest
from unittest import mock

from agent_control_plane.policy_engine import PolicyEngine

from enkstein_guard.agt_policy import AGTPolicyError, build_policy_control
from enkstein_guard.contracts import Action, ControlResult, SecurityContext
from enkstein_guard.runtime import (
    AccessDenied,
    GuardRuntime,
    Operation,
    Principal,
    Route,
)


@contextmanager
def outbound_sockets_forbidden():
    message = "outbound I/O is forbidden in AGT policy runtime tests"
    with mock.patch.object(socket, "socket", side_effect=AssertionError(message)), \
            mock.patch.object(socket, "create_connection", side_effect=AssertionError(message)):
        yield


class AGTPolicyRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.agents = [{
            "id": "agent-a",
            "tenant": "tenant-a",
            "principal": "principal-a",
            "routes": ["orders.read"],
        }]
        self.routes = [{
            "name": "orders.read",
            "tenant": "tenant-a",
            "operation": "records.read",
            "policy_engine": "orders-policy",
        }]
        self.definition = {
            "name": "orders-policy",
            "kind": "agt",
            "tenant": "tenant-a",
            "bindings": [{
                "agent": "agent-a",
                "route": "orders.read",
                "conditions": [
                    {"field": "approved", "operator": "eq", "value": True},
                    {"field": "order.amount", "operator": "lte", "value": 100},
                    {"field": "order.risk", "operator": "gte", "value": 0.5},
                    {"field": "order.label", "operator": "eq", "value": "normal"},
                ],
            }],
        }

    @staticmethod
    def payload():
        return {
            "approved": True,
            "order": {"amount": 50, "risk": 0.75, "label": "normal"},
        }

    @staticmethod
    def operation(payload, *, tenant="tenant-a", principal="principal-a",
                  agent="agent-a", route="orders.read"):
        context = SecurityContext(
            tenant,
            principal,
            agent,
            "workflow-a",
            "operation-a",
            "records.read",
            "policy-v1",
        )
        return Operation(
            context,
            route,
            "orders",
            "records-service",
            json.dumps(payload, separators=(",", ":"), allow_nan=True),
            "digest",
        )

    def build(self):
        return build_policy_control(
            self.definition,
            agents=self.agents,
            routes=self.routes,
        )

    async def test_real_pinned_sdk_allows_only_exact_bound_policy(self):
        self.assertEqual(
            importlib.metadata.version("agent-governance-toolkit-control-plane"),
            "5.0.0",
        )
        control = self.build()
        self.assertTrue(inspect.iscoroutinefunction(control))
        self.assertEqual(control.__name__, "agt.orders-policy")

        with outbound_sockets_forbidden():
            allowed = await control(self.operation(self.payload()))
            wrong_value = self.payload()
            wrong_value["order"]["amount"] = 101
            denied = await control(self.operation(wrong_value))

        self.assertEqual(
            (allowed.control_id, allowed.action),
            ("agt.orders-policy", Action.ALLOW),
        )
        self.assertEqual(denied.action, Action.DENY)

    async def test_strict_local_types_presence_and_scalars_prevent_sdk_coercion(self):
        control = self.build()
        cases = []
        approved_integer = self.payload()
        approved_integer["approved"] = 1
        cases.append(approved_integer)
        amount_boolean = self.payload()
        amount_boolean["order"]["amount"] = True
        cases.append(amount_boolean)
        amount_float = self.payload()
        amount_float["order"]["amount"] = 50.0
        cases.append(amount_float)
        risk_integer = self.payload()
        risk_integer["order"]["risk"] = 1
        cases.append(risk_integer)
        missing = self.payload()
        del missing["order"]["label"]
        cases.append(missing)
        null_leaf = self.payload()
        null_leaf["order"]["label"] = None
        cases.append(null_leaf)
        nonscalar = self.payload()
        nonscalar["order"]["label"] = ["normal"]
        cases.append(nonscalar)
        nonfinite = self.payload()
        nonfinite["order"]["risk"] = math.nan
        cases.append(nonfinite)

        with outbound_sockets_forbidden(), mock.patch.object(
                PolicyEngine,
                "check_violation",
                side_effect=AssertionError("vendor must not see locally invalid payload")):
            for index, payload in enumerate(cases):
                with self.subTest(index=index):
                    self.assertEqual(
                        (await control(self.operation(payload))).action,
                        Action.DENY,
                    )

    async def test_payload_cannot_spoof_trusted_identity_or_route_binding(self):
        control = self.build()
        spoofed = self.payload()
        spoofed.update({
            "tenant": "tenant-a",
            "principal": "principal-a",
            "agent": "agent-a",
            "route": "orders.read",
        })
        operations = (
            self.operation(spoofed, tenant="tenant-b"),
            self.operation(spoofed, principal="principal-b"),
            self.operation(spoofed, agent="agent-b"),
            self.operation(spoofed, route="orders.write"),
        )
        with outbound_sockets_forbidden():
            for operation in operations:
                self.assertEqual((await control(operation)).action, Action.DENY)

    async def test_configuration_is_snapshotted_before_caller_mutation(self):
        control = self.build()
        self.definition["bindings"][0]["conditions"][0]["value"] = False
        self.agents[0].update({"tenant": "tenant-b", "principal": "principal-b"})
        self.routes[0].update({"tenant": "tenant-b", "policy_engine": None})

        with outbound_sockets_forbidden():
            self.assertEqual(
                (await control(self.operation(self.payload()))).action,
                Action.ALLOW,
            )

    async def test_sdk_error_and_shadow_state_raise_only_fixed_runtime_error(self):
        control = self.build()
        with outbound_sockets_forbidden(), mock.patch.object(
                PolicyEngine,
                "check_violation",
                side_effect=RuntimeError("sensitive-vendor-detail")):
            with self.assertRaisesRegex(
                    AGTPolicyError, "^agt_policy_runtime_failed$") as caught:
                await control(self.operation(self.payload()))
        self.assertNotIn("sensitive", str(caught.exception))

        with outbound_sockets_forbidden(), mock.patch.object(
                PolicyEngine, "is_shadow_mode", return_value=True):
            with self.assertRaisesRegex(
                    AGTPolicyError, "^agt_policy_runtime_failed$"):
                await control(self.operation(self.payload()))

    async def test_required_agt_cannot_override_deterministic_denial(self):
        control = self.build()
        transport_calls = []

        async def deterministic_deny(operation):
            return ControlResult(
                "deterministic",
                operation.context.tenant_id,
                operation.context.operation_id,
                Action.DENY,
            )

        async def transport(operation):
            transport_calls.append(operation)
            return {"unexpected": True}

        token = "agt-policy-runtime-" + "x" * 32
        runtime = GuardRuntime(
            credentials={
                token: Principal(
                    "tenant-a",
                    "principal-a",
                    "agent-a",
                    frozenset({"orders.read"}),
                ),
            },
            routes=(Route(
                "orders.read",
                "records.read",
                "orders",
                "records-service",
                "tenant-a",
                ("deterministic", "agt.orders-policy"),
                transport,
            ),),
            controls={
                "deterministic": deterministic_deny,
                "agt.orders-policy": control,
            },
            audit=lambda event: None,
        )

        with outbound_sockets_forbidden(), self.assertRaises(AccessDenied):
            await runtime.execute(token, "orders.read", self.payload())
        self.assertEqual(transport_calls, [])


if __name__ == "__main__":
    unittest.main()
