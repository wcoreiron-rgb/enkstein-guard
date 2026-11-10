from contextlib import contextmanager, redirect_stdout
import asyncio
import copy
import importlib.metadata
import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest import mock

from enkstein_guard.agt_policy import AGTPolicyError, build_policy_control
from enkstein_guard.cli import main as cli_main
from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard import host as host_module
from enkstein_guard.host import (
    Components,
    GuardHost,
    Policy,
    StateLayout,
    initialize_state,
)
from enkstein_guard.identities import IdentityStore
from enkstein_guard.productconfig import validate
from enkstein_guard.runtime import AccessDenied, GuardRuntime, Operation, Principal, Route
from test_host import make_config


def _has_supported_agt():
    try:
        return (
            importlib.util.find_spec("agent_control_plane.policy_engine") is not None
            and importlib.metadata.version(
                "agent-governance-toolkit-control-plane"
            ) == "5.0.0"
        )
    except (ImportError, ModuleNotFoundError, importlib.metadata.PackageNotFoundError):
        return False


HAS_SUPPORTED_AGT = _has_supported_agt()


@contextmanager
def sockets_forbidden():
    message = "socket creation is forbidden in AGT CLI contract tests"
    with mock.patch("socket.socket", side_effect=AssertionError(message)), \
            mock.patch("socket.create_connection", side_effect=AssertionError(message)), \
            mock.patch("asyncio.start_unix_server", side_effect=AssertionError(message)):
        yield


@contextmanager
def service_sockets_forbidden():
    """Permit wrapping asyncio's existing wakeup FDs, but no new socket."""
    message = "service socket creation is forbidden in AGT CLI contract tests"
    real_socket = socket.socket

    def existing_descriptor_only(family=-1, type=-1, proto=-1, fileno=None):
        if fileno is None:
            raise AssertionError(message)
        return real_socket(family, type, proto, fileno)

    with mock.patch("socket.socket", side_effect=existing_descriptor_only), \
            mock.patch("socket.create_connection", side_effect=AssertionError(message)), \
            mock.patch("asyncio.start_unix_server", side_effect=AssertionError(message)):
        yield


def definition(*, field="approved", operator="eq", value=True):
    return {
        "name": "orders-gate",
        "kind": "agt",
        "tenant": "tenant-a",
        "bindings": [{
            "agent": "agent-a",
            "route": "orders.read",
            "conditions": [{"field": field, "operator": operator, "value": value}],
        }],
    }


def registries():
    agents = [{
        "id": "agent-a",
        "tenant": "tenant-a",
        "principal": "principal-a",
        "routes": ["orders.read"],
    }]
    routes = [{
        "name": "orders.read",
        "tenant": "tenant-a",
        "operation": "orders.read",
        "policy_engine": "orders-gate",
    }]
    return agents, routes


def operation(payload, *, tenant="tenant-a", principal="principal-a",
              agent="agent-a", route="orders.read"):
    context = SecurityContext(
        tenant, principal, agent, "workflow-a", "operation-a",
        "orders.read", "policy-1",
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=True)
    return Operation(context, route, "orders", "local", encoded, "digest")


@unittest.skipUnless(HAS_SUPPORTED_AGT, "supported AGT control-plane SDK is not installed")
class AGTRealRuntimeSecurityContracts(unittest.IsolatedAsyncioTestCase):
    def build(self, policy=None, *, agents=None, routes=None):
        default_agents, default_routes = registries()
        return build_policy_control(
            policy or definition(),
            agents=default_agents if agents is None else agents,
            routes=default_routes if routes is None else routes,
        )

    async def test_payload_cannot_spoof_trusted_tenant_principal_agent_or_route(self):
        control = self.build()
        spoof = {
            "approved": True,
            "tenant": "tenant-a",
            "principal": "principal-a",
            "agent": "agent-a",
            "route": "orders.read",
        }
        cases = (
            {"tenant": "tenant-b"},
            {"principal": "principal-b"},
            {"agent": "agent-b"},
            {"route": "orders.write"},
        )
        with sockets_forbidden():
            self.assertEqual((await control(operation(spoof))).action, Action.ALLOW)
            for changes in cases:
                with self.subTest(changes=changes):
                    self.assertEqual(
                        (await control(operation(spoof, **changes))).action,
                        Action.DENY,
                    )

    async def test_missing_null_type_coercion_nonfinite_nonscalar_and_dotted_leaves_deny(self):
        agents, routes = registries()
        integer = self.build(definition(field="order.amount", value=1))
        floating = self.build(definition(field="order.amount", value=1.0))
        boolean = self.build(definition(field="order.approved", value=True))
        integer_bad = (
            {},
            {"order": {}},
            {"order": {"amount": None}},
            {"order": {"amount": True}},
            {"order": {"amount": 1.0}},
            {"order": {"amount": float("nan")}},
            {"order": {"amount": float("inf")}},
            {"order": {"amount": []}},
            {"order": {"amount": {}}},
            {"order": []},
        )
        with sockets_forbidden():
            self.assertEqual(
                (await integer(operation({"order": {"amount": 1}}))).action,
                Action.ALLOW,
            )
            for payload in integer_bad:
                with self.subTest(payload=repr(payload)):
                    self.assertEqual((await integer(operation(payload))).action, Action.DENY)
            self.assertEqual(
                (await floating(operation({"order": {"amount": 1}}))).action,
                Action.DENY,
            )
            self.assertEqual(
                (await boolean(operation({"order": {"approved": 1}}))).action,
                Action.DENY,
            )

    async def test_built_control_is_detached_from_mutable_configuration(self):
        agents, routes = registries()
        policy = definition()
        control = self.build(policy, agents=agents, routes=routes)

        policy["bindings"][0]["conditions"][0]["value"] = False
        agents[0]["tenant"] = "tenant-b"
        agents[0]["routes"].clear()
        routes[0]["policy_engine"] = None

        with sockets_forbidden():
            result = await control(operation({"approved": True}))
        self.assertEqual(result.action, Action.ALLOW)

    async def required_runtime(self, control, *, timeout=0.05):
        transport_calls = []
        audit = []

        async def transport(item):
            transport_calls.append(item.payload())
            return {"unexpected": True}

        token = "agt-runtime-contract-" + "x" * 32
        runtime = GuardRuntime(
            credentials={
                token: Principal(
                    "tenant-a", "principal-a", "agent-a", frozenset({"orders.read"})
                )
            },
            routes=(Route(
                "orders.read", "orders.read", "orders", "local", "tenant-a",
                ("agt.orders-gate",), transport,
            ),),
            controls={"agt.orders-gate": control},
            audit=audit.append,
            control_timeout=timeout,
        )
        return runtime, token, transport_calls, audit

    async def test_vendor_deny_error_and_timeout_are_authoritative_and_non_sensitive(self):
        from agent_control_plane.policy_engine import PolicyEngine

        control = self.build()
        secret = "synthetic-vendor-sensitive-detail"

        runtime, token, calls, audit = await self.required_runtime(control)
        with sockets_forbidden(), mock.patch.object(
                PolicyEngine, "check_violation", autospec=True, return_value="denied"):
            with self.assertRaisesRegex(AccessDenied, "^control_denied$"):
                await runtime.execute(token, "orders.read", {"approved": True})
        self.assertEqual(calls, [])
        self.assertEqual(audit[-1]["controls"][0]["status"], "ok")
        self.assertEqual(audit[-1]["controls"][0]["action"], "deny")

        runtime, token, calls, audit = await self.required_runtime(control)
        with sockets_forbidden(), mock.patch.object(
                PolicyEngine, "check_violation", autospec=True,
                side_effect=RuntimeError(secret)):
            with self.assertRaisesRegex(AccessDenied, "^control_denied$") as caught:
                await runtime.execute(token, "orders.read", {"approved": True})
        self.assertEqual(calls, [])
        self.assertEqual(audit[-1]["controls"][0]["status"], "error")
        self.assertNotIn(secret, str(caught.exception) + json.dumps(audit))

        def slow_check(*args, **kwargs):
            time.sleep(0.05)
            return None

        runtime, token, calls, audit = await self.required_runtime(control, timeout=0.005)
        with sockets_forbidden(), mock.patch.object(
                PolicyEngine, "check_violation", autospec=True, side_effect=slow_check):
            with self.assertRaisesRegex(AccessDenied, "^control_denied$"):
                await runtime.execute(token, "orders.read", {"approved": True})
        self.assertEqual(calls, [])
        self.assertEqual(audit[-1]["controls"][0]["status"], "timeout")


def host_config(root):
    data = make_config(root)
    next(item for item in data["routes"] if item["name"] == "ticket.comment")[
        "policy_engine"
    ] = "ticket-gate"
    data["policy_engines"] = [{
        "name": "ticket-gate",
        "kind": "agt",
        "tenant": "tenant-a",
        "bindings": [{
            "agent": "agent-a",
            "route": "ticket.comment",
            "conditions": [{"field": "comment", "operator": "eq", "value": "approved"}],
        }],
    }]
    return data


@unittest.skipUnless(HAS_SUPPORTED_AGT, "supported AGT control-plane SDK is not installed")
class AGTRealHostSecurityContracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-agt-host-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text("cobalt orchard")
        self.raw = host_config(self.root)
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps(self.raw))
        self.config = validate(self.raw, source=str(self.config_path))
        initialize_state(self.config)
        identity = IdentityStore(*StateLayout(self.config).identities)
        token_path = self.root / "agent.token"
        identity.issue("agent", "agent-a", token_path)
        self.token = token_path.read_text().strip()

    async def test_real_host_policy_preserves_execution_payload_and_deterministic_deny(self):
        captured = []
        original = host_module._fixture

        def capture(behavior, timeout, delay=1):
            inner = original(behavior, timeout, delay)

            async def transport(item):
                captured.append(item.payload())
                return await inner(item)
            return transport

        with sockets_forbidden(), mock.patch.object(host_module, "_fixture", capture):
            host = GuardHost(self.config)
            host.components = Components(self.config)
            host.approvals = host._approval_book()
            policy = Policy(host.components, self.config, host.approvals)

            payload = {"ticket": "INC-42", "comment": "approved"}
            await policy.runtime.execute(self.token, "ticket.comment", payload)
            self.assertEqual(captured, [payload])

            with self.assertRaisesRegex(AccessDenied, "^control_denied$"):
                await policy.runtime.execute(
                    self.token,
                    "ticket.comment",
                    {"ticket": "INC-99", "comment": "approved"},
                )
            with self.assertRaisesRegex(AccessDenied, "^control_denied$"):
                await policy.runtime.execute(
                    self.token,
                    "ticket.comment",
                    {"ticket": "INC-42", "comment": "rejected"},
                )
        self.assertEqual(captured, [payload])


@unittest.skipUnless(HAS_SUPPORTED_AGT, "supported AGT control-plane SDK is not installed")
class AGTRealCLIContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-agt-cli-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text("cobalt orchard")
        self.raw = host_config(self.root)
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps(self.raw))

    def run_cli(self, *arguments):
        output = io.StringIO()
        with sockets_forbidden(), redirect_stdout(output):
            code = cli_main(["--config", str(self.config_path), *arguments])
        lines = [line for line in output.getvalue().splitlines() if line]
        self.assertEqual(len(lines), 1, output.getvalue())
        return code, json.loads(lines[0])

    def test_config_validate_uses_no_socket_and_reports_required_policy(self):
        code, payload = self.run_cli("config", "validate")
        self.assertEqual(code, 0)
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["summary"]["policy_engine_count"], 1)
        self.assertEqual(payload["summary"]["policy_engine_route_count"], 1)
        self.assertEqual(payload["summary"]["policy_engines"][0]["stage"], "configured")

    def test_required_sdk_build_failures_stop_service_before_socket_creation(self):
        initialize_state(validate(self.raw, source=str(self.config_path)))
        secret = "synthetic-build-sensitive-detail"
        cases = ("agt_policy_sdk_unavailable", "agt_policy_sdk_incompatible")
        for error in cases:
            with self.subTest(error=error):
                output = io.StringIO()
                with service_sockets_forbidden(), redirect_stdout(output), mock.patch(
                    "enkstein_guard.agt_policy.build_policy_control",
                    side_effect=AGTPolicyError(error),
                ):
                    code = cli_main([
                        "--config", str(self.config_path), "service", "start"
                    ])
                payload = json.loads(output.getvalue())
                self.assertEqual(code, 4)
                self.assertEqual(payload["error"], error)
                self.assertNotIn(secret, json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
