"""Focused offline contracts for the optional AGT and NeMo adapters.

Run only in the optional-engine environment.  Every test is synthetic; socket
creation is disabled around engine execution so an accidental provider call
fails the test instead of leaving the host.
"""

from contextlib import contextmanager
import importlib.util
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.engines import agt_control, nemo_control
from enkstein_guard.runtime import AccessDenied, GuardRuntime, Operation, Principal, Route


def _module_available(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


HAS_AGT_CONTROL_PLANE = _module_available("agent_control_plane.policy_engine")
HAS_NEMO = _module_available("nemoguardrails.rails.llm.options")


@contextmanager
def _outbound_sockets_forbidden():
    """Make unexpected direct socket use a deterministic local test failure."""
    message = "outbound I/O is forbidden in optional engine contract tests"
    with patch("socket.socket", side_effect=AssertionError(message)), patch(
        "socket.create_connection", side_effect=AssertionError(message)
    ):
        yield


def _operation(*, tenant="tenant-a", principal="principal-a", agent="agent-a", payload=None):
    content = json.dumps(payload or {"approved": True}, sort_keys=True, separators=(",", ":"))
    context = SecurityContext(tenant, principal, agent, "workflow", "operation", "model.call", "policy-v1")
    return Operation(context, "model", "configured-model", "model-provider", content, "digest")


class ReusedEngineContractTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(HAS_AGT_CONTROL_PLANE, "AGT control-plane distribution is not installed")
    async def test_real_agt_abac_receives_bound_identity_route_and_payload(self):
        from agent_control_plane.policy_engine import Condition, ConditionalPermission, PolicyEngine

        role = json.dumps(["tenant-a", "principal-a", "agent-a"], separators=(",", ":"))
        engine = PolicyEngine()
        engine.add_constraint(role, ["model"])
        engine.add_conditional_permission(
            role,
            ConditionalPermission("model", [Condition("args.approved", "eq", True)]),
        )
        engine.freeze()
        control = agt_control(engine)

        with _outbound_sockets_forbidden():
            allowed = await control(_operation(payload={"approved": True}))
            denied_by_payload = await control(_operation(payload={"approved": False}))
            denied_by_identity = await control(_operation(tenant="tenant-b", payload={"approved": True}))

        self.assertEqual(allowed.action, Action.ALLOW)
        self.assertEqual(denied_by_payload.action, Action.DENY)
        self.assertEqual(denied_by_identity.action, Action.DENY)

    @unittest.skipUnless(HAS_AGT_CONTROL_PLANE, "AGT control-plane distribution is not installed")
    async def test_real_agt_shadow_context_is_rejected_before_policy_check(self):
        from agent_control_plane.policy_engine import PolicyEngine

        role = json.dumps(["tenant-a", "principal-a", "agent-a"], separators=(",", ":"))
        engine = PolicyEngine()
        engine.add_constraint(role, ["model"])
        engine.set_agent_context(role, {"shadow_mode": True})
        engine.freeze()

        with _outbound_sockets_forbidden(), self.assertRaises(ValueError):
            await agt_control(engine)(_operation())

    @unittest.skipUnless(HAS_NEMO, "NeMo Guardrails is not installed")
    async def test_nemo_modified_result_denies_and_preserves_explicit_stage_contract(self):
        from nemoguardrails.rails.llm.options import RailStatus, RailsResult, RailType

        class ScriptedRails:
            config = SimpleNamespace(
                rails=SimpleNamespace(
                    input=SimpleNamespace(flows=["configured-input"]),
                    output=SimpleNamespace(flows=["configured-output"]),
                )
            )

            def __init__(self):
                self.calls = []

            async def check_async(self, messages, rail_types):
                self.calls.append((messages, rail_types))
                return RailsResult(status=RailStatus.MODIFIED, content="rewritten")

        rails = ScriptedRails()
        operation = _operation(payload={"text": "tokenized"})
        with _outbound_sockets_forbidden():
            input_result = await nemo_control(rails)(operation)
            output_result = await nemo_control(rails, stage="output")(operation)

        self.assertEqual(input_result.action, Action.DENY)
        self.assertEqual(output_result.action, Action.DENY)
        self.assertEqual(rails.calls[0], ([{"role": "user", "content": operation.payload_json}], [RailType.INPUT]))
        self.assertEqual(
            rails.calls[1],
            ([{"role": "assistant", "content": operation.payload_json}], [RailType.OUTPUT]),
        )

    @unittest.skipUnless(HAS_NEMO, "NeMo Guardrails is not installed")
    async def test_required_nemo_exception_fails_closed_before_local_model(self):
        class UnavailableRails:
            config = SimpleNamespace(
                rails=SimpleNamespace(input=SimpleNamespace(flows=["configured-input"]))
            )

            async def check_async(self, messages, rail_types):
                raise RuntimeError("synthetic engine outage")

        model_calls = []
        audit_events = []

        async def local_model(operation):
            model_calls.append(operation.payload())
            return {"unexpected": True}

        token = "optional-engine-contract-" + "x" * 32
        runtime = GuardRuntime(
            credentials={
                token: Principal("tenant-a", "principal-a", "agent-a", frozenset({"model"}))
            },
            routes=(
                Route(
                    "model",
                    "model.call",
                    "configured-model",
                    "model-provider",
                    "tenant-a",
                    ("nemo",),
                    local_model,
                ),
            ),
            controls={"nemo": nemo_control(UnavailableRails())},
            audit=audit_events.append,
        )

        with _outbound_sockets_forbidden(), self.assertRaises(AccessDenied):
            await runtime.execute(token, "model", {"text": "tokenized"})

        self.assertEqual(model_calls, [])
        self.assertEqual(audit_events[-1]["outcome"], "denied")
        self.assertEqual(
            audit_events[-1]["controls"],
            [{"id": "nemo", "action": "deny", "status": "error"}],
        )


if __name__ == "__main__":
    unittest.main()
