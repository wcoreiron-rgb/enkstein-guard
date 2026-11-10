"""Run explicitly in the pinned optional-engine environment; no paid API calls."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.engines import agt_control, cisco_control, nemo_control
from enkstein_guard.private_ai import PrivateAI
from enkstein_guard.runtime import AccessDenied, Operation, Principal
from enkstein_guard.vault import LocalVault


class SDKTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_agt_frozen_policy_allows_and_denies(self):
        from agent_control_plane.policy_engine import PolicyEngine
        engine = PolicyEngine()
        role = json.dumps(["t", "p", "a"], separators=(",", ":"))
        engine.add_constraint(role, ["model"])
        engine.freeze()
        control = agt_control(engine)
        c = SecurityContext("t", "p", "a", "w", "o", "model.call", "v")
        self.assertEqual((await control(Operation(c, "model", "r", "d", '{}', "digest"))).action, Action.ALLOW)
        self.assertEqual((await control(Operation(c, "forbidden", "r", "d", '{}', "digest"))).action, Action.DENY)

    async def test_real_nemo_input_output_inside_private_pipeline(self):
        from nemoguardrails import RailsConfig, LLMRails
        config = RailsConfig.from_content(yaml_content='''models: []
rails:
  input:
    flows: [guard input]
  output:
    flows: [guard output]
''', colang_content='''define flow guard input
  $allowed = execute check_private_input
  if not $allowed
    bot refuse to respond
    stop

define flow guard output
  $allowed = execute check_private_output
  if not $allowed
    bot refuse to respond
    stop
''')
        rails = LLMRails(config)
        inspected = []
        async def check_private_input(context):
            inspected.append(context.get("user_message", ""))
            return "FORBIDDEN" not in context.get("user_message", "")
        async def check_private_output(context):
            inspected.append(context.get("bot_message", ""))
            return "FORBIDDEN" not in context.get("bot_message", "")
        rails.register_action(check_private_input, name="check_private_input")
        rails.register_action(check_private_output, name="check_private_output")
        from agent_control_plane.policy_engine import PolicyEngine
        engine = PolicyEngine()
        engine.add_constraint(json.dumps(["t","p","a"], separators=(",", ":")), ["model"])
        engine.freeze()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = LocalVault.initialize(root/'data/v.db', root/'keys/key.json')
            calls, deliveries = [], []
            async def model(op): calls.append(op.payload_json); return op.payload()
            async def sink(payload): deliveries.append(payload)
            token = "sdk-fixture-"+"a"*40
            runtime = PrivateAI(vault=vault, tenant_id="t", model=model, sinks={"human": sink},
                                credentials={token: Principal("t","p","a",frozenset({"model","sink:human"}))},
                                input_controls={"agt": agt_control(engine), "nemo": nemo_control(rails)},
                                output_controls={"nemo": nemo_control(rails,stage="output")},
                                audit=lambda event: None)
            reply = await runtime.generate(token, {"prompt":"Email jane@example.com"})
            self.assertNotIn("jane@example.com", str(calls)+str(inspected))
            await runtime.restore_to(token, reply.receipt, "human")
            self.assertEqual(deliveries, [{"prompt":"Email jane@example.com"}])
            with self.assertRaises(AccessDenied):
                await runtime.generate(token, {"prompt":"FORBIDDEN"})
            self.assertEqual(len(calls),1)
            # Execute actual output rail with prohibited content as well.
            c = SecurityContext("t","p","a","w","output","model.output","v")
            result = await nemo_control(rails,stage="output")(Operation(c,"model","r","d",'{"answer":"FORBIDDEN"}',"digest"))
            self.assertEqual(result.action,Action.DENY)

    async def test_real_cisco_sdk_serialization_with_mocked_inspection_boundary(self):
        from aidefense.runtime import AsyncChatInspectionClient
        from aidefense.runtime.models import InspectResponse, Action as CiscoAction
        async with AsyncChatInspectionClient(api_key="0"*64) as client:
            client._inspect = AsyncMock(return_value=InspectResponse(classifications=[],is_safe=True,action=CiscoAction.ALLOW))
            c=SecurityContext("t","p","a","w","o","model.call","v")
            op=Operation(c,"model","r","d",'{"prompt":"tokenized"}',"digest")
            self.assertEqual((await cisco_control(client)(op)).action,Action.ALLOW)
            messages=client._inspect.call_args.args[0]
            self.assertEqual(messages[0].content,op.payload_json)
            client._inspect.return_value=InspectResponse(classifications=[],is_safe=False,action=CiscoAction.BLOCK)
            self.assertEqual((await cisco_control(client,stage="output")(op)).action,Action.DENY)
