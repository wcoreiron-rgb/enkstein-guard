from enum import Enum
import json
import sys
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import patch

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.engines import agt_control, cisco_control, nemo_control
from enkstein_guard.runtime import Operation


class EngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.op = Operation(SecurityContext("t", "p", "a", "w", "o", "model.call", "v"),
                            "model", "model", "provider", '{"text":"tokenized"}', "digest")

    async def test_cisco_strict_boolean_and_stages(self):
        seen = []
        class Client:
            async def inspect_prompt(self, **kwargs):
                seen.append(kwargs); return SimpleNamespace(is_safe=True, action=SimpleNamespace(value="Allow"))
            async def inspect_response(self, **kwargs):
                seen.append(kwargs); return SimpleNamespace(is_safe=False, action=SimpleNamespace(value="Block"))
        self.assertEqual((await cisco_control(Client())(self.op)).action, Action.ALLOW)
        self.assertEqual((await cisco_control(Client(), stage="output")(self.op)).action, Action.DENY)
        self.assertIn("prompt", seen[0]); self.assertIn("response", seen[1])
        class Bad:
            async def inspect_prompt(self, **kwargs):
                return SimpleNamespace(is_safe="true")
        with self.assertRaises(ValueError):
            await cisco_control(Bad())(self.op)

    async def test_cisco_explicit_block_wins_over_safe_flag(self):
        class Conflict:
            async def inspect_prompt(self, **kwargs):
                return SimpleNamespace(is_safe=True, action=SimpleNamespace(value="Block"))
        self.assertEqual((await cisco_control(Conflict())(self.op)).action, Action.DENY)

    async def test_agt_requires_frozen_enforcement_and_tenant_role(self):
        class Engine:
            is_frozen = True
            role = None
            def is_shadow_mode(self, role): return False
            def check_violation(self, role, tool, args):
                self.role = role; return None
        engine = Engine()
        self.assertEqual((await agt_control(engine)(self.op)).action, Action.ALLOW)
        self.assertEqual(json.loads(engine.role), ["t", "p", "a"])
        engine.is_frozen = False
        with self.assertRaises(ValueError):
            agt_control(engine)

    async def test_agt_denial_and_invalid_verdict(self):
        class Engine:
            is_frozen = True
            def is_shadow_mode(self, role): return False
            def check_violation(self, *args): return "denied"
        self.assertEqual((await agt_control(Engine())(self.op)).action, Action.DENY)
        class Bad(Engine):
            def check_violation(self, *args): return False
        with self.assertRaises(ValueError):
            await agt_control(Bad())(self.op)

    async def test_nemo_explicit_rail_and_modified_blocks(self):
        class RailType(str, Enum):
            INPUT = "input"
            OUTPUT = "output"
        options = ModuleType("nemoguardrails.rails.llm.options")
        options.RailType = RailType
        class Rails:
            config = SimpleNamespace(rails=SimpleNamespace(input=SimpleNamespace(flows=["configured"])))
            status = "passed"
            async def check_async(self, messages, rail_types):
                self.messages = messages; self.types = rail_types
                return SimpleNamespace(status=SimpleNamespace(value=self.status))
        rails = Rails()
        with patch.dict(sys.modules, {"nemoguardrails.rails.llm.options": options}):
            self.assertEqual((await nemo_control(rails)(self.op)).action, Action.ALLOW)
            self.assertEqual(rails.types, [RailType.INPUT])
            for status in ("modified", "blocked"):
                rails.status = status
                self.assertEqual((await nemo_control(rails)(self.op)).action, Action.DENY)
            rails.status = "unknown"
            with self.assertRaises(ValueError):
                await nemo_control(rails)(self.op)

    async def test_nemo_unconfigured_rails_rejected(self):
        class Rails:
            config = SimpleNamespace(rails=SimpleNamespace(input=SimpleNamespace(flows=[])))
            async def check_async(self, *args, **kwargs): pass
        with self.assertRaises(ValueError):
            nemo_control(Rails())
