"""Synthetic adversarial probes for durable orchestration recovery."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.orchestration import (
    Admission, Budget, DELEGATE, HANDOFF, READ, RECEIVE,
    ProtectedOrchestrator, Tool,
)
from enkstein_guard.runtime import AccessDenied, Route
from enkstein_guard.vault import LocalVault
from enkstein_guard.workflow_store import WorkflowStore
from test_attack_scenarios import scenario


LABELS = frozenset({"sensitive", "confidential", "untrusted"})


class WorkflowRecoveryScenarios(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-recovery-scenario-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "state/workflows.sqlite3"
        self.key = self.root / "keys/workflows.key"
        self.vault = LocalVault.initialize(
            self.root / "vault/data.sqlite3", self.root / "vault/key.json")
        component = self.root / "synthetic_tool.py"
        component.write_text("# reviewed synthetic recovery tool\n")
        self.admission = Admission(
            str(component), hashlib.sha256(component.read_bytes()).hexdigest())
        self.calls = []

    async def policy(self, operation):
        return ControlResult("policy", operation.context.tenant_id,
                             operation.context.operation_id, Action.ALLOW)

    async def plain(self, operation):
        self.calls.append("plain")
        return {"ok": True}

    async def source(self, operation):
        self.calls.append("source")
        return {"record": "synthetic restricted fixture"}

    async def send(self, operation):
        self.calls.append("send")
        return {"sent": True}

    def tool(self, name, callback, *, accepts=LABELS, produces=frozenset()):
        return Tool(
            Route(name, "tool.call", name,
                  "external" if name == "send" else "internal",
                  "tenant-a", ("policy",), callback),
            self.admission, accepts, produces)

    def guard(self, store, *, tools=None):
        return ProtectedOrchestrator(
            tools=tuple(tools or (self.tool("plain", self.plain),)),
            controls={"policy": self.policy}, vault=self.vault,
            audit=lambda event: None, store=store)

    @scenario("LLM06:2026", "ASI08:2026", atlas=("AML.T0034.002",))
    async def test_restart_cannot_reset_depleted_shared_budget(self):
        guard = self.guard(WorkflowStore.initialize(self.database, self.key))
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}), budget=Budget(calls=2))
        await guard.execute(lease.credential, "plain", {})
        await guard.execute(lease.credential, "plain", {})
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key))
        with self.assertRaisesRegex(AccessDenied, "shared_budget_exhausted"):
            await restarted.execute(lease.credential, "plain", {})
        self.assertEqual(self.calls, ["plain", "plain"])
        restarted.close()

    @scenario("LLM02:2026", "ASI07:2026", atlas=("AML.T0057",))
    async def test_sensitive_handoff_remains_blocked_after_recovery(self):
        tools = (
            self.tool("source", self.source, produces=frozenset({"sensitive"})),
            self.tool("send", self.send, accepts=frozenset()),
        )
        guard = self.guard(WorkflowStore.initialize(self.database, self.key), tools=tools)
        root = guard.start(
            tenant="tenant-a", principal="operator",
            grants=frozenset({"source", "send", DELEGATE, HANDOFF, READ, RECEIVE}),
            budget=Budget(calls=10))
        child = await guard.delegate(
            root.credential, frozenset({"send", READ, RECEIVE}))
        artifact = await guard.execute(root.credential, "source", {})
        await guard.handoff(root.credential, child.agent_id, artifact.handle)
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key), tools=tools)
        received = await restarted.receive(child.credential)
        self.assertEqual(received[0].handle, artifact.handle)
        await restarted.read(child.credential, artifact.handle)
        with self.assertRaisesRegex(AccessDenied, "information_flow_denied"):
            await restarted.execute(child.credential, "send", {"summary": "synthetic"})
        self.assertNotIn("send", self.calls)
        restarted.close()

    @scenario("LLM06:2026", "ASI08:2026", atlas=("AML.T0034.002",), kind="benign")
    async def test_benign_within_budget_work_continues_after_recovery(self):
        guard = self.guard(WorkflowStore.initialize(self.database, self.key))
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}), budget=Budget(calls=3))
        await guard.execute(lease.credential, "plain", {})
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key))
        await restarted.execute(lease.credential, "plain", {})
        self.assertEqual(restarted.usage(lease.credential)["calls"], 2)
        self.assertEqual(self.calls, ["plain", "plain"])
        restarted.close()


if __name__ == "__main__":
    unittest.main()
