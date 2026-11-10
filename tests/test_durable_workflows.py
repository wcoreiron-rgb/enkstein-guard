import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
from contextlib import closing
import asyncio

from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.intent import TaskBoundary
from enkstein_guard.orchestration import (
    Admission, Budget, DELEGATE, HANDOFF, READ, RECEIVE,
    ProtectedOrchestrator, Tool,
)
from enkstein_guard.runtime import AccessDenied, GuardError, Route
from enkstein_guard.vault import LocalVault
from enkstein_guard.workflow_store import WorkflowStore, WorkflowStoreError


LABELS = frozenset({"confidential", "sensitive", "untrusted"})


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class DurableWorkflowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-workflows-")
        self.root = Path(self.temp.name)
        self.database = self.root / "state/workflows.sqlite3"
        self.key = self.root / "keys/workflows.key"
        self.vault_database = self.root / "vault/data.sqlite3"
        self.vault_key = self.root / "vault/key.json"
        self.vault = LocalVault.initialize(self.vault_database, self.vault_key)
        self.component = self.root / "component.py"
        self.component.write_text("# reviewed durable workflow fixture\n")
        self.admission = Admission(
            str(self.component), hashlib.sha256(self.component.read_bytes()).hexdigest())
        self.clock = Clock()
        self.calls = []
        self.inspections = []

    def tearDown(self):
        self.temp.cleanup()

    async def policy(self, operation):
        self.inspections.append(operation)
        return ControlResult("policy", operation.context.tenant_id,
                             operation.context.operation_id, Action.ALLOW)

    async def transport(self, operation):
        self.calls.append(operation.context.tenant_id)
        return {"tenant": operation.context.tenant_id, "result": "ok"}

    def tool(self, *, name="plain", tenant="tenant-a", units=1,
             produces=frozenset()):
        return Tool(
            Route(name, "tool.call", "fixture", "local", tenant,
                  ("policy",), self.transport),
            self.admission, LABELS, produces, units)

    def guard(self, store, *, tools=None, task_boundary_factory=None):
        return ProtectedOrchestrator(
            tools=tuple(tools or (self.tool(),)), controls={"policy": self.policy},
            vault=self.vault, audit=lambda event: None, store=store,
            wall_clock=self.clock, task_boundary_factory=task_boundary_factory)

    def initialize(self, *, tools=None):
        return self.guard(WorkflowStore.initialize(self.database, self.key), tools=tools)

    @staticmethod
    def grants(name="plain"):
        return frozenset({name, READ, DELEGATE, HANDOFF, RECEIVE})

    async def test_restart_preserves_budget_exhaustion_and_wall_deadline(self):
        guard = self.initialize()
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=self.grants(), budget=Budget(calls=1, seconds=20))
        await guard.execute(lease.credential, "plain", {})
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key))
        self.assertEqual(restarted.usage(lease.credential)["calls"], 1)
        with self.assertRaisesRegex(AccessDenied, "shared_budget_exhausted"):
            await restarted.execute(lease.credential, "plain", {})
        self.clock.now += 21
        with self.assertRaisesRegex(AccessDenied, "workflow_deadline"):
            await restarted.execute(lease.credential, "plain", {})
        restarted.close()

    async def test_tenant_delegation_and_sticky_labels_survive_restart(self):
        tools = (self.tool(name="a", tenant="tenant-a"),
                 self.tool(name="b", tenant="tenant-b"))
        guard = self.initialize(tools=tools)
        root = guard.start(tenant="tenant-a", principal="operator",
                           grants=frozenset({"a", DELEGATE}), budget=Budget(calls=5))
        child = await guard.delegate(root.credential, frozenset({"a"}))
        await guard.execute(child.credential, "a", {"email": "owner@example.com"})
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key), tools=tools)
        self.assertIn("sensitive", restarted.usage(child.credential)["labels"])
        await restarted.execute(child.credential, "a", {})
        self.assertEqual(self.inspections[-1].context.tenant_id, "tenant-a")
        with self.assertRaises(AccessDenied):
            await restarted.execute(child.credential, "b", {})
        restarted.close()

    async def test_label_discovered_before_flow_denial_is_durable(self):
        restricted = Tool(
            Route("send", "tool.call", "fixture", "external", "tenant-a",
                  ("policy",), self.transport),
            self.admission, accepts=frozenset())
        guard = self.initialize(tools=(restricted,))
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"send"}))
        with self.assertRaisesRegex(AccessDenied, "information_flow_denied"):
            await guard.execute(lease.credential, "send", {"email": "owner@example.com"})
        self.assertEqual(self.calls, [])
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key), tools=(restricted,))
        self.assertIn("sensitive", restarted.usage(lease.credential)["labels"])
        restarted.close()

    async def test_artifact_mailbox_retrieval_and_revocation_survive_restart(self):
        guard = self.initialize()
        root = guard.start(tenant="tenant-a", principal="operator", grants=self.grants())
        child = await guard.delegate(root.credential, frozenset({READ, RECEIVE}))
        artifact = await guard.execute(root.credential, "plain", {})
        await guard.handoff(root.credential, child.agent_id, artifact.handle)
        guard.cancel(child.credential)
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key))
        self.assertEqual(await restarted.read(root.credential, artifact.handle),
                         {"tenant": "tenant-a", "result": "ok"})
        with self.assertRaisesRegex(AccessDenied, "agent_revoked"):
            await restarted.receive(child.credential)
        restarted.close()

    async def test_interrupted_admission_stays_charged_and_is_never_replayed(self):
        guard = self.initialize()
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}), budget=Budget(calls=1))
        snapshot = guard._workflow_store.load()
        workflow = snapshot["workflows"][0]
        workflow.update(calls=1, units=1, active=1)
        snapshot["inflight"] = [{
            "id": "f" * 32, "workflow": workflow["id"], "agent": lease.agent_id,
            "route": "plain", "units": 1, "admitted_at": self.clock.now,
        }]
        guard._workflow_store.save(snapshot)
        guard._workflow_store.close()  # Simulated abrupt coordinator death.
        guard._closed = True

        restarted = self.guard(WorkflowStore(self.database, self.key))
        usage = restarted.usage(lease.credential)
        self.assertEqual((usage["calls"], usage["active"]), (1, 0))
        self.assertEqual(self.calls, [])
        with self.assertRaisesRegex(AccessDenied, "shared_budget_exhausted"):
            await restarted.execute(lease.credential, "plain", {})
        state = restarted._workflow_store.load()
        self.assertEqual(state["inflight"], [])
        self.assertEqual(state["interrupted"][0]["status"], "interrupted")
        restarted.close()

    async def test_registry_mismatch_fails_closed_and_releases_lock(self):
        guard = self.initialize()
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}))
        guard.close()
        with self.assertRaisesRegex(WorkflowStoreError, "workflow_registry_mismatch"):
            self.guard(WorkflowStore(self.database, self.key),
                       tools=(self.tool(units=2),))
        recovered = self.guard(WorkflowStore(self.database, self.key))
        self.assertEqual(recovered.usage(lease.credential)["calls"], 0)
        recovered.close()

    async def test_task_controls_are_rebuilt_from_current_factory(self):
        observed = []

        def factory(tenant, principal, workflow, routes):
            observed.append(workflow)
            return tuple(TaskBoundary(
                tenant, principal, workflow, route.name, route.resource,
                route.destination, frozenset({route.operation})) for route in routes)

        guard = self.guard(WorkflowStore.initialize(self.database, self.key),
                           task_boundary_factory=factory)
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}))
        guard.close()
        restarted = self.guard(WorkflowStore(self.database, self.key),
                               task_boundary_factory=factory)
        await restarted.execute(lease.credential, "plain", {})
        self.assertEqual(len(observed), 2)
        self.assertEqual(observed[0], observed[1])
        restarted.close()

    async def test_exclusive_ownership_including_same_store_object(self):
        store = WorkflowStore.initialize(self.database, self.key)
        guard = self.guard(store)
        with self.assertRaisesRegex(WorkflowStoreError, "workflow_store_already_owned"):
            WorkflowStore(self.database, self.key)
        with self.assertRaisesRegex(WorkflowStoreError, "workflow_store_already_attached"):
            self.guard(store)
        with self.assertRaisesRegex(WorkflowStoreError, "workflow_store_already_owned"):
            WorkflowStore(self.database, self.key)
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}))
        self.assertEqual(guard.usage(lease.credential)["calls"], 0)
        guard.close()

    async def test_close_refuses_active_work(self):
        started, release = asyncio.Event(), asyncio.Event()

        async def slow(operation):
            started.set()
            await release.wait()
            return {"ok": True}

        tool = Tool(Route("slow", "tool.call", "fixture", "local", "tenant-a",
                          ("policy",), slow), self.admission, LABELS)
        guard = self.initialize(tools=(tool,))
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"slow"}))
        task = asyncio.create_task(guard.execute(lease.credential, "slow", {}))
        await started.wait()
        with self.assertRaisesRegex(GuardError, "orchestration_work_active"):
            guard.close()
        release.set()
        await task
        guard.close()

    async def test_corruption_and_write_failure_fail_closed(self):
        guard = self.initialize()
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}))
        with mock.patch.object(guard._workflow_store, "save",
                               side_effect=WorkflowStoreError("workflow_storage_unavailable")):
            with self.assertRaisesRegex(GuardError, "orchestration_storage_unavailable"):
                await guard.execute(lease.credential, "plain", {})
        self.assertEqual(self.calls, [])
        with self.assertRaisesRegex(GuardError, "orchestration_storage_unavailable"):
            guard.usage(lease.credential)
        guard.close()

        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE snapshot SET record=? WHERE id=1", (b"corrupt",))
            connection.commit()
        with self.assertRaisesRegex(WorkflowStoreError, "workflow_store_integrity_failed"):
            WorkflowStore(self.database, self.key)

    async def test_post_dispatch_commit_failure_reports_unknown_without_result(self):
        guard = self.initialize()
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}), budget=Budget(calls=2))
        original_save = guard._workflow_store.save
        saves = 0

        def fail_final(snapshot):
            nonlocal saves
            saves += 1
            if saves == 3:
                raise WorkflowStoreError("workflow_storage_unavailable")
            return original_save(snapshot)

        with mock.patch.object(guard._workflow_store, "save", side_effect=fail_final):
            with self.assertRaisesRegex(GuardError, "orchestration_outcome_unknown"):
                await guard.execute(lease.credential, "plain", {})
        self.assertEqual(self.calls, ["tenant-a"])
        guard.close()

        restarted = self.guard(WorkflowStore(self.database, self.key))
        self.assertEqual(restarted.usage(lease.credential)["calls"], 1)
        self.assertEqual(self.calls, ["tenant-a"])  # Recovery never replays it.
        self.assertEqual(restarted._workflows[next(iter(restarted._workflows))].artifacts, {})
        restarted.close()

    async def test_admission_commit_failure_clears_transient_active_slot(self):
        guard = self.initialize()
        lease = guard.start(tenant="tenant-a", principal="operator",
                            grants=frozenset({"plain"}))
        original_save = guard._workflow_store.save
        saves = 0

        def fail_admission(snapshot):
            nonlocal saves
            saves += 1
            if saves == 2:
                raise WorkflowStoreError("workflow_storage_unavailable")
            return original_save(snapshot)

        with mock.patch.object(guard._workflow_store, "save", side_effect=fail_admission):
            with self.assertRaisesRegex(GuardError, "orchestration_storage_unavailable"):
                await guard.execute(lease.credential, "plain", {})
        self.assertEqual(self.calls, [])
        self.assertEqual(next(iter(guard._workflows.values())).active, 0)
        with self.assertRaisesRegex(GuardError, "orchestration_storage_unavailable"):
            guard.usage(lease.credential)
        guard.close()  # Poisoned state can still release exclusive ownership.
        reopened = self.guard(WorkflowStore(self.database, self.key))
        self.assertEqual(reopened.usage(lease.credential)["active"], 0)
        reopened.close()

    async def test_clock_rollback_fails_recovery(self):
        guard = self.initialize()
        guard.start(tenant="tenant-a", principal="operator",
                    grants=frozenset({"plain"}))
        guard.close()
        self.clock.now -= 1
        with self.assertRaisesRegex(WorkflowStoreError, "workflow_clock_rollback"):
            self.guard(WorkflowStore(self.database, self.key))

    def test_private_encrypted_paths_and_missing_half_fail_closed(self):
        store = WorkflowStore.initialize(self.database, self.key)
        try:
            self.assertEqual(os.stat(self.database).st_mode & 0o077, 0)
            self.assertEqual(os.stat(self.key).st_mode & 0o077, 0)
            self.assertNotIn(b"tenant-a", self.database.read_bytes())
        finally:
            store.close()
        self.key.unlink()
        with self.assertRaises(WorkflowStoreError):
            WorkflowStore(self.database, self.key)


if __name__ == "__main__":
    unittest.main()
