import hashlib
from pathlib import Path
import tempfile
import unittest

from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.intent import FieldRule, TaskBoundary
from enkstein_guard.orchestration import Admission, DELEGATE, ProtectedOrchestrator, Tool
from enkstein_guard.runtime import AccessDenied, Route
from enkstein_guard.vault import LocalVault, VaultError


class OrchestrationIntentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        source = root / "ticket_component.py"
        source.write_text("# reviewed ticket fixture\n")
        self.admission = Admission(str(source), hashlib.sha256(source.read_bytes()).hexdigest())
        self.vault = LocalVault.initialize(root / "data/v.db", root / "keys/k.json")
        self.calls = []
        self.inspections = []

    def tearDown(self):
        self.tmp.cleanup()

    async def policy(self, operation):
        self.inspections.append(operation.payload())
        return ControlResult("policy", operation.context.tenant_id,
                             operation.context.operation_id, Action.ALLOW)

    async def transport(self, operation):
        self.calls.append(operation.payload())
        return {"ok": True}

    def tool(self, *, name="ticket.write", tenant="tenant-a"):
        route = Route(name, "ticket.update", "support-ticket", "internal-ticket-service",
                      tenant, ("policy",), self.transport)
        return Tool(route, self.admission,
                    accepts=frozenset({"confidential", "sensitive", "untrusted"}))

    @staticmethod
    def boundary(tenant, principal, workflow_id, route, **changes):
        values = {
            "tenant_id": tenant,
            "principal_id": principal,
            "workflow_id": workflow_id,
            "route": route.name,
            "resource": route.resource,
            "destination": route.destination,
            "operations": frozenset({route.operation}),
        }
        values.update(changes)
        return TaskBoundary(
            **values,
            fields=(
                FieldRule(("ticket", "id"), "str", choices=("INC-42",)),
                FieldRule(("action",), "str", choices=("comment",)),
                FieldRule(("comment",), "str", choices=("owner@example.com",)),
            ),
        )

    def factory(self, tenant, principal, workflow_id, routes):
        return tuple(self.boundary(tenant, principal, workflow_id, route) for route in routes)

    def guard(self, factory=None, tools=None, controls=None):
        return ProtectedOrchestrator(
            tools=tuple(tools or (self.tool(),)),
            controls=controls or {"policy": self.policy},
            vault=self.vault,
            audit=lambda event: None,
            task_boundary_factory=self.factory if factory is None else factory,
        )

    @staticmethod
    def payload(**changes):
        value = {"ticket": {"id": "INC-42"}, "action": "comment",
                 "comment": "owner@example.com"}
        value.update(changes)
        return value

    async def test_benign_task_uses_raw_payload_and_reaches_transport(self):
        guard = self.guard()
        lease = guard.start(tenant="tenant-a", principal="operator-a",
                            grants=frozenset({"ticket.write"}))
        await guard.execute(lease.credential, "ticket.write", self.payload())

        self.assertEqual(self.calls, [self.payload()])
        self.assertNotEqual(self.inspections, [self.payload()])
        self.assertNotIn("owner@example.com", str(self.inspections))

    async def test_changed_ticket_action_and_unknown_field_never_reach_transport(self):
        guard = self.guard()
        lease = guard.start(tenant="tenant-a", principal="operator-a",
                            grants=frozenset({"ticket.write"}))
        attacks = (
            self.payload(ticket={"id": "INC-99"}),
            self.payload(action="close"),
            self.payload(approved=True),
        )
        for payload in attacks:
            with self.subTest(payload=payload), self.assertRaises(AccessDenied):
                await guard.execute(lease.credential, "ticket.write", payload)
        self.assertEqual(self.calls, [])

    async def test_child_shares_boundary_and_cannot_bypass_it(self):
        guard = self.guard()
        root = guard.start(tenant="tenant-a", principal="operator-a",
                           grants=frozenset({"ticket.write", DELEGATE}))
        child = await guard.delegate(root.credential, frozenset({"ticket.write"}))

        with self.assertRaises(AccessDenied):
            await guard.execute(child.credential, "ticket.write",
                                self.payload(ticket={"id": "INC-99"}))
        await guard.execute(child.credential, "ticket.write", self.payload())
        self.assertEqual(self.calls, [self.payload()])

    def test_every_boundary_binding_is_validated_before_workflow_publication(self):
        state = {"change": {}}

        def factory(tenant, principal, workflow_id, routes):
            return (self.boundary(tenant, principal, workflow_id, routes[0],
                                  **state["change"]),)

        guard = self.guard(factory=factory)
        mismatches = (
            {"tenant_id": "tenant-b"},
            {"principal_id": "operator-b"},
            {"workflow_id": "reused-workflow"},
            {"route": "ticket.admin"},
            {"resource": "other-resource"},
            {"destination": "external-service"},
            {"operations": frozenset({"ticket.delete"})},
        )
        for change in mismatches:
            state["change"] = change
            with self.subTest(change=change), self.assertRaisesRegex(
                    ValueError, "invalid_workflow_task_boundaries"):
                guard.start(tenant="tenant-a", principal="operator-a",
                            grants=frozenset({"ticket.write"}))

    async def test_reusing_previous_workflow_boundary_is_refused(self):
        cached = []

        def factory(tenant, principal, workflow_id, routes):
            if not cached:
                cached.append(self.boundary(tenant, principal, workflow_id, routes[0]))
            return tuple(cached)

        guard = self.guard(factory=factory)
        first = guard.start(tenant="tenant-a", principal="operator-a",
                            grants=frozenset({"ticket.write"}))
        with self.assertRaisesRegex(ValueError, "invalid_workflow_task_boundaries"):
            guard.start(tenant="tenant-a", principal="operator-a",
                        grants=frozenset({"ticket.write"}))
        await guard.execute(first.credential, "ticket.write", self.payload())
        self.assertEqual(self.calls, [self.payload()])

    def test_factory_requires_exact_tuple_and_one_boundary_per_tool(self):
        async def async_result():
            return ()

        factories = (
            lambda tenant, principal, workflow, routes: [],
            lambda tenant, principal, workflow, routes: (),
            lambda tenant, principal, workflow, routes: async_result(),
            lambda tenant, principal, workflow, routes: (
                self.boundary(tenant, principal, workflow, routes[0]),
                self.boundary(tenant, principal, workflow, routes[0]),
            ),
        )
        for factory in factories:
            guard = self.guard(factory=factory)
            with self.subTest(factory=factory), self.assertRaisesRegex(
                    ValueError, "invalid_workflow_task_boundaries"):
                guard.start(tenant="tenant-a", principal="operator-a",
                            grants=frozenset({"ticket.write"}))

    def test_async_factory_and_reserved_control_name_are_rejected(self):
        async def async_factory(tenant, principal, workflow, routes):
            return ()

        with self.assertRaisesRegex(ValueError, "synchronous_task_boundary_factory_required"):
            self.guard(factory=async_factory)
        with self.assertRaisesRegex(ValueError, "invalid_orchestrator_registry"):
            self.guard(controls={"policy": self.policy, "task_boundary": self.policy})

    def test_constructor_preallocates_multi_tenant_vault_reservations(self):
        tools = (self.tool(name="tenant-a.ticket", tenant="tenant-a"),
                 self.tool(name="tenant-b.ticket", tenant="tenant-b"))
        guard = self.guard(tools=tools)
        one = guard.start(tenant="tenant-a", principal="operator-a",
                          grants=frozenset({"tenant-a.ticket"}))
        two = guard.start(tenant="tenant-b", principal="operator-b",
                          grants=frozenset({"tenant-b.ticket"}))
        self.assertNotEqual(one.agent_id, two.agent_id)

    def test_start_vault_configuration_failure_publishes_no_workflow(self):
        guard = self.guard()

        def failed(tenants):
            raise VaultError("tenant_reservation_mismatch")

        self.vault.configure_tenants = failed
        with self.assertRaisesRegex(VaultError, "tenant_reservation_mismatch"):
            guard.start(tenant="tenant-a", principal="operator-a",
                        grants=frozenset({"ticket.write"}))
        self.assertEqual(guard._agents, {})
        self.assertEqual(guard._workflows, {})
