import json
import unittest
from dataclasses import FrozenInstanceError

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.intent import FieldRule, TaskBoundary, intent_control
from enkstein_guard.runtime import AccessDenied, GuardRuntime, Operation, Principal, Route


class IntentControlTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.boundary = TaskBoundary(
            tenant_id="tenant-a",
            principal_id="operator-a",
            workflow_id="workflow-42",
            route="ticket.write",
            resource="support-ticket",
            destination="internal-ticket-service",
            operations=frozenset({"ticket.update"}),
            fields=(
                FieldRule(("ticket", "id"), "str", choices=frozenset({"INC-42"}), max_length=32),
                FieldRule(("action",), "str", choices=frozenset({"comment"})),
                FieldRule(("comment",), "str", max_length=2000),
                FieldRule(("attempt",), "int", minimum=1, maximum=3, required=False),
                FieldRule(("notify",), "bool", required=False),
            ),
        )
        self.control = intent_control(self.boundary)

    def operation(self, payload, **changes):
        context = SecurityContext(
            changes.get("tenant_id", "tenant-a"),
            changes.get("principal_id", "operator-a"),
            "agent-a",
            changes.get("workflow_id", "workflow-42"),
            "operation-1",
            changes.get("operation", "ticket.update"),
            "v1",
        )
        return Operation(
            context,
            changes.get("route", "ticket.write"),
            changes.get("resource", "support-ticket"),
            changes.get("destination", "internal-ticket-service"),
            json.dumps(payload, allow_nan=True),
            "digest",
        )

    async def action(self, payload, **changes):
        return (await self.control(self.operation(payload, **changes))).action

    async def test_legitimate_ticket_comment_is_allowed(self):
        payload = {"ticket": {"id": "INC-42"}, "action": "comment", "comment": "Investigating now."}
        self.assertEqual(await self.action(payload), Action.ALLOW)

    async def test_control_connects_to_guard_runtime_and_blocks_before_transport(self):
        calls = []

        async def transport(operation):
            calls.append(operation.payload())
            return "written"

        token = "intent-test-credential-" + "x" * 32
        runtime = GuardRuntime(
            credentials={token: Principal("tenant-a", "operator-a", "agent-a",
                                          frozenset({"ticket.write"}))},
            routes=(Route("ticket.write", "ticket.update", "support-ticket",
                          "internal-ticket-service", "tenant-a", ("task_boundary",), transport),),
            controls={"task_boundary": self.control},
            audit=lambda event: None,
            context_factory=lambda principal, route: SecurityContext(
                principal.tenant_id, principal.principal_id, principal.agent_id,
                "workflow-42", "operation-1", route.operation, "1"),
        )
        valid = {"ticket": {"id": "INC-42"}, "action": "comment", "comment": "ok"}
        self.assertEqual(await runtime.execute(token, "ticket.write", valid), "written")
        with self.assertRaises(AccessDenied):
            await runtime.execute(token, "ticket.write", {**valid, "approved": True})
        self.assertEqual(calls, [valid])

    async def test_permitted_ticket_tool_cannot_close_the_wrong_ticket(self):
        payload = {"ticket": {"id": "INC-99"}, "action": "close", "comment": "done"}
        self.assertEqual(await self.action(payload), Action.DENY)

    async def test_unknown_approval_and_spoofed_context_fields_are_denied(self):
        base = {"ticket": {"id": "INC-42"}, "action": "comment", "comment": "ok"}
        for extra in ({"approved": True}, {"tenant_id": "tenant-a"},
                      {"context": {"workflow_id": "workflow-42"}}):
            with self.subTest(extra=extra):
                self.assertEqual(await self.action({**base, **extra}), Action.DENY)

    async def test_exact_host_context_and_route_binding_are_required(self):
        payload = {"ticket": {"id": "INC-42"}, "action": "comment", "comment": "ok"}
        changes = (
            {"tenant_id": "tenant-b"}, {"principal_id": "operator-b"},
            {"workflow_id": "workflow-other"}, {"operation": "ticket.delete"},
            {"route": "ticket.admin"}, {"resource": "other-ticket"},
            {"destination": "external-service"},
        )
        for change in changes:
            with self.subTest(change=change):
                self.assertEqual(await self.action(payload, **change), Action.DENY)

    async def test_string_integer_and_boolean_rules_are_strict(self):
        base = {"ticket": {"id": "INC-42"}, "action": "comment", "comment": "ok"}
        valid = {**base, "attempt": 2, "notify": True}
        self.assertEqual(await self.action(valid), Action.ALLOW)
        invalid = (
            {**base, "comment": "x" * 2001},
            {**base, "attempt": 0},
            {**base, "attempt": 4},
            {**base, "attempt": True},
            {**base, "notify": 1},
            {**base, "attempt": 1.0},
            {**base, "attempt": float("nan")},
            {**base, "attempt": float("inf")},
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                self.assertEqual(await self.action(payload), Action.DENY)

    async def test_missing_required_nested_fields_and_non_dict_nodes_are_denied(self):
        for payload in (
            {"action": "comment", "comment": "ok"},
            {"ticket": {}, "action": "comment", "comment": "ok"},
            {"ticket": ["INC-42"], "action": "comment", "comment": "ok"},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(await self.action(payload), Action.DENY)

    async def test_constructor_inputs_are_snapshotted_and_instances_are_frozen(self):
        choices = ["INC-42"]
        operations = {"ticket.update"}
        fields = [FieldRule(("ticket_id",), "str", choices=choices)]
        boundary = TaskBoundary("tenant-a", "operator-a", "workflow-42", "ticket.write",
                                "support-ticket", "internal-ticket-service", operations, fields)
        control = intent_control(boundary)

        choices.append("INC-99")
        operations.add("ticket.delete")
        fields.clear()
        allowed = self.operation({"ticket_id": "INC-42"})
        denied = self.operation({"ticket_id": "INC-99"}, operation="ticket.delete")
        self.assertEqual((await control(allowed)).action, Action.ALLOW)
        self.assertEqual((await control(denied)).action, Action.DENY)
        with self.assertRaises(FrozenInstanceError):
            boundary.route = "ticket.admin"
        with self.assertRaises(FrozenInstanceError):
            boundary.fields[0].required = False


class IntentConfigurationTests(unittest.TestCase):
    def boundary(self, fields=()):
        return TaskBoundary("tenant-a", "operator-a", "workflow-42", "ticket.write",
                            "support-ticket", "internal-ticket-service",
                            frozenset({"ticket.update"}), fields)

    def test_duplicate_and_conflicting_paths_are_rejected(self):
        invalid = (
            (FieldRule(("ticket", "id"), "str"), FieldRule(("ticket", "id"), "str")),
            (FieldRule(("ticket",), "str"), FieldRule(("ticket", "id"), "str")),
            (FieldRule(("ticket", "id"), "str"), FieldRule(("ticket",), "str")),
        )
        for fields in invalid:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.boundary(fields)

    def test_invalid_rule_configuration_is_rejected(self):
        class CallerRule(FieldRule):
            def accepts(self, value):
                return True

        constructors = (
            lambda: FieldRule(["ticket"], "str"),
            lambda: FieldRule((), "str"),
            lambda: FieldRule(("ticket",), "float"),
            lambda: FieldRule(("attempt",), "int", minimum=True),
            lambda: FieldRule(("attempt",), "int", minimum=4, maximum=3),
            lambda: FieldRule(("notify",), "bool", maximum=1),
            lambda: FieldRule(("comment",), "str", max_length=-1),
            lambda: FieldRule(("attempt",), "int", choices=(True,)),
            lambda: FieldRule(("comment",), "str", choices=()),
            lambda: self.boundary((CallerRule(("comment",), "str"),)),
        )
        for constructor in constructors:
            with self.subTest(constructor=constructor), self.assertRaises(ValueError):
                constructor()

    def test_boundary_strings_and_control_name_are_strictly_bounded(self):
        with self.assertRaises(ValueError):
            TaskBoundary(" tenant-a", "operator-a", "workflow-42", "ticket.write",
                         "support-ticket", "internal-ticket-service", {"ticket.update"})
        with self.assertRaises(ValueError):
            TaskBoundary("tenant-a", "operator-a", "workflow-42", "ticket.write",
                         "support-ticket", "internal-ticket-service", set())
        with self.assertRaises(ValueError):
            intent_control(self.boundary(), name="bad\nname")
