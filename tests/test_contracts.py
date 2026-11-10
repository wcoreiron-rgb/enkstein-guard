import unittest
from itertools import permutations

from enkstein_guard.contracts import (
    Action, ControlResult, SecurityContext, Status, combine_results,
)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.context = SecurityContext("tenant-a", "user", "agent", "workflow", "op", "tool", "v1")

    def result(self, name, action=Action.ALLOW, status=Status.OK, tenant="tenant-a", operation="op"):
        return ControlResult(name, tenant, operation, action, status)

    def combine(self, results, required=("policy",)):
        return combine_results(self.context, results, required_controls=required)

    def test_deny_wins_independent_of_order(self):
        items = [self.result("policy"), self.result("inspection", Action.DENY),
                 self.result("approval", Action.REQUIRE_APPROVAL)]
        for order in permutations(items):
            self.assertEqual(self.combine(order).action, Action.DENY)

    def test_missing_required_control_denies(self):
        self.assertIn("required_control_missing", self.combine([]).reason_codes)

    def test_required_failure_denies_all_statuses(self):
        for status in (Status.ERROR, Status.TIMEOUT, Status.UNAVAILABLE):
            decision = self.combine([self.result("policy", status=status)])
            self.assertEqual(decision.action, Action.DENY)
            self.assertTrue(decision.degraded)

    def test_tenant_or_operation_mismatch_denies(self):
        for result in (self.result("policy", tenant="other"), self.result("policy", operation="other")):
            self.assertIn("context_mismatch", self.combine([result]).reason_codes)

    def test_duplicate_control_denies(self):
        self.assertEqual(self.combine([self.result("policy"), self.result("policy")]).action, Action.DENY)

    def test_empty_required_set_does_not_authorize(self):
        self.assertEqual(self.combine([self.result("optional")], required=()).action, Action.DENY)

    def test_optional_failure_is_visible(self):
        result = self.combine([self.result("policy"), self.result("optional", status=Status.TIMEOUT)])
        self.assertEqual(result.action, Action.ALLOW)
        self.assertTrue(result.degraded)

    def test_approval_and_mask_are_not_dropped(self):
        for action in (Action.REQUIRE_APPROVAL, Action.MASK):
            self.assertEqual(self.combine([self.result("policy", action)]).action, action)

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            self.result("policy", "unknown")

    def test_empty_identity_rejected(self):
        with self.assertRaises(ValueError):
            SecurityContext("", "user", "agent", "workflow", "op", "tool", "v1")
