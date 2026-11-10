import hashlib
import json
import unittest

from enkstein_guard.approvals import CURRENT, ApprovalBook, ApprovalError, action_binding, review_view
from enkstein_guard.contracts import SecurityContext
from enkstein_guard.runtime import Operation, Principal, Route

APPROVER = "egh_" + "h" * 43
OTHER_TENANT_APPROVER = "egh_" + "o" * 43
AGENT = "ega_" + "a" * 43


async def transport(operation):
    return {}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.events = []
        self.book = ApprovalBook(approvers={"alice": ["tenant-a"], "bob": ["tenant-b"]},
                                 approver_digests={"alice": hashlib.sha256(APPROVER.encode()).digest(),
                                                   "bob": hashlib.sha256(OTHER_TENANT_APPROVER.encode()).digest()},
                                 ttl=60, clock=self.clock, audit=self.events.append, max_per_tenant=3)
        self.principal = Principal("tenant-a", "support-bot", "agent-a", frozenset({"ticket.close"}))
        self.route = Route("ticket.close", "ticket.close", "support-ticket", "internal-ticket-service", "tenant-a",
                           ("approval",), transport)
        self.payload = {"ticket": "INC-42", "note": "Customer jane@example.com confirmed"}

    def ticket(self, payload=None):
        binding, digest = action_binding(self.principal, self.route, payload or self.payload, policy_version="cfg-1")
        return binding, digest, self.book.request(binding, digest, review_view(payload or self.payload))

    def operation(self, principal=None):
        principal = principal or self.principal
        context = SecurityContext(principal.tenant_id, principal.principal_id, principal.agent_id, "w", "op",
                                  "ticket.close", "cfg-1")
        return Operation(context, "ticket.close", "support-ticket", "internal-ticket-service", "{}", "d")

    def test_review_masks_sensitive_values_and_binds_exact_action(self):
        _, digest, ticket = self.ticket()
        view = self.book.review(APPROVER, ticket["ticket"])
        self.assertEqual(view["action_digest"], digest)
        self.assertNotIn("jane@example.com", json.dumps(view))
        self.assertEqual(view["binding"]["route"], "ticket.close")

    def test_exact_digest_and_single_use(self):
        _, digest, ticket = self.ticket()
        with self.assertRaises(ApprovalError):
            self.book.decide(APPROVER, ticket["ticket"], "0" * 64, "approve")
        self.book.decide(APPROVER, ticket["ticket"], digest, "approve")
        state = {}
        CURRENT.set((ticket["ticket"], digest, state))
        self.assertTrue(self.book.satisfied(self.operation()))
        self.book.consume(self.operation())
        self.assertFalse(self.book.satisfied(self.operation()))
        with self.assertRaises(ApprovalError):
            self.book.consume(self.operation())
        self.assertEqual(self.events[0]["outcome"], "approval_approved")
        self.assertNotIn(ticket["ticket"], json.dumps(self.events))

    def test_substituted_payload_does_not_match(self):
        _, digest, ticket = self.ticket()
        self.book.decide(APPROVER, ticket["ticket"], digest, "approve")
        _, other_digest = action_binding(self.principal, self.route, {"ticket": "INC-43"}, policy_version="cfg-1")
        CURRENT.set((ticket["ticket"], other_digest, {}))
        self.assertFalse(self.book.satisfied(self.operation()))

    def test_other_agent_cannot_use_ticket(self):
        _, digest, ticket = self.ticket()
        self.book.decide(APPROVER, ticket["ticket"], digest, "approve")
        CURRENT.set((ticket["ticket"], digest, {}))
        other = Principal("tenant-a", "support-bot", "agent-b", frozenset({"ticket.close"}))
        self.assertFalse(self.book.satisfied(self.operation(other)))

    def test_agent_credential_and_cross_tenant_approver_rejected(self):
        _, digest, ticket = self.ticket()
        for credential in (AGENT, OTHER_TENANT_APPROVER, "short", None):
            with self.subTest(credential=credential):
                with self.assertRaises(ApprovalError):
                    self.book.decide(credential, ticket["ticket"], digest, "approve")

    def test_expiry_and_denial(self):
        _, digest, ticket = self.ticket()
        self.book.decide(APPROVER, ticket["ticket"], digest, "deny")
        CURRENT.set((ticket["ticket"], digest, {}))
        self.assertFalse(self.book.satisfied(self.operation()))
        _, digest2, ticket2 = self.ticket({"ticket": "INC-44"})
        self.clock.now += 61
        with self.assertRaises(ApprovalError):
            self.book.decide(APPROVER, ticket2["ticket"], digest2, "approve")

    def test_duplicate_request_reuses_ticket_and_capacity_bounded(self):
        _, _, first = self.ticket()
        _, _, again = self.ticket()
        self.assertEqual(first["ticket"], again["ticket"])
        for number in range(2):
            self.ticket({"ticket": "INC-%d" % number})
        with self.assertRaises(ApprovalError):
            self.ticket({"ticket": "INC-overflow"})

    def test_consume_without_use_is_noop_for_on_demand_routes(self):
        CURRENT.set((None, "digest", {}))
        self.book.consume(self.operation())  # No approval was required.
