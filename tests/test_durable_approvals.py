import hashlib
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet

from enkstein_guard.approval_store import ApprovalStoreError, DurableApprovalStore
from enkstein_guard.approvals import CURRENT, ApprovalBook, ApprovalError, action_binding, review_view
from enkstein_guard.contracts import SecurityContext
from enkstein_guard.runtime import Operation, Principal, Route


APPROVER = "egh_" + "h" * 43
ROTATED = "egh_" + "r" * 43


async def transport(operation):
    return {}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class DurableApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.database, self.key = root / "state/approvals.sqlite3", root / "keys/approvals.key"
        self.store = DurableApprovalStore.initialize(self.database, self.key)
        self.clock = Clock()
        self.principal = Principal("tenant-a", "support-bot", "agent-a", frozenset({"ticket.close"}))
        self.route = Route("ticket.close", "ticket.close", "support-ticket", "internal-ticket-service",
                           "tenant-a", ("approval",), transport)
        self.payload = {"ticket": "INC-42", "note": "Customer jane@example.com confirmed"}

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def digests(credential=APPROVER):
        return {"alice": hashlib.sha256(credential.encode()).digest()}

    def book(self, store=None, *, approvers=None, credential=APPROVER, maximum=8, per_tenant=4):
        return ApprovalBook(approvers=approvers or {"alice": ["tenant-a", "tenant-b", "tenant-c"]},
                            approver_digests=self.digests(credential), ttl=60, clock=self.clock,
                            max_pending=maximum, max_per_tenant=per_tenant,
                            store=store or self.store)

    def issue(self, book, payload=None, principal=None):
        payload, principal = payload or self.payload, principal or self.principal
        binding, digest = action_binding(principal, self.route, payload, policy_version="cfg-1")
        return digest, book.request(binding, digest, review_view(payload))

    def operation(self, principal=None):
        principal = principal or self.principal
        context = SecurityContext(principal.tenant_id, principal.principal_id, principal.agent_id,
                                  "workflow", "operation", "ticket.close", "cfg-1")
        return Operation(context, "ticket.close", "support-ticket", "internal-ticket-service", "{}", "d")

    def approve(self, book, digest, ticket):
        book.decide(APPROVER, ticket["ticket"], digest, "approve")

    def test_restart_preserves_approval_and_consumption_is_single_use(self):
        first = self.book()
        digest, ticket = self.issue(first)
        self.approve(first, digest, ticket)

        restarted = self.book(DurableApprovalStore(self.database, self.key))
        state = {}
        CURRENT.set((ticket["ticket"], digest, state))
        self.assertTrue(restarted.satisfied(self.operation()))
        restarted.consume(self.operation())

        after_consume = self.book(DurableApprovalStore(self.database, self.key))
        CURRENT.set((ticket["ticket"], digest, {}))
        self.assertFalse(after_consume.satisfied(self.operation()))

    def test_two_instances_racing_to_consume_only_dispatch_once(self):
        issuer = self.book()
        digest, ticket = self.issue(issuer)
        self.approve(issuer, digest, ticket)
        books = [self.book(DurableApprovalStore(self.database, self.key)) for _ in range(2)]
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def consume(book):
            state = {}
            CURRENT.set((ticket["ticket"], digest, state))
            satisfied = book.satisfied(self.operation())
            barrier.wait()
            try:
                book.consume(self.operation())
                result = "consumed" if satisfied else "unexpected"
            except ApprovalError:
                result = "rejected"
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=consume, args=(book,)) for book in books]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertCountEqual(outcomes, ["consumed", "rejected"])

    def test_exact_action_denial_and_expiry_survive_restart(self):
        book = self.book()
        digest, ticket = self.issue(book)
        book.decide(APPROVER, ticket["ticket"], digest, "deny")
        restarted = self.book(DurableApprovalStore(self.database, self.key))
        CURRENT.set((ticket["ticket"], digest, {}))
        self.assertFalse(restarted.satisfied(self.operation()))
        self.assertEqual(restarted.pending()[0]["status"], "denied")

        other_digest, other = self.issue(book, {"ticket": "INC-expire"})
        self.clock.now += 61
        with self.assertRaisesRegex(ApprovalError, "approval_forbidden"):
            restarted.decide(APPROVER, other["ticket"], other_digest, "approve")
        self.assertEqual(restarted.pending(), [])

    def test_tenant_and_global_capacity_are_transactional(self):
        book = self.book(maximum=2, per_tenant=1)
        self.issue(book, {"ticket": "A-1"})
        with self.assertRaisesRegex(ApprovalError, "approval_capacity_reached"):
            self.issue(book, {"ticket": "A-2"})

        tenant_b = Principal("tenant-b", "support-bot", "agent-b", frozenset({"ticket.close"}))
        self.issue(book, {"ticket": "B-1"}, tenant_b)
        tenant_c = Principal("tenant-c", "support-bot", "agent-c", frozenset({"ticket.close"}))
        with self.assertRaisesRegex(ApprovalError, "approval_capacity_reached"):
            self.issue(book, {"ticket": "C-1"}, tenant_c)

    def test_scope_or_credential_revocation_invalidates_approved_ticket(self):
        book = self.book()
        digest, ticket = self.issue(book)
        self.approve(book, digest, ticket)

        state = {}
        CURRENT.set((ticket["ticket"], digest, state))
        self.assertTrue(book.satisfied(self.operation()))
        book.update({"alice": ["tenant-b"]}, self.digests())
        with self.assertRaisesRegex(ApprovalError, "approval_not_consumable"):
            book.consume(self.operation())

        book.update({"alice": ["tenant-a"]}, self.digests(ROTATED))
        CURRENT.set((ticket["ticket"], digest, {}))
        self.assertFalse(book.satisfied(self.operation()))

    def test_restart_still_rejects_a_substituted_exact_action(self):
        book = self.book()
        digest, ticket = self.issue(book)
        self.approve(book, digest, ticket)
        _, substituted = action_binding(self.principal, self.route, {"ticket": "INC-43"},
                                        policy_version="cfg-1")
        restarted = self.book(DurableApprovalStore(self.database, self.key))
        CURRENT.set((ticket["ticket"], substituted, {}))
        self.assertFalse(restarted.satisfied(self.operation()))

    def test_sensitive_review_is_encrypted_and_tampering_fails_closed(self):
        book = self.book()
        self.issue(book)
        self.assertNotIn(b"jane@example.com", self.database.read_bytes())
        with closing(sqlite3.connect(self.database)) as connection:
            name = connection.execute("SELECT id FROM approvals").fetchone()[0]
            connection.execute("UPDATE approvals SET record=? WHERE id=?", (b"tampered", name))
            connection.commit()
        with self.assertRaisesRegex(ApprovalError, "approval_store_integrity_failed"):
            book.pending()

    def test_missing_or_replaced_key_fails_closed_without_regeneration(self):
        original = self.key.read_bytes()
        self.key.write_bytes(Fernet.generate_key())
        with self.assertRaises(ApprovalStoreError):
            DurableApprovalStore(self.database, self.key)
        self.key.write_bytes(original)
        self.key.unlink()
        with self.assertRaises(ApprovalStoreError):
            DurableApprovalStore(self.database, self.key)
        self.assertTrue(self.database.exists())

    def test_sqlite_write_failure_is_not_treated_as_an_approval(self):
        book = self.book()
        binding, digest = action_binding(self.principal, self.route, self.payload, policy_version="cfg-1")
        with mock.patch("enkstein_guard.approval_store.sqlite3.connect",
                        side_effect=sqlite3.OperationalError("database or disk is full")):
            with self.assertRaisesRegex(ApprovalError, "approval_storage_unavailable"):
                book.request(binding, digest, review_view(self.payload))


if __name__ == "__main__":
    unittest.main()
