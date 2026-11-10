"""Exact-action human approvals for GuardService routes.

A ticket binds tenant, principal, agent, route, operation, resource,
destination, policy version and the SHA-256 digest of the canonical request
payload. A human approver authenticates with a Guard-issued approver
credential scoped to tenants and must present the exact action digest shown by
review. Tickets are single use and expire. They live in memory by default; an
optional encrypted store makes the same API durable across local restarts.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import re
import secrets
import threading
import time

from .contracts import Action, ControlResult
from .approval_store import ApprovalStoreError
from .privacy import _CARD, _PATTERNS
from .runtime import AccessDenied

# Set by the service for the request being executed:
# (ticket or None, action digest, mutable per-request state).
CURRENT = contextvars.ContextVar("enkstein_guard_approval", default=(None, None, None))
_TICKET = re.compile(r"[A-Za-z0-9_-]{32,64}")


class ApprovalError(AccessDenied):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def action_binding(principal, route, payload, *, policy_version):
    """Return (binding, action digest) for a trusted principal and Route."""
    binding = {"tenant": principal.tenant_id, "principal": principal.principal_id, "agent": principal.agent_id,
               "route": route.name, "operation": route.operation, "resource": route.resource,
               "destination": route.destination, "policy_version": policy_version,
               "payload_sha256": hashlib.sha256(canonical(payload).encode()).hexdigest()}
    return binding, hashlib.sha256(canonical(binding).encode()).hexdigest()


def review_view(payload):
    """Payload for human review with detected sensitive spans masked."""
    def text(value):
        spans = []
        for pattern in _PATTERNS:
            spans.extend((m.start(), m.end()) for m in pattern.finditer(value))
        spans.extend((m.start(), m.end()) for m in _CARD.finditer(value))
        merged = []
        for start, end in sorted(spans):
            if merged and start < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        for start, end in reversed(merged):
            value = value[:start] + "[MASKED]" + value[end:]
        return value

    def walk(value, depth=0):
        if depth > 40:
            return "[MASKED]"
        if isinstance(value, str):
            return text(value)
        if type(value) is dict:
            return {key: walk(child, depth + 1) for key, child in value.items()}
        if type(value) is list:
            return [walk(child, depth + 1) for child in value]
        return value

    return walk(payload)


class ApprovalBook:
    def __init__(self, *, approvers, approver_digests, ttl=900, max_pending=1024, max_per_tenant=128,
                 clock=time.time, audit=None, store=None):
        """``approvers`` maps approver IDs to tenant sets; ``approver_digests``
        maps approver IDs to SHA-256 digests of their Guard-issued credentials."""
        if type(ttl) not in (int, float) or not 30 <= ttl <= 3600:
            raise ValueError("invalid_approval_ttl")
        self._approvers = {name: frozenset(tenants) for name, tenants in approvers.items()}
        self._digests = {name: digest for name, digest in approver_digests.items() if name in self._approvers}
        self.ttl, self._max, self._per_tenant = ttl, max_pending, max_per_tenant
        self._clock = clock
        self._audit = audit
        self._store = store
        self._tickets = {}
        self._lock = threading.Lock()

    def update(self, approvers, approver_digests):
        """Hot reload: new approver scopes/credentials apply to later decisions."""
        with self._lock:
            self._approvers = {name: frozenset(tenants) for name, tenants in approvers.items()}
            self._digests = {name: digest for name, digest in approver_digests.items() if name in self._approvers}

    def _purge(self):
        now = self._clock()
        for ticket in [t for t, item in self._tickets.items() if item["expires"] <= now or item["status"] == "consumed"]:
            del self._tickets[ticket]

    @staticmethod
    def _store_error(error):
        raise ApprovalError(str(error)) from None

    def _item(self, ticket):
        if self._store is None:
            return self._tickets.get(ticket)
        try:
            return self._store.get(ticket)
        except ApprovalStoreError as error:
            self._store_error(error)

    def _authenticate(self, credential):
        if not isinstance(credential, str) or len(credential) < 32:
            raise ApprovalError("approver_unauthenticated")
        digest = hashlib.sha256(credential.encode()).digest()
        for name, expected in self._digests.items():
            if hmac.compare_digest(expected, digest):
                return name
        raise ApprovalError("approver_unauthenticated")

    def request(self, binding, digest, view):
        with self._lock:
            if self._store is not None:
                created = self._clock()
                try:
                    item = self._store.request(binding, digest, view, expires=created + self.ttl,
                                               created=created, max_pending=self._max,
                                               max_per_tenant=self._per_tenant)
                except ApprovalStoreError as error:
                    self._store_error(error)
                return {"ticket": item["ticket"], "action_digest": digest,
                        "expires_at": int(item["expires"]), "status": item["status"]}
            self._purge()
            for ticket, item in self._tickets.items():
                if item["digest"] == digest and item["status"] in ("pending", "approved"):
                    return {"ticket": ticket, "action_digest": digest, "expires_at": int(item["expires"]),
                            "status": item["status"]}
            tenant_count = sum(1 for item in self._tickets.values() if item["binding"]["tenant"] == binding["tenant"])
            if len(self._tickets) >= self._max or tenant_count >= self._per_tenant:
                raise ApprovalError("approval_capacity_reached")
            ticket = secrets.token_urlsafe(32)
            self._tickets[ticket] = {"binding": dict(binding), "digest": digest, "view": view, "status": "pending",
                                     "expires": self._clock() + self.ttl, "created": self._clock()}
            return {"ticket": ticket, "action_digest": digest, "expires_at": int(self._tickets[ticket]["expires"]),
                    "status": "pending"}

    def pending(self, tenants=None):
        with self._lock:
            if self._store is not None:
                try:
                    items = self._store.pending(tenants, self._clock())
                except ApprovalStoreError as error:
                    self._store_error(error)
                return [{"ticket": item["ticket"], "action_digest": item["digest"],
                         "status": item["status"], "tenant": item["binding"]["tenant"],
                         "route": item["binding"]["route"], "agent": item["binding"]["agent"],
                         "expires_at": int(item["expires"])} for item in items]
            self._purge()
            return [{"ticket": ticket, "action_digest": item["digest"], "status": item["status"],
                     "tenant": item["binding"]["tenant"], "route": item["binding"]["route"],
                     "agent": item["binding"]["agent"], "expires_at": int(item["expires"])}
                    for ticket, item in sorted(self._tickets.items(), key=lambda kv: kv[1]["created"])
                    if tenants is None or item["binding"]["tenant"] in tenants]

    def _record(self, credential, ticket):
        approver = self._authenticate(credential)
        if not isinstance(ticket, str) or not _TICKET.fullmatch(ticket):
            raise ApprovalError("approval_forbidden")
        item = self._item(ticket)
        if (item is None or item["expires"] <= self._clock()
                or item["binding"]["tenant"] not in self._approvers.get(approver, ())):
            raise ApprovalError("approval_forbidden")
        return approver, item

    def review(self, credential, ticket):
        with self._lock:
            approver, item = self._record(credential, ticket)
            return {"ticket": ticket, "action_digest": item["digest"], "ticket_status": item["status"],
                    "binding": dict(item["binding"]), "payload": item["view"], "expires_at": int(item["expires"]),
                    "reviewer": approver}

    def decide(self, credential, ticket, action_digest, decision):
        if decision not in ("approve", "deny"):
            raise ApprovalError("invalid_decision")
        with self._lock:
            approver, item = self._record(credential, ticket)
            if not isinstance(action_digest, str) or not hmac.compare_digest(action_digest, item["digest"]):
                raise ApprovalError("action_digest_mismatch")
            if item["status"] != "pending":
                raise ApprovalError("approval_not_pending")
            status = "approved" if decision == "approve" else "denied"
            approver_digest = self._digests[approver].hex()
            if self._store is not None:
                try:
                    item = self._store.decide(ticket, action_digest, status, approver,
                                              approver_digest, self._clock())
                except ApprovalStoreError as error:
                    self._store_error(error)
            else:
                item["status"] = status
                item["approver"] = approver
                item["approver_digest"] = approver_digest
            result = {"ticket": ticket, "ticket_status": item["status"], "approver_id": approver,
                      "action_digest": item["digest"], "tenant": item["binding"]["tenant"]}
        if self._audit is not None:
            self._audit({"event": "approval_decision", "outcome": "approval_" + result["ticket_status"],
                         "tenant_id": result["tenant"], "approver_id": approver,
                         "ticket_digest": hashlib.sha256(ticket.encode()).hexdigest(),
                         "action_digest": result["action_digest"]})
        return result

    # -- runtime hooks ---------------------------------------------------
    def _matches(self, operation, item):
        binding, context = item["binding"], operation.context
        return (binding["tenant"] == context.tenant_id and binding["principal"] == context.principal_id
                and binding["agent"] == context.agent_id and binding["route"] == operation.route
                and binding["resource"] == operation.resource and binding["destination"] == operation.destination
                and binding["operation"] == context.operation and binding["policy_version"] == context.policy_version)

    def _approval_current(self, item):
        approver = item.get("approver")
        expected = self._digests.get(approver)
        stored = item.get("approver_digest")
        return bool(approver and expected is not None and isinstance(stored, str)
                    and item["binding"]["tenant"] in self._approvers.get(approver, ())
                    and hmac.compare_digest(stored, expected.hex()))

    def satisfied(self, operation):
        """Route.approval hook: True when an approved, unexpired ticket for this
        exact action is attached to the current request."""
        ticket, digest, state = CURRENT.get()
        if ticket is None or digest is None or state is None:
            return False
        with self._lock:
            item = self._item(ticket)
            valid = bool(item and item["status"] == "approved" and item["expires"] > self._clock()
                         and hmac.compare_digest(item["digest"], digest) and self._matches(operation, item)
                         and self._approval_current(item))
        if valid:
            state["used"] = True
        return valid

    def consume(self, operation):
        """Route.pre_dispatch hook: atomically consume the ticket that satisfied
        this request's approval requirement, or deny. No-op when no approval
        was needed (on-demand routes whose controls all allowed)."""
        ticket, digest, state = CURRENT.get()
        if not state or not state.get("used"):
            return
        with self._lock:
            item = self._item(ticket) if ticket is not None else None
            if not (item and item["status"] == "approved" and item["expires"] > self._clock()
                    and digest is not None and hmac.compare_digest(item["digest"], digest)
                    and self._matches(operation, item) and self._approval_current(item)):
                raise ApprovalError("approval_not_consumable")
            if self._store is not None:
                try:
                    self._store.consume(ticket, digest, self._clock(), item["approver"],
                                        item["approver_digest"])
                except ApprovalStoreError as error:
                    self._store_error(error)
            else:
                item["status"] = "consumed"


def approval_required_control(name="approval"):
    """Control for routes configured with approval required."""
    async def control(operation):
        return ControlResult(name, operation.context.tenant_id, operation.context.operation_id,
                             Action.REQUIRE_APPROVAL)
    return control
