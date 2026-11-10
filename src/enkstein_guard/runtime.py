"""Application execution boundary for trusted hosts, not a Python sandbox.

Register transports and credentials in trusted bootstrap code. Untrusted callers
may submit only a credential, route name and JSON payload. They cannot submit
identities, control results, approval assertions or transport implementations.
"""

import asyncio
from dataclasses import dataclass, field
import hashlib
import inspect
import json
import secrets
from types import MappingProxyType
from typing import Awaitable, Callable, Mapping

from .contracts import Action, ControlResult, SecurityContext, Status, combine_results


class GuardError(Exception):
    """Public errors contain fixed reason codes, never transport exceptions."""


class AccessDenied(GuardError):
    pass


class RejectedBeforeDispatch(AccessDenied):
    """Raised by a trusted transport that refused the request before any side
    effect (for example request validation). Reported as a denial, not as an
    unknown outcome. Never raise it after an external call was attempted."""


class UnavailableBeforeDispatch(GuardError):
    """A required store (audit, vault, outcome ledger) failed before dispatch.

    Nothing was sent, so this is neither a policy denial nor an unknown
    outcome; the request may be retried later. Fixed reason codes only.
    """


class ApprovalRequired(AccessDenied):
    """Controls require a bound human approval; nothing was dispatched.

    Subclasses AccessDenied so callers that do not support approvals keep
    denying. ``reason_codes`` and ``operation_id`` are fixed identifiers only.
    """

    def __init__(self, operation_id: str, reason_codes: tuple[str, ...] = ()):
        super().__init__("approval_required")
        self.operation_id = operation_id
        self.reason_codes = tuple(reason_codes)


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    principal_id: str
    agent_id: str
    allowed_routes: frozenset[str]

    def __post_init__(self):
        # Use the context validator; caller identity is configured by the host.
        SecurityContext(self.tenant_id, self.principal_id, self.agent_id, "validation", "validation", "validation", "v1")
        object.__setattr__(self, "allowed_routes", frozenset(self.allowed_routes))


@dataclass(frozen=True)
class Operation:
    context: SecurityContext
    route: str
    resource: str
    destination: str
    payload_json: str = field(repr=False)
    digest: str

    def payload(self):
        """Return a fresh copy so inspection cannot change executor input."""
        return json.loads(self.payload_json)


Control = Callable[[Operation], Awaitable[ControlResult]]
Transport = Callable[[Operation], Awaitable[object]]


@dataclass(frozen=True)
class Route:
    name: str
    operation: str
    resource: str
    destination: str
    tenant_id: str
    required_controls: tuple[str, ...]
    transport: Transport = field(repr=False)
    prepare_payload: Callable[[Operation], dict] | None = field(default=None, repr=False)
    # Trusted host hooks: ``approval`` may satisfy a REQUIRE_APPROVAL decision
    # with a verified bound human approval (never a denial). ``pre_dispatch``
    # runs after authorization and before the transport; raising denies the
    # request with no side effect.
    approval: Callable[[Operation], bool] | None = field(default=None, repr=False)
    pre_dispatch: Callable[[Operation], None] | None = field(default=None, repr=False)

    def __post_init__(self):
        for value in (self.name, self.operation, self.resource, self.destination, self.tenant_id):
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError("invalid_route")
        object.__setattr__(self, "required_controls", tuple(self.required_controls))
        if not self.required_controls or len(set(self.required_controls)) != len(self.required_controls):
            raise ValueError("invalid_required_controls")
        if not inspect.iscoroutinefunction(self.transport):
            raise ValueError("async_transport_required")


class GuardRuntime:
    """Immutable registry with per-request auth, inspection and audit gates.

    Credentials are configured by trusted bootstrap, hashed in memory and never
    exposed in diagnostics. This local adapter does not replace OIDC/mTLS or
    credential rotation/revocation in a production network gateway.
    """

    def __init__(
        self, *, credentials: Mapping[str, Principal] | None = None, routes: tuple[Route, ...],
        controls: Mapping[str, Control], audit: Callable[[dict], None],
        policy_version: str = "1", control_timeout: float = 2.0,
        transport_timeout: float = 30.0, max_payload_bytes: int = 1_048_576,
        context_factory: Callable[[Principal, Route], SecurityContext] | None = None,
        credential_digests: Mapping[bytes, Principal] | None = None,
    ):
        """``credential_digests`` maps SHA-256 digests of host-issued tokens to
        principals so a host that stores only digests never handles plaintext."""
        if credentials is None and credential_digests is None:
            raise ValueError("invalid_credential_registration")
        if not callable(audit) or inspect.iscoroutinefunction(audit):
            raise ValueError("synchronous_audit_sink_required")
        for timeout in (control_timeout, transport_timeout):
            if type(timeout) not in (int, float) or not 0 < timeout <= 300:
                raise ValueError("invalid_timeout")
        if type(max_payload_bytes) is not int or not 0 < max_payload_bytes <= 16_777_216:
            raise ValueError("invalid_payload_limit")
        SecurityContext("bootstrap", "bootstrap", "bootstrap", "bootstrap", "bootstrap", "bootstrap", policy_version)
        registry = {route.name: route for route in routes}
        if len(registry) != len(routes):
            raise ValueError("duplicate_route")
        for route in routes:
            for name in route.required_controls:
                if name not in controls or not inspect.iscoroutinefunction(controls[name]):
                    raise ValueError("required_control_unavailable")
        identities = {}
        for token, principal in (credentials or {}).items():
            if not isinstance(token, str) or len(token) < 32 or not isinstance(principal, Principal):
                raise ValueError("invalid_credential_registration")
            if not principal.allowed_routes <= registry.keys():
                raise ValueError("unknown_route_grant")
            identities[hashlib.sha256(token.encode()).digest()] = principal
        for digest, principal in (credential_digests or {}).items():
            if (type(digest) is not bytes or len(digest) != 32 or digest in identities
                    or not isinstance(principal, Principal)):
                raise ValueError("invalid_credential_registration")
            if not principal.allowed_routes <= registry.keys():
                raise ValueError("unknown_route_grant")
            identities[digest] = principal
        self._identities = MappingProxyType(identities)
        self._routes = MappingProxyType(registry)
        self._controls = MappingProxyType(dict(controls))
        self._audit = audit
        self._policy_version = policy_version
        self._control_timeout = control_timeout
        self._transport_timeout = transport_timeout
        self._max_payload_bytes = max_payload_bytes
        self._context_factory = context_factory

    def _record(self, operation: Operation, outcome: str, decision=None, results=(), reason_codes=()):
        # No payload, token, detector message or arbitrary exception text.
        # Only fixed identifiers: route/control names and reason codes come
        # from trusted bootstrap, never from the caller.
        event = {"operation_id": operation.context.operation_id,
                 "tenant_id": operation.context.tenant_id,
                 "principal_id": operation.context.principal_id,
                 "agent_id": operation.context.agent_id,
                 "route": operation.route,
                 "operation": operation.context.operation,
                 "policy_version": self._policy_version,
                 "action_digest": operation.digest, "outcome": outcome}
        if reason_codes:
            event["reason_codes"] = list(reason_codes)
        if decision is not None:
            event["decision"] = decision.action.value
            event["reason_codes"] = list(decision.reason_codes)
            event["controls"] = [{"id": item.control_id, "action": item.action.value, "status": item.status.value}
                                 for item in results]
        try:
            result = self._audit(event)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise ValueError("async_audit_not_supported")
            if result is False:
                raise ValueError("audit_rejected")
        except Exception:
            raise GuardError("audit_unavailable") from None

    def _record_before_dispatch(self, operation: Operation, outcome: str, decision=None, results=(), reason_codes=()):
        """Audit is required before any dispatch; its failure stops the request
        with nothing sent, reported distinctly from denials and unknown outcomes."""
        try:
            self._record(operation, outcome, decision, results, reason_codes)
        except GuardError:
            raise UnavailableBeforeDispatch("audit_unavailable") from None

    def registered_tenants(self):
        """Trusted-host inventory for reserving shared service capacity."""
        return frozenset(principal.tenant_id for principal in self._identities.values())

    def describe(self):
        """Secret-free registry summary for operator diagnostics."""
        return {"policy_version": self._policy_version,
                "identities": len(self._identities),
                "routes": [{"name": route.name, "operation": route.operation, "resource": route.resource,
                            "destination": route.destination, "tenant_id": route.tenant_id,
                            "required_controls": list(route.required_controls)}
                           for route in sorted(self._routes.values(), key=lambda item: item.name)]}

    def route(self, name):
        return self._routes.get(name)

    def authorize(self, credential: str, route_name: str) -> Principal:
        if not isinstance(credential, str):
            raise AccessDenied("unauthenticated")
        principal = self._identities.get(hashlib.sha256(credential.encode()).digest())
        if principal is None:
            raise AccessDenied("unauthenticated")
        if not isinstance(route_name, str):
            raise AccessDenied("route_forbidden")
        route = self._routes.get(route_name)
        if route is None or route_name not in principal.allowed_routes or route.tenant_id != principal.tenant_id:
            raise AccessDenied("route_forbidden")
        return principal

    async def execute(self, credential: str, route_name: str, payload: dict):
        principal = self.authorize(credential, route_name)
        route = self._routes[route_name]
        if type(payload) is not dict:
            raise AccessDenied("invalid_payload")
        try:
            frozen = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
            if len(frozen.encode()) > self._max_payload_bytes:
                raise ValueError()
        except (ValueError, TypeError, RecursionError):
            raise AccessDenied("invalid_payload") from None
        context = SecurityContext(principal.tenant_id, principal.principal_id, principal.agent_id,
                                  secrets.token_hex(16), secrets.token_hex(16), route.operation, self._policy_version)
        if self._context_factory is not None:
            context = self._context_factory(principal, route)
            if (not isinstance(context, SecurityContext) or context.tenant_id != principal.tenant_id
                    or context.principal_id != principal.principal_id or context.agent_id != principal.agent_id
                    or context.operation != route.operation):
                raise AccessDenied("invalid_host_context")
        binding = json.dumps({"context": vars(context), "route": route.name,
                              "resource": route.resource, "destination": route.destination,
                              "payload": frozen}, sort_keys=True, separators=(",", ":"))
        operation = Operation(context, route.name, route.resource, route.destination, frozen,
                              hashlib.sha256(binding.encode()).hexdigest())
        if route.prepare_payload is not None:
            try:
                prepared = route.prepare_payload(operation)
                if type(prepared) is not dict:
                    raise ValueError()
                frozen = json.dumps(prepared, sort_keys=True, separators=(",", ":"), allow_nan=False)
                if len(frozen.encode()) > self._max_payload_bytes:
                    raise ValueError()
                binding = json.dumps({"context": vars(context), "route": route.name,
                                      "resource": route.resource, "destination": route.destination,
                                      "payload": frozen}, sort_keys=True, separators=(",", ":"))
                operation = Operation(context, route.name, route.resource, route.destination, frozen,
                                      hashlib.sha256(binding.encode()).hexdigest())
            except UnavailableBeforeDispatch:
                self._record_before_dispatch(operation, "preparation_unavailable_no_execution")
                raise
            except Exception:
                self._record_before_dispatch(operation, "preparation_denied")
                raise AccessDenied("preparation_denied") from None
        results = []
        for name in route.required_controls:
            try:
                result = await asyncio.wait_for(self._controls[name](operation), self._control_timeout)
                if not isinstance(result, ControlResult) or result.control_id != name:
                    raise ValueError()
            except TimeoutError:
                result = ControlResult(name, context.tenant_id, context.operation_id, Action.DENY, Status.TIMEOUT)
            except Exception:
                result = ControlResult(name, context.tenant_id, context.operation_id, Action.DENY, Status.ERROR)
            results.append(result)
        decision = combine_results(context, results, required_controls=route.required_controls)
        outcome = "authorized"
        if decision.action == Action.REQUIRE_APPROVAL:
            approved = False
            if route.approval is not None:
                try:
                    approved = route.approval(operation) is True
                except Exception:
                    approved = False
            if not approved:
                self._record_before_dispatch(operation, "approval_required", decision, results)
                raise ApprovalRequired(context.operation_id, decision.reason_codes)
            outcome = "authorized_with_approval"
        elif decision.action not in (Action.ALLOW, Action.MONITOR):
            self._record_before_dispatch(operation, "denied", decision, results)
            # Masking cannot be silently treated as completed.
            raise AccessDenied("control_denied")
        self._record_before_dispatch(operation, outcome, decision, results)
        if route.pre_dispatch is not None:
            try:
                route.pre_dispatch(operation)
            except Exception:
                self._record_before_dispatch(operation, "dispatch_denied")
                raise AccessDenied("dispatch_denied") from None
        try:
            result = await asyncio.wait_for(route.transport(operation), self._transport_timeout)
        except asyncio.CancelledError:
            self._record(operation, "execution_cancelled_outcome_unknown")
            raise
        except RejectedBeforeDispatch:
            self._record(operation, "transport_rejected_no_side_effect")
            raise AccessDenied("transport_rejected") from None
        except UnavailableBeforeDispatch as error:
            # Trusted transports raise this only before any external call.
            self._record_before_dispatch(operation, "transport_unavailable_no_execution", reason_codes=(str(error),))
            raise
        except Exception as error:
            # A fixed reason code from a trusted transport, never exception text.
            code = getattr(error, "reason_code", None)
            self._record(operation, "execution_failed_outcome_unknown",
                         reason_codes=(code,) if isinstance(code, str) else ())
            raise GuardError("execution_failed_outcome_unknown") from None
        try:
            self._record(operation, "transport_completed")
        except GuardError:
            raise GuardError("execution_completed_audit_unavailable") from None
        return result


async def local_prompt_control(operation: Operation) -> ControlResult:
    """Inspect all JSON text with built-in prompt rules; not a vault or firewall."""
    from .policy import scan_prompt
    # Local inspection is synchronous trusted code, not a hard-kill sandbox.
    decision = scan_prompt(operation.payload_json)
    return ControlResult("local_prompt", operation.context.tenant_id,
                         operation.context.operation_id, Action(decision.decision))
