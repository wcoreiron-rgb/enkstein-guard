"""Configuration-driven trusted host for the enkstein-guard CLI.

Builds GuardRuntime routes, controls and connectors from a validated product
configuration, hosts them behind GuardService (peer-bound in production), and
exposes a private admin socket for status, readiness, reload, shutdown,
approvals and maintenance. Bootstrap, configuration and this process are
trusted; agents are not.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import contextvars
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import struct
import sys
import time

from . import __version__
from .approval_store import ApprovalStore
from .ai_security import AISecurityControl
from .approvals import CURRENT as APPROVAL, ApprovalBook, ApprovalError, action_binding, approval_required_control, review_view
from .audit import DurableAudit
from .contracts import Action, ControlResult, SecurityContext, combine_results
from .egress import EgressClient, network_interfaces
from .identities import IdentityStore, SecretBroker, SecretStore
from .intent import FieldRule, TaskBoundary, intent_control
from .outcomes import OutcomeError, OutcomeLedger
from .privacy import Tokenizer
from .productconfig import PRODUCTION, ProductConfig, load as load_config, outcome_sizing
from .retrieval import DocumentStore, LocalRetrieval, RetrievalLedger, check_grounding
from .security_assessment import ChatSecurityAnalyzer, InspectionBoundaryError
from .security_context import SecurityHistoryError, SecurityHistoryStore
from .runtime import (AccessDenied, ApprovalRequired, GuardError, GuardRuntime, Operation, Principal, RejectedBeforeDispatch,
                      Route, UnavailableBeforeDispatch, local_prompt_control)
from .sensitivity import (Classifier, DeclaredContext, DeclaredEntry, FieldLevel, TaintError, TaintStore, agent_key,
                          highest, permits, rank, sensitivity_control)
from .service import GuardService
from .vault import LocalVault, Scope, VaultError, _check_private

# Vault failures that are storage or capacity problems rather than a refusal of
# the payload: reported as unavailable (nothing sent), not as a policy denial.
VAULT_UNAVAILABLE = frozenset({"vault_write_failed", "vault_unreadable", "vault_key_unavailable",
                               "vault_capacity_exceeded", "vault_integrity_failed", "tenant_not_reserved"})


class RateLimiter:
    """Per-agent token buckets that share ``service.max_requests_per_second``.

    Each configured agent receives an equal share, so the configured rate bounds
    total admitted tracked requests (the outcome-ledger sizing input) and one
    agent cannot consume another agent's share. ``None`` disables limiting.
    """

    def __init__(self, rate, agents, *, clock=time.monotonic):
        self.rate = rate
        self.share = rate / max(1, len(agents)) if rate else None
        self.burst = max(1.0, self.share * 2) if rate else None
        self._clock = clock
        self._buckets = {}
        self.limited = 0

    def allow(self, agent_id):
        if self.rate is None:
            return True
        now = self._clock()
        tokens, last = self._buckets.get(agent_id, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.share)
        if tokens < 1:
            self._buckets[agent_id] = (tokens, now)
            self.limited += 1
            return False
        self._buckets[agent_id] = (tokens - 1, now)
        return True

    def describe(self):
        return {"max_requests_per_second": self.rate, "per_agent_requests_per_second": self.share,
                "per_agent_burst": self.burst, "rate_limited": self.limited}

DIAGNOSTIC = contextvars.ContextVar("enkstein_guard_diagnostic", default=None)
RELEASE = contextvars.ContextVar("enkstein_guard_release", default=None)
SESSION_OPERATION = "service-session"


class HostError(Exception):
    """Fixed reason codes only."""


# -- state layout -------------------------------------------------------------
class StateLayout:
    def __init__(self, config: ProductConfig):
        state, keys = Path(config["paths"]["state_directory"]), Path(config["paths"]["key_directory"])
        self.state, self.keys = state, keys
        self.archive = Path(config["paths"]["archive_directory"])
        self.vault = (state / "vault" / "vault.sqlite3", keys / "vault.keyring")
        self.audit = (state / "audit" / "audit.sqlite3", keys / "audit.key")
        self.outcomes = (state / "outcomes" / "outcomes.sqlite3", keys / "outcomes.key")
        self.approvals = (state / "approvals" / "approvals.sqlite3", keys / "approvals.key")
        self.taint = (state / "taint" / "taint.sqlite3", keys / "taint.key")
        self.identities = (state / "identities" / "identities.json", keys / "identities.key")
        self.secrets = (state / "secrets" / "secrets.sqlite3", keys / "secrets.key")
        self.documents = (state / "documents" / "documents.sqlite3", keys / "documents.key")
        self.security_history = (state / "security-history" / "security.sqlite3", keys / "security-history.key")
        self.lock = state / "guard.lock"

    def stores(self):
        return {"vault": self.vault, "audit": self.audit, "outcomes": self.outcomes,
                "approvals": self.approvals, "taint": self.taint, "identities": self.identities,
                "secrets": self.secrets, "documents": self.documents, "security_history": self.security_history}


def _private_directory(path: Path, *, create):
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_private(path, directory=True)


def vault_limits(config):
    tenants = config["tenants"]
    if tenants and tenants[0]["vault_bytes"] is not None:
        limits = {t["id"]: t["vault_bytes"] for t in tenants}
    else:
        share = min(8_388_608, (config["vault"]["max_bytes"] // 2) // len(tenants))
        limits = {t["id"]: share for t in tenants}
    return {"max_bytes": config["vault"]["max_bytes"], "max_entries": config["vault"]["max_entries"],
            "tenant_limits": limits}


def security_history_limits(config):
    return {key: config["security_history"][key]
            for key in ("capacity", "ttl_seconds", "per_actor_capacity")}


def initialize_state(config: ProductConfig, *, adopt=False):
    """Exclusive creation of every store; never overwrites or regenerates keys.

    ``adopt`` (upgrade from an earlier release): stores whose database and key
    both exist are opened and verified instead of created; a store with only one
    of the two files present is refused. Nothing existing is modified except the
    outcome ledger's request-ID policy upgrade performed when it is opened.
    """
    layout = StateLayout(config)
    for directory in (layout.state, layout.keys, layout.archive):
        _private_directory(directory, create=True)
    stores = layout.stores()
    partial = [name for name, (data, key) in stores.items() if data.exists() != key.exists()]
    existing = [name for name, (data, key) in stores.items() if data.exists() and key.exists()]
    if partial:
        raise HostError("state_partially_present:" + ",".join(sorted(partial)))
    if existing and not adopt:
        raise HostError("state_already_initialized")
    created, adopted = [], []
    openers = {
        "vault": (lambda: LocalVault.initialize(*layout.vault, **vault_limits(config)),
                  lambda: LocalVault(*layout.vault, **vault_limits(config))),
        "audit": (lambda: DurableAudit.initialize(*layout.audit, full_verify_every=config["audit"]["full_verify_every"]),
                  lambda: DurableAudit(*layout.audit).verify(archives=layout.archive)),
        "outcomes": (lambda: OutcomeLedger.initialize(*layout.outcomes, maximum=config["outcomes"]["capacity"],
                                                      time_bound=config["outcomes"]["time_bound_request_ids"],
                                                      max_request_age=config["outcomes"]["max_request_age_seconds"],
                                                      clock_skew=config["outcomes"]["clock_skew_seconds"]),
                     lambda: OutcomeLedger(*layout.outcomes, maximum=config["outcomes"]["capacity"],
                                           time_bound=config["outcomes"]["time_bound_request_ids"],
                                           max_request_age=config["outcomes"]["max_request_age_seconds"],
                                           clock_skew=config["outcomes"]["clock_skew_seconds"])),
        "approvals": (lambda: ApprovalStore.initialize(*layout.approvals),
                      lambda: ApprovalStore(*layout.approvals).verify()),
        "taint": (lambda: TaintStore.initialize(*layout.taint), lambda: TaintStore(*layout.taint)),
        "identities": (lambda: IdentityStore.initialize(*layout.identities), lambda: IdentityStore(*layout.identities)),
        "secrets": (lambda: SecretStore.initialize(*layout.secrets), lambda: SecretStore(*layout.secrets)),
        "documents": (lambda: DocumentStore.initialize(*layout.documents), lambda: DocumentStore(*layout.documents)),
        "security_history": (lambda: SecurityHistoryStore.initialize(
                                 *layout.security_history, **security_history_limits(config)),
                             lambda: SecurityHistoryStore(
                                 *layout.security_history, **security_history_limits(config)).verify()),
    }
    for name, (create, open_existing) in openers.items():
        try:
            if name in existing:
                open_existing()
                adopted.append(name)
            else:
                create()
                created.append(name)
        except Exception:
            raise HostError("state_initialization_failed:%s;created:%s" % (name, ",".join(created))) from None
    audit = DurableAudit(*layout.audit)
    audit({"event": "state_adopted" if adopted else "state_initialized", "outcome": "initialized",
           "profile": config["profile"], "version": __version__, "count": len(adopted)})
    return {"stores": created, "adopted": adopted, "state_directory": str(layout.state),
            "key_directory": str(layout.keys), "audit_checkpoint": audit.verify()}


@contextmanager
def state_lock(config, *, blocking=False):
    """Single-owner lock held by the running service (and offline maintenance)."""
    layout = StateLayout(config)
    _private_directory(layout.state, create=False)
    fd = os.open(layout.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise HostError("unsafe_state_lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            raise HostError("service_running_or_state_locked") from None
        yield
    finally:
        os.close(fd)


def policy_version(config: ProductConfig):
    digest = hashlib.sha256(json.dumps(config.data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return "cfg-" + digest[:16]


# -- connectors and controls ---------------------------------------------------
def _fixture(behavior, timeout, delay=1):
    async def echo(operation):
        return {"accepted": True, "route": operation.route, "payload": operation.payload()}

    async def delayed(operation):
        # Synthetic slow-but-successful backend (acceptance only).
        await asyncio.sleep(delay)
        return await echo(operation)

    async def accept(operation):
        return {"accepted": True}

    async def fail(operation):
        raise RuntimeError("synthetic connector failure")

    async def slow(operation):
        await asyncio.sleep(timeout * 4)
        return {"accepted": True}

    return {"echo": echo, "accept": accept, "fail": fail, "slow": slow, "delay": delayed}[behavior]


class _ControlledSecurityProvider:
    """Apply the inspector route's deterministic controls before model dispatch.

    The supplied operation is the already-sanitized request constructed by
    ``ChatSecurityAnalyzer``.  This boundary intentionally does not enter the
    public runtime or create an identity/grant for the internal model route.
    """

    def __init__(self, provider, controls, required_controls, timeout):
        self._provider = provider
        self._controls = {name: controls[name] for name in required_controls}
        self._required = tuple(required_controls)
        self._timeout = timeout
        self.model = provider.model

    async def call(self, operation):
        try:
            if type(operation) is not Operation or type(operation.context) is not SecurityContext:
                raise ValueError()
            results = []
            for name in self._required:
                result = await asyncio.wait_for(self._controls[name](operation), self._timeout)
                if not isinstance(result, ControlResult) or result.control_id != name:
                    raise ValueError()
                results.append(result)
            decision = combine_results(
                operation.context, results, required_controls=self._required)
            if decision.degraded or decision.action not in (Action.ALLOW, Action.MONITOR):
                raise ValueError()
        except asyncio.CancelledError:
            # The analyzer's tighter deadline may cancel this phase before the
            # service-level control deadline.  That is still a deterministic
            # local-boundary failure, never model availability fallback.
            raise InspectionBoundaryError() from None
        except InspectionBoundaryError:
            raise
        except Exception:
            raise InspectionBoundaryError() from None
        # Provider/network failures remain assessment availability failures;
        # only deterministic local-boundary failures are non-overridable.
        return await self._provider.call(operation)


class Components:
    """Opened stores and derived policy objects for one configuration."""

    def __init__(self, config: ProductConfig):
        self.config = config
        self.layout = StateLayout(config)
        for directory in (self.layout.state, self.layout.keys):
            _private_directory(directory, create=False)
        self.vault = LocalVault(*self.layout.vault, **vault_limits(config))
        self.audit = DurableAudit(*self.layout.audit, full_verify_every=config["audit"]["full_verify_every"])
        self.outcomes = OutcomeLedger(*self.layout.outcomes, maximum=config["outcomes"]["capacity"],
                                      time_bound=config["outcomes"]["time_bound_request_ids"],
                                      max_request_age=config["outcomes"]["max_request_age_seconds"],
                                      clock_skew=config["outcomes"]["clock_skew_seconds"])
        self.approvals = ApprovalStore(*self.layout.approvals)
        self.taint = TaintStore(*self.layout.taint)
        self.identities = IdentityStore(*self.layout.identities)
        self.secrets = SecretStore(*self.layout.secrets)
        self.documents = DocumentStore(*self.layout.documents)
        self.security_history = SecurityHistoryStore(*self.layout.security_history, **security_history_limits(config))
        self.retrievals = RetrievalLedger()

    def classifier(self, config=None):
        config = config or self.config
        sensitivity = config["sensitivity"]
        entries = []
        for item in sensitivity["declared_context"]:
            path = Path(item["file"])
            data = path.read_bytes()
            if len(data) > 1_048_576:
                raise HostError("declared_context_too_large")
            entries.append(DeclaredEntry(item["name"], item["level"], data.decode("utf-8"), item.get("canary", False)))
        return Classifier(field_levels=[FieldLevel(tuple(r["path"]), r["level"]) for r in sensitivity["field_rules"]],
                          detected_level=sensitivity["detected_level"], secret_level=sensitivity["secret_level"],
                          declared=DeclaredContext(entries), heuristics=sensitivity["unlabelled_heuristics"])

    def egress_client(self, config=None):
        config = config or self.config
        if config["egress"]["mode"] != "proxy":
            return None
        return EgressClient(config["egress"]["socket"], timeout=config["egress"]["connect_timeout_seconds"])


class Policy:
    """GuardRuntime plus per-route metadata derived from one configuration."""

    def __init__(self, components: Components, config: ProductConfig, approvals: ApprovalBook):
        self.config = config
        self.version = policy_version(config)
        self.classifier = components.classifier(config)
        self.routes = {route["name"]: route for route in config["routes"]}
        self.agents = {agent["id"]: agent for agent in config["agents"]}
        tokenizer = Tokenizer(components.vault, ttl=config["vault"]["token_ttl_seconds"])
        egress = components.egress_client(config)
        broker = SecretBroker(components.secrets)
        clearances = {name: route["clearance"] for name, route in self.routes.items()}
        sensitivity = sensitivity_control(self.classifier, clearances, components.taint)
        restore_destinations = tuple(sorted({route["destination"] for route in config["routes"]
                                             if route["privacy"] == "restore"})) or ("guard-no-restore",)
        timeout = config["service"]["transport_timeout_seconds"]
        controls = {"local_prompt": local_prompt_control, "sensitivity": sensitivity,
                    "approval": approval_required_control()}
        if config["policy_engines"]:
            # Optional SDK loading is confined to the configured service-start
            # path. A configured required control is never silently omitted.
            from .agt_policy import AGTPolicyError, build_policy_control
            for definition in config["policy_engines"]:
                try:
                    control = build_policy_control(
                        definition, agents=config["agents"], routes=config["routes"])
                except AGTPolicyError as error:
                    raise HostError(str(error)) from None
                expected = "agt." + definition["name"]
                if not callable(control):
                    raise HostError("agt_policy_build_failed")
                controls[expected] = control
        boundaries = {}
        built = []
        connectors = {}
        chat_providers = {}
        for connector in config["connectors"]:
            kind = connector["type"]
            if kind == "fixture":
                connectors[connector["name"]] = _fixture(connector["behavior"], timeout, connector["delay_seconds"])
            elif kind == "chat_completions":
                from .providers import BrokeredChatProvider
                from urllib.parse import urlsplit
                context = ssl.create_default_context(cafile=connector["ca_file"]) if connector["ca_file"] else None
                provider = BrokeredChatProvider(endpoint=connector["endpoint"],
                                                allowed_hosts={urlsplit(connector["endpoint"]).hostname},
                                                model=connector["model"], broker=broker,
                                                credential_name=connector["credential"],
                                                timeout=connector["timeout_seconds"],
                                                max_response_bytes=connector["max_response_bytes"],
                                                authentication=connector["authentication"], egress=egress,
                                                ssl_context=context,
                                                max_concurrent_calls=connector["max_concurrent_calls"])
                connectors[connector["name"]] = provider.call
                chat_providers[connector["name"]] = provider
            elif kind == "virustotal_ip":
                from .threat_intel import VirusTotalIPProvider
                provider = VirusTotalIPProvider(broker=broker, credential_name=connector["credential"],
                                                timeout=connector["timeout_seconds"], egress=egress,
                                                max_concurrent_calls=connector["max_concurrent_calls"])
                connectors[connector["name"]] = provider.call
            elif kind == "retrieval_local":
                def released(documents):
                    holder = RELEASE.get()
                    if holder is not None and documents:
                        holder["level"] = highest(holder["level"], *(d.label for d in documents))
                        holder["documents"] = holder.get("documents", 0) + len(documents)
                retrieval = LocalRetrieval(components.documents, collection=connector["collection"],
                                           agents={a["id"]: (a["groups"], a["clearance"]) for a in config["agents"]},
                                           ledger=components.retrievals, max_results=connector["max_results"],
                                           max_chars=connector["max_chars"], on_release=released)
                connectors[connector["name"]] = retrieval.call

        def trusted_security_context(operation):
            context = operation.context
            level = highest(self.classifier.classify(operation.payload()).level,
                            components.taint.level(agent_key(
                                context.tenant_id, context.principal_id, context.agent_id)))
            labels = ["untrusted"]
            if level in ("internal", "confidential", "restricted"):
                labels.append(level)
            return {"level": level, "labels": labels}

        for engine in config["security_engines"]:
            model_route = self.routes[engine["model_route"]]
            provider = _ControlledSecurityProvider(
                chat_providers[model_route["connector"]], controls,
                model_route["controls"], config["service"]["control_timeout_seconds"])
            analyzer = ChatSecurityAnalyzer(provider, timeout=engine["timeout_seconds"])
            control_name = "ai_security." + engine["name"]

            def inspector_operation_for(operation, model_route=model_route):
                payload_json = "{}"
                context = SecurityContext(
                    operation.context.tenant_id, "guard-security", "guard-security", "security-inspection",
                    operation.context.operation_id, "security.assess", self.version)
                binding = json.dumps({"action": operation.digest, "route": model_route["name"]},
                                     sort_keys=True, separators=(",", ":"))
                return Operation(context, model_route["name"], model_route["resource"],
                                 model_route["destination"], payload_json,
                                 hashlib.sha256(binding.encode()).hexdigest())

            security_control = AISecurityControl(
                analyzer=analyzer, inspector_operation_for=inspector_operation_for,
                tokenizer=tokenizer, history=components.security_history,
                context_for=trusted_security_context,
                confidence_threshold=engine["confidence_threshold"],
                failure_action=engine["failure_action"], name=control_name)

            async def invoke_security(operation, control=security_control):
                return await control(operation)

            controls[control_name] = invoke_security
        for route in config["routes"]:
            transport = connectors[route["connector"]]
            prepare = None

            def scope_of(operation):
                c = operation.context
                return Scope(c.tenant_id, c.principal_id, c.agent_id, SESSION_OPERATION)

            if route["privacy"] in ("tokenize", "restore"):
                def make(inner, mode):
                    async def wrapped(operation):
                        if mode == "restore":
                            try:
                                restored = components.vault.restore(operation.payload_json, scope_of(operation),
                                                                    operation.destination, consume=False,
                                                                    json_encoded=True)
                            except Exception:
                                # Wrong scope/destination/expired: nothing was sent.
                                raise RejectedBeforeDispatch("restore_denied") from None
                            operation = Operation(operation.context, operation.route, operation.resource,
                                                  operation.destination, restored, operation.digest)
                        result = await inner(operation)
                        return tokenizer.tokenize(result, scope_of(operation), restore_destinations,
                                                  allow_references=True, numeric_cards="tokenize")
                    return wrapped
                transport = make(transport, route["privacy"])
                if route["privacy"] == "tokenize":
                    connector_config = config.connector(route["connector"])
                    numeric_cards = "tokenize" if connector_config["type"] == "chat_completions" else "reject"

                    def prepare(operation, numeric_cards=numeric_cards):
                        try:
                            return tokenizer.tokenize(operation.payload(), scope_of(operation), restore_destinations,
                                                      numeric_cards=numeric_cards)
                        except VaultError as error:
                            if str(error) in VAULT_UNAVAILABLE:
                                raise UnavailableBeforeDispatch("vault_unavailable") from None
                            raise
            required = list(route["controls"])
            if route["task_boundaries"]:
                mapping = {}
                for boundary in route["task_boundaries"]:
                    rules = tuple(FieldRule(tuple(rule["path"]), rule["kind"], rule.get("required", True),
                                            rule.get("choices"), rule.get("minimum"), rule.get("maximum"),
                                            rule.get("max_length")) for rule in boundary["fields"])
                    mapping[(boundary["principal"], boundary["workflow"])] = intent_control(TaskBoundary(
                        tenant_id=route["tenant"], principal_id=boundary["principal"], workflow_id=boundary["workflow"],
                        route=route["name"], resource=route["resource"], destination=route["destination"],
                        operations=frozenset({route["operation"]}), fields=rules))
                boundaries[route["name"]] = mapping
                required.append("task_boundary")
            if route["security_engine"] is not None:
                required.append("ai_security." + route["security_engine"])
            if route["policy_engine"] is not None:
                required.append("agt." + route["policy_engine"])
            if route["approval"] == "required":
                required.append("approval")
            hooks = {}
            if route["approval"] != "none":
                hooks = {"approval": approvals.satisfied, "pre_dispatch": approvals.consume}
            built.append(Route(route["name"], route["operation"], route["resource"], route["destination"],
                               route["tenant"], tuple(required), transport, prepare, **hooks))

        async def task_boundary(operation):
            control = boundaries.get(operation.route, {}).get((operation.context.principal_id,
                                                               operation.context.workflow_id))
            if control is None:
                return ControlResult("task_boundary", operation.context.tenant_id, operation.context.operation_id,
                                     Action.DENY)
            return await control(operation)

        controls["task_boundary"] = task_boundary
        digests = components.identities.digests("agent")
        credentials = {}
        for agent in config["agents"]:
            digest = digests.get(agent["id"])
            if digest is not None:
                credentials[digest] = Principal(agent["tenant"], agent["principal"], agent["id"],
                                                frozenset(agent["routes"]))
        version = self.version

        def context_factory(principal, route):
            agent = self.agents[principal.agent_id]
            return SecurityContext(principal.tenant_id, principal.principal_id, principal.agent_id, agent["task"],
                                   DIAGNOSTIC.get() or secrets.token_hex(16), route.operation, version)

        self.credential_generations = {name: digest for name, digest in digests.items()}
        self.runtime = GuardRuntime(credential_digests=credentials, routes=tuple(built), controls=controls,
                                    audit=components.audit, policy_version=version,
                                    control_timeout=config["service"]["control_timeout_seconds"],
                                    transport_timeout=config["service"]["transport_timeout_seconds"],
                                    max_payload_bytes=config["service"]["max_frame_bytes"],
                                    context_factory=context_factory)


def authorization_changed(old, new, agent_id, route_name, *, credentials_changed=()):
    """True when a reload revokes or alters what in-flight work was admitted under.

    Work admitted before a reload keeps running only if the agent's credential,
    tenant, principal and task are unchanged, its clearance and groups are
    unchanged or widened, it is still granted the route, and neither the route
    nor the route's connector changed. Otherwise the work is cancelled (outcome
    unknown if it already dispatched), so no action completes, and no response
    is released, under authorization that no longer exists.
    """
    if agent_id in credentials_changed:
        return True
    before, after = old.agents.get(agent_id), new.agents.get(agent_id)
    if before is None or after is None or route_name is None:
        return True
    if any(before[key] != after[key] for key in ("tenant", "principal", "task")):
        return True
    if rank(after["clearance"]) < rank(before["clearance"]) or not set(before["groups"]) <= set(after["groups"]):
        return True
    route_before, route_after = old.routes.get(route_name), new.routes.get(route_name)
    if route_name not in after["routes"] or route_before is None or route_before != route_after:
        return True
    connectors_before = {item["name"]: item for item in old.config["connectors"]}
    connectors_after = {item["name"]: item for item in new.config["connectors"]}
    return connectors_before.get(route_before["connector"]) != connectors_after.get(route_after["connector"])


# -- service -------------------------------------------------------------------
class ProductService(GuardService):
    _request_shapes = GuardService._request_shapes + (
        {"credential", "route", "payload", "approval"}, {"credential", "route", "payload", "request_id", "approval"})

    def __init__(self, host, runtime, path, *, rate_limiter=None, **kwargs):
        super().__init__(runtime, path, **kwargs)
        self.host = host
        self._agent_tasks = {}
        self._task_routes = {}
        self.rate_limiter = rate_limiter or RateLimiter(None, ())
        # Ledger names whose final state could not be written (storage failure):
        # the intended state is kept here so a resubmitted ID is answered
        # correctly and never replayed; Guard retries the write later.
        self.unsettled = {}
        self.tracked = 0

    def _valid_request(self, request):
        return super()._valid_request(request) and ("approval" not in request or isinstance(request["approval"], str))

    def _begin_connection(self):
        DIAGNOSTIC.set(secrets.token_hex(16))

    def _finalize(self, response):
        if type(response) is dict and "diagnostic_id" not in response:
            response = dict(response, diagnostic_id=DIAGNOSTIC.get())
        return response

    def cancel_in_flight(self, revoked):
        """Cancel in-flight work for which ``revoked(agent_id, route_name)`` is true."""
        cancelled = 0
        for agent_id, tasks in tuple(self._agent_tasks.items()):
            for task in tuple(tasks):
                if revoked(agent_id, self._task_routes.get(task)):
                    task.cancel()
                    cancelled += 1
        return cancelled

    async def drain(self, timeout):
        """Stop accepting; wait for in-flight work, then cancel the rest."""
        if self._server is None:
            return {"cancelled": 0}
        self._server.close()
        pending = {task for task in self._tasks if task is not asyncio.current_task()}
        if pending and timeout > 0:
            done, pending = await asyncio.wait(pending, timeout=timeout)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        cancelled = len(pending)
        await self.close()
        return {"cancelled": cancelled}

    async def _execute(self, request):
        host, diag = self.host, DIAGNOSTIC.get()
        policy = host.policy
        try:
            principal = self.runtime.authorize(request["credential"], request["route"])
        except AccessDenied:
            host.event("request_denied", diagnostic_id=diag, reason="not_authorized")
            return {"status": "denied", "reason": "not_authorized"}
        route = self.runtime.route(request["route"])
        settings = policy.routes[route.name]
        if not self.rate_limiter.allow(principal.agent_id):
            # Not tracked and not executed: the configured rate bounds ledger growth.
            return {"status": "busy", "reason": "rate_limited"}
        binding, digest = action_binding(principal, route, request["payload"], policy_version=policy.version)
        name = None
        if self.outcomes is not None:
            if self.unsettled:
                answered = self._answer_unsettled(principal, request)
                if answered is not None:
                    return answered
            try:
                name, state = self.outcomes.begin(principal, request.get("request_id"), request["route"], request["payload"])
            except OutcomeError as error:
                reason = str(error) if str(error) in {"invalid_request_id", "request_id_expired", "request_id_outside_window",
                                                      "request_id_conflict", "outcome_capacity_reached",
                                                      "tenant_outcome_capacity_reached"} else "tracking_unavailable"
                host.event("request_tracking_rejected", diagnostic_id=diag, reason=reason, tenant_id=principal.tenant_id,
                           agent_id=principal.agent_id, route=route.name)
                return {"status": "request_tracking_unavailable_or_conflict", "reason": reason}
            if state != "new":
                return {"status": {"executing": "in_progress", "completed": "completed_no_replay", "denied": "denied",
                                   "uncertain": "outcome_unknown_no_replay"}[state]}
            self.tracked += 1
        elif "request_id" in request:
            return {"status": "durable_request_tracking_unavailable"}
        holder = {"level": "public"}
        APPROVAL.set((request.get("approval"), digest, {}))
        RELEASE.set(holder)
        task = asyncio.current_task()
        self._agent_tasks.setdefault(principal.agent_id, set()).add(task)
        self._task_routes[task] = route.name
        agent = policy.agents[principal.agent_id]
        key = agent_key(principal.tenant_id, principal.principal_id, principal.agent_id)
        try:
            try:
                result = await self.runtime.execute(request["credential"], request["route"], request["payload"])
            except ApprovalRequired:
                if settings["approval"] in ("required", "on_demand"):
                    try:
                        ticket = host.approvals.request(binding, digest, review_view(request["payload"]))
                    except ApprovalError:
                        self._settle(name, "denied", strict=False)
                        return {"status": "denied", "reason": "approval_capacity_reached"}
                    self._settle(name, "approval_pending", strict=False)
                    host.event("approval_requested", diagnostic_id=diag, tenant_id=principal.tenant_id,
                               agent_id=principal.agent_id, route=route.name, action_digest=digest,
                               ticket_digest=hashlib.sha256(ticket["ticket"].encode()).hexdigest())
                    return {"status": "approval_required", "ticket": ticket["ticket"], "action_digest": digest,
                            "expires_at": ticket["expires_at"]}
                self._settle(name, "denied", strict=False)
                return {"status": "denied", "reason": "approval_required_not_configured"}
            except AccessDenied:
                # Nothing was dispatched: a ledger write failure here never turns
                # a denial into an unknown outcome.
                self._settle(name, "denied", strict=False)
                return {"status": "denied", "reason": "policy_denied"}
            except UnavailableBeforeDispatch as error:
                self._release_undispatched(name)
                host.event("request_unavailable_no_execution", diagnostic_id=diag, reason=str(error),
                           tenant_id=principal.tenant_id, agent_id=principal.agent_id, route=route.name)
                return {"status": "unavailable_no_execution", "reason": str(error)}
            except GuardError:
                self._settle(name, "uncertain", strict=False)
                return {"status": "execution_or_audit_failed_outcome_unknown"}
            except BaseException:
                self._settle(name, "uncertain", strict=False)
                raise
            # Executed: the outcome is settled as completed whatever is released.
            # If the ledger cannot record it now, the state is kept in memory
            # (resubmissions get completed_no_replay; a restart makes the record
            # uncertain), and the completed result is still released below.
            self._settle(name, "completed", strict=False)
            # A reload during execution must not loosen release checks: use the
            # stricter of the policy in force at admission and the current one.
            current = host.policy
            agent_now = current.agents.get(principal.agent_id)
            if agent_now is None:
                host.event("response_withheld", diagnostic_id=diag, reason="agent_removed", route=route.name)
                return {"status": "response_withheld", "reason": "agent_removed"}
            route_now = current.routes.get(route.name)
            if (route_now is None or route.name not in agent_now["routes"]
                    or any(agent_now[key] != agent[key] for key in ("tenant", "principal"))
                    or (holder.get("documents") and not set(agent["groups"]) <= set(agent_now["groups"]))):
                # A reload revoked the grant or changed the identity while the
                # action ran; reload normally cancels such work first.
                host.event("response_withheld", diagnostic_id=diag, reason="authorization_changed", route=route.name)
                return {"status": "response_withheld", "reason": "authorization_changed"}
            clearance = min(agent["clearance"], agent_now["clearance"], key=rank)
            groundings = [g for g in (settings["grounding"], route_now.get("grounding")) if g is not None]
            grounding = None
            if groundings:
                grounding = {"citations": "required" if any(g["citations"] == "required" for g in groundings)
                             else groundings[0]["citations"],
                             "mode": "extractive" if any(g.get("mode") == "extractive" for g in groundings)
                             else "citations"}
            if grounding is not None and grounding["mode"] == "extractive" and (
                    policy.config.connector(settings["connector"])["type"] == "chat_completions"):
                from .model_responses import ModelResponseError, extract_chat_answer
                try:
                    result = extract_chat_answer(result)
                except ModelResponseError:
                    host.event("response_withheld", diagnostic_id=diag,
                               reason="invalid_extractive_model_response", route=route.name,
                               agent_id=principal.agent_id)
                    return {"status": "response_withheld", "reason": "ungrounded"}
            try:
                level = highest(settings["produces"], route_now["produces"], holder["level"],
                                policy.classifier.classify(result).level, current.classifier.classify(result).level)
            except Exception:
                host.event("response_withheld", diagnostic_id=diag, reason="classification_failed", route=route.name)
                return {"status": "response_withheld", "reason": "classification_failed"}
            if not permits(clearance, level):
                host.event("response_withheld", diagnostic_id=diag, reason="sensitivity", route=route.name,
                           agent_id=principal.agent_id, level=level)
                return {"status": "response_withheld", "reason": "sensitivity"}
            if grounding is not None:
                grounded, why = check_grounding(result, host.components.retrievals.allowed(key),
                                                required=grounding["citations"] == "required", mode=grounding["mode"])
                if not grounded:
                    host.event("response_withheld", diagnostic_id=diag, reason=why, route=route.name,
                               agent_id=principal.agent_id)
                    return {"status": "response_withheld", "reason": "ungrounded"}
            try:
                previous, current = host.components.taint.raise_to(key, level)
            except TaintError:
                host.event("response_withheld", diagnostic_id=diag, reason="taint_unavailable", route=route.name)
                return {"status": "response_withheld", "reason": "taint_unavailable"}
            if current != previous:
                host.event("taint_raised", diagnostic_id=diag, tenant_id=principal.tenant_id,
                           agent_id=principal.agent_id, level=current, previous_level=previous)
            return {"status": "ok", "result": result}
        finally:
            self._agent_tasks.get(principal.agent_id, set()).discard(task)
            self._task_routes.pop(task, None)

    def _settle(self, name, state, *, strict=True):
        if name is None or self.outcomes is None:
            return
        try:
            self.outcomes.finish(name, state)
        except Exception:
            self.unsettled[name] = state
            self.host.event("outcome_settle_failed", diagnostic_id=DIAGNOSTIC.get(), status=state)
            if strict:
                raise GuardError("request_tracking_failed_outcome_unknown") from None

    def _release_undispatched(self, name):
        """Free the ledger entry of a request that never left Guard."""
        if name is None or self.outcomes is None:
            return
        try:
            self.outcomes.abandon(name)
        except Exception:
            self.unsettled[name] = "abandon"

    def _answer_unsettled(self, principal, request):
        """Answer a resubmitted ID whose final state is still only in memory."""
        try:
            name, _ = OutcomeLedger.binding(principal, request.get("request_id"), request["route"], request["payload"])
        except OutcomeError:
            return None
        intended = self.unsettled.get(name)
        if intended is None:
            return None
        if self.retry_unsettled(name):
            # Written now: abandoned or approval-pending requests proceed normally.
            return None if intended in ("abandon", "approval_pending") else {
                "status": {"completed": "completed_no_replay", "uncertain": "outcome_unknown_no_replay",
                           "denied": "denied"}[intended]}
        if intended == "completed":
            return {"status": "completed_no_replay"}
        if intended == "denied":
            return {"status": "denied"}
        if intended == "uncertain":
            return {"status": "outcome_unknown_no_replay"}
        return {"status": "unavailable_no_execution", "reason": "tracking_unavailable"}

    def retry_unsettled(self, name=None, *, limit=50):
        """Write pending final states; returns True when ``name`` (or all
        attempted, at most ``limit`` per pass) succeeded."""
        names = [name] if name is not None else list(self.unsettled)[:limit]
        written = 0
        for item in names:
            intended = self.unsettled.get(item)
            if intended is None:
                continue
            try:
                if intended == "abandon":
                    self.outcomes.abandon(item)
                else:
                    self.outcomes.finish(item, intended)
            except OutcomeError as error:
                if str(error) not in ("outcome_ownership_lost", "unknown_request"):
                    continue
            except Exception:
                continue
            self.unsettled.pop(item, None)
            written += 1
        return written == len(names)


# -- admin channel ---------------------------------------------------------------
class AdminServer:
    def __init__(self, host, path):
        self.host, self.path = host, Path(path)
        self._server = None

    async def start(self):
        parent = self.path.parent
        info = parent.stat()
        if (parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise HostError("private_admin_directory_required")
        if self.path.exists() or self.path.is_symlink():
            raise HostError("admin_socket_exists")
        self._server = await asyncio.start_unix_server(self._handle, path=str(self.path), limit=65536)
        self.path.chmod(0o600)
        info = self.path.stat()
        self._identity = (info.st_dev, info.st_ino)
        return self

    async def close(self):
        if self._server is None:
            return
        self._server.close()
        self._server = None
        try:
            info = self.path.lstat()
            if (info.st_dev, info.st_ino) == self._identity:
                self.path.unlink()
        except FileNotFoundError:
            pass

    async def _handle(self, reader, writer):
        response = {"status": "error", "error": "invalid_admin_request"}
        try:
            sock = writer.get_extra_info("socket")
            if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
                _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                 struct.calcsize("3i")))
                if uid != os.getuid():
                    response = {"status": "error", "error": "admin_peer_forbidden"}
                    raise PermissionError()
            line = await asyncio.wait_for(reader.readline(), 5)
            request = json.loads(line)
            if type(request) is not dict or set(request) - {"command", "arguments"} or not isinstance(request.get("command"), str):
                raise ValueError()
            arguments = request.get("arguments", {})
            if type(arguments) is not dict:
                raise ValueError()
            response = await self.host.admin(request["command"], arguments)
        except PermissionError:
            pass
        except Exception:
            response = {"status": "error", "error": "invalid_admin_request"}
        try:
            writer.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")
            await asyncio.wait_for(writer.drain(), 5)
        except Exception:
            pass
        finally:
            writer.close()


async def admin_request(path, command, arguments=None, *, timeout=30):
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path), limit=16_777_216), timeout)
    try:
        writer.write(json.dumps({"command": command, "arguments": arguments or {}}).encode() + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
        return json.loads(line)
    finally:
        writer.close()


# -- host ------------------------------------------------------------------------
class GuardHost:
    EVENT_FAILURE_WINDOW = 60

    def __init__(self, config: ProductConfig):
        self.config = config
        self.started = None
        self.stop_event = asyncio.Event()
        self.components = None
        self.policy = None
        self.service = None
        self.admin_server = None
        self.approvals = None
        self.preflight_results = {}
        self.retention_task = None
        self.retention_status = {name: {"runs": 0, "failures": 0, "last_run": None, "last_seconds": None,
                                        "last_result": None, "last_error": None, "runs_with_records": 0,
                                        "records_total": 0, "max_seconds": 0}
                                 for name in ("outcomes", "audit", "vault", "settlement")}

    # -- scheduled retention -------------------------------------------------
    def run_retention(self, name):
        """One retention job; runs in a worker thread except settlement."""
        retention, status = self.config["retention"], self.retention_status[name]
        started = time.time()
        try:
            if name == "outcomes":
                if not self.config["outcomes"]["time_bound_request_ids"]:
                    result = {"skipped": "time_bound_ids_disabled"}
                else:
                    ledger = self.components.outcomes
                    # Scheduled runs skip the pass over records retained for
                    # reconciliation; operators archive those after resolving.
                    archived = ledger.archive(self.components.layout.archive,
                                              before=int(ledger.now()) - retention["outcome_archive_age_seconds"],
                                              include_retained=False)
                    result = {key: archived[key] for key in ("archived", "retained_unreconciled", "cutoff", "files")}
            elif name == "audit":
                active = self.components.audit.summary()["active_events"]
                result = {"active_events": active, "archived": 0}
                if active > retention["audit_archive_threshold_events"]:
                    archived = self.components.audit.archive(self.components.layout.archive,
                                                             keep=retention["audit_archive_keep_events"])
                    result.update(archived=archived["archived"], files=archived.get("files", 1))
            elif name == "vault":
                result = {"purged": self.components.vault.purge_expired()}
            else:
                pending = len(self.service.unsettled)
                self.service.retry_unsettled()
                result = {"pending_before": pending, "pending_after": len(self.service.unsettled)}
        except Exception as error:
            code = str(error) if type(error).__name__ in ("OutcomeError", "AuditError", "VaultError") else "retention_failed"
            status.update(failures=status["failures"] + 1, last_run=int(started), last_error=code,
                          last_seconds=round(time.time() - started, 3))
            self.event("retention_failed", store=name, reason=code)
            return status
        status.update(runs=status["runs"] + 1, last_run=int(started), last_error=None, last_result=result,
                      last_seconds=round(time.time() - started, 3))
        status["max_seconds"] = max(status["max_seconds"], status["last_seconds"])
        count = result.get("archived", result.get("purged", 0))
        if count:
            status["runs_with_records"] += 1
            status["records_total"] += count
        if name != "settlement" and count:
            self.event("retention_run", store=name, count=count, duration_ms=int(status["last_seconds"] * 1000))
        return status

    async def _retention_loop(self):
        intervals = {"outcomes": "outcome_archive_interval_seconds", "audit": "audit_archive_interval_seconds",
                     "vault": "vault_purge_interval_seconds"}
        now = time.monotonic()
        due = {name: now + self.config["retention"][key] for name, key in intervals.items()}
        due["settlement"] = now + 5
        while True:
            await asyncio.sleep(1)
            now = time.monotonic()
            for name in ("settlement", "vault", "outcomes", "audit"):
                if now < due[name]:
                    continue
                if name == "settlement":
                    if self.service.unsettled:
                        self.run_retention(name)
                    due[name] = time.monotonic() + 5
                    continue
                await asyncio.to_thread(self.run_retention, name)
                due[name] = time.monotonic() + self.config["retention"][intervals[name]]

    # events never include payloads, credentials or detector text
    def event(self, name, **fields):
        """Best-effort service event. Decision and execution records are written
        by GuardRuntime, whose audit failures fail closed; failures here are
        counted and reported by status/ready instead of blocking a response."""
        try:
            self.components.audit({"event": name, "outcome": name, **fields})
        except Exception:
            self.audit_event_failures = getattr(self, "audit_event_failures", 0) + 1
            self.audit_event_failed_at = time.monotonic()

    def preflight(self):
        config, checks = self.config, {}
        linux = sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED")
        checks["platform_linux_peer_credentials"] = linux
        checks["non_root"] = os.getuid() != 0
        guard_uid = config["deployment"]["guard_uid"]
        checks["guard_uid_matches"] = guard_uid is None or os.getuid() == guard_uid
        interfaces = network_interfaces()
        checks["network_interfaces"] = interfaces
        checks["no_network_interfaces"] = interfaces == ["lo"]
        if config.production:
            failures = [name for name in ("platform_linux_peer_credentials", "non_root", "guard_uid_matches")
                        if not checks[name]]
            if config["egress"]["mode"] in ("proxy", "none") and not checks["no_network_interfaces"]:
                failures.append("guard_has_network_interfaces")
            if failures:
                self.preflight_results = checks
                raise HostError("production_preflight_failed:" + ",".join(failures))
        self.preflight_results = checks
        return checks

    def _apply_inspection(self, config):
        from .policy import load_packs, pack_policy_summary
        os.environ["ENKSTEIN_POLICY_PACK"] = config["inspection"]["private_pack"] or "/nonexistent/enkstein-guard-disabled"
        load_packs.cache_clear()
        pack_policy_summary.cache_clear()

    def _approval_book(self):
        return ApprovalBook(approvers={a["id"]: a["tenants"] for a in self.config["approvers"]},
                            approver_digests=self.components.identities.digests("approver"),
                            ttl=self.config["service"]["approval_ttl_seconds"], audit=self.components.audit,
                            store=self.components.approvals)

    async def start(self):
        self.preflight()
        self._apply_inspection(self.config)
        self.components = Components(self.config)
        if self.config.production and self.components.secrets.shared_value_groups():
            # One provider account for several tenants shares provider-side
            # state across tenant boundaries; refuse to serve until separated.
            raise HostError("secret_value_shared_across_tenants")
        self.approvals = self._approval_book()
        self.policy = Policy(self.components, self.config, self.approvals)
        service = self.config["service"]
        peers = None
        if self.config.production:
            peers = {agent["uid"]: (agent["tenant"], agent["principal"], agent["id"]) for agent in self.config["agents"]}
        self.service = ProductService(self, self.policy.runtime, self.config["paths"]["socket"],
                                      max_connections=service["max_connections"],
                                      max_frame_bytes=service["max_frame_bytes"],
                                      request_timeout=service["request_timeout_seconds"],
                                      read_timeout=service["read_timeout_seconds"],
                                      peer_bindings=peers, per_peer_connections=service["per_peer_connections"],
                                      socket_group=service["socket_group"] if peers else None,
                                      rate_limiter=RateLimiter(service["max_requests_per_second"],
                                                               self.config["agents"]))
        if self.config["egress"]["mode"] == "proxy":
            try:
                healthy = self.components.egress_client().health()
            except Exception:
                healthy = False
            if self.config.production and not healthy:
                raise HostError("egress_proxy_unavailable")
            self.preflight_results["egress_proxy_healthy"] = healthy
        self.service.outcomes = self.components.outcomes
        # After a crash the previous sockets remain. The state lock is held, so a
        # socket that refuses connections is stale and is removed; a live socket
        # (another process) or a non-socket path is never removed.
        from .daemon import _prepare_socket
        for path in (self.config["paths"]["socket"], self.config["paths"]["admin_socket"]):
            try:
                _prepare_socket(Path(path))
            except ValueError as error:
                raise HostError(str(error)) from None
        self.admin_server = await AdminServer(self, self.config["paths"]["admin_socket"]).start()
        try:
            await self.service.start()
        except Exception:
            await self.admin_server.close()
            raise
        self.started = time.time()
        if self.config["retention"]["scheduled"]:
            self.retention_task = asyncio.ensure_future(self._retention_loop())
        self.event("service_started", profile=self.config["profile"], version=__version__,
                   policy_version=self.policy.version)
        return self

    async def stop(self):
        result = {"cancelled": 0}
        if self.retention_task is not None:
            self.retention_task.cancel()
            await asyncio.gather(self.retention_task, return_exceptions=True)
            self.retention_task = None
        if self.service is not None:
            result = await self.service.drain(self.config["service"]["drain_timeout_seconds"])
        if self.admin_server is not None:
            await self.admin_server.close()
        if self.components is not None:
            self.event("service_stopped", count=result["cancelled"], reason="cancelled_in_flight_outcome_unknown"
                       if result["cancelled"] else "drained")
        return result

    async def reload(self):
        try:
            fresh = load_config(self.config.source)
        except Exception:
            return {"status": "error", "error": "configuration_invalid"}
        if fresh.reload_key() != self.config.reload_key():
            return {"status": "error", "error": "restart_required"}
        old = self.policy
        try:
            self._apply_inspection(fresh)
            self.approvals.update({a["id"]: a["tenants"] for a in fresh["approvers"]},
                                  self.components.identities.digests("approver"))
            policy = Policy(self.components, fresh, self.approvals)
        except Exception:
            return {"status": "error", "error": "reload_failed"}
        changed = {name for name, digest in old.credential_generations.items()
                   if policy.credential_generations.get(name) != digest}
        self.config, self.policy = fresh, policy
        self.service.runtime = policy.runtime
        cancelled = self.service.cancel_in_flight(
            lambda agent_id, route_name: authorization_changed(old, policy, agent_id, route_name,
                                                               credentials_changed=changed))
        self.event("policy_reloaded", policy_version=policy.version, count=len(changed))
        return {"status": "ok", "policy_version": policy.version, "credentials_changed": len(changed),
                "cancelled_in_flight": cancelled}

    def ready(self):
        checks = {}
        checks["service_socket"] = self.service is not None and self.service._server is not None
        try:
            self.components.audit.verify()
            checks["audit_verified"] = True
        except Exception:
            checks["audit_verified"] = False
        for name, probe in (("outcomes", self.components.outcomes.usage), ("vault", self.components.vault.usage),
                            ("security_history", self.components.security_history.verify)):
            try:
                probe()
                checks[name] = True
            except Exception:
                checks[name] = False
        if self.config["egress"]["mode"] == "proxy":
            try:
                checks["egress_proxy"] = self.components.egress_client().health()
            except Exception:
                checks["egress_proxy"] = False
        # Not ready while service events are failing to record; the lifetime
        # count of lost events stays visible in status and doctor.
        failed_at = getattr(self, "audit_event_failed_at", None)
        checks["service_events_recorded"] = failed_at is None or time.monotonic() - failed_at > self.EVENT_FAILURE_WINDOW
        ready = all(checks.values())
        return {"status": "ok", "ready": ready, "checks": checks}

    def status(self):
        identities = self.components.identities.listing()
        configured = {a["id"] for a in self.config["agents"]}
        issued = {name for name, item in identities["agent"].items() if not item["revoked"] and name in configured}
        synthetic = [c["name"] for c in self.config["connectors"] if c["type"] == "fixture"]
        summary = self.config.summary()
        for engine in summary["security_engines"]:
            engine["stage"] = "active"
        for engine in summary["policy_engines"]:
            engine["stage"] = "active"
        return {"status": "ok", "service": "running", "version": __version__, "pid": os.getpid(),
                "profile": self.config["profile"], "scope": "single_host",
                "uptime_seconds": int(time.time() - self.started) if self.started else 0,
                "policy_version": self.policy.version, "config": summary,
                "peer_bound": bool(self.service._peer_bindings),
                "connections": {"active": self.service._active, "maximum": self.service.maximum,
                                **self.service.counters},
                "agents": {"configured": len(configured), "with_active_credentials": len(issued)},
                "approvals_pending": len(self.approvals.pending()),
                "audit": self.components.audit.summary(), "outcomes": self.components.outcomes.usage(),
                "vault": self.components.vault.usage(),
                "security_history": self.components.security_history.verify(),
                "synthetic_connectors": synthetic,
                "audit_event_failures": getattr(self, "audit_event_failures", 0),
                "preflight": self.preflight_results,
                "rate_limit": self.service.rate_limiter.describe(),
                "tracked_requests": self.service.tracked,
                "unsettled_outcomes": len(self.service.unsettled),
                "outcome_sizing": outcome_sizing(self.config.data),
                "retention": {"scheduled": self.config["retention"]["scheduled"], **self.retention_status},
                "production_ready": self.config.production and not synthetic}

    async def admin(self, command, arguments):
        try:
            if command == "status":
                return self.status()
            if command == "ready":
                return self.ready()
            if command == "reload":
                return await self.reload()
            if command == "shutdown":
                asyncio.get_running_loop().call_soon(self.stop_event.set)
                return {"status": "ok", "stopping": True}
            if command == "approvals.list":
                return {"status": "ok", "approvals": self.approvals.pending()}
            if command == "approvals.review":
                return {"status": "ok", **self.approvals.review(arguments.get("approver_credential"),
                                                                 arguments.get("ticket"))}
            if command == "approvals.decide":
                return {"status": "ok", **self.approvals.decide(arguments.get("approver_credential"),
                                                                 arguments.get("ticket"),
                                                                 arguments.get("action_digest"),
                                                                 arguments.get("decision"))}
            if command == "taint.reset":
                agent = self.config.agent(arguments.get("agent"))
                if agent is None:
                    return {"status": "error", "error": "unknown_agent"}
                previous = self.components.taint.reset(agent_key(agent["tenant"], agent["principal"], agent["id"]))
                self.event("taint_reset", agent_id=agent["id"], tenant_id=agent["tenant"], previous_level=previous)
                return {"status": "ok", "agent": agent["id"], "previous_level": previous}
            if command == "security.history":
                agent = self.config.agent(arguments.get("agent"))
                if agent is None:
                    return {"status": "error", "error": "unknown_agent"}
                limit = arguments.get("limit", 16)
                if type(limit) is not int or not 1 <= limit <= 16:
                    return {"status": "error", "error": "invalid_limit"}
                context = SecurityContext(
                    agent["tenant"], agent["principal"], agent["id"], agent["task"],
                    "security-history-query", "security.history", self.policy.version)
                payload_json = "{}"
                operation = Operation(
                    context, "security.history", "security-history", "guard-local", payload_json,
                    hashlib.sha256(payload_json.encode()).hexdigest())
                records = await asyncio.to_thread(self.components.security_history.recent, operation, limit)
                history = [{"timestamp": item.created, "route": item.route,
                            "action_digest": item.action_digest, "decision": item.decision,
                            "risk": item.risk, "confidence": item.confidence,
                            "signals": list(item.signals), "enforced_control_action": item.action}
                           for item in records]
                return {"status": "ok", "history": history}
            if command == "audit.archive":
                keep = arguments.get("keep", self.config["retention"]["audit_archive_keep_events"])
                # Off the event loop: archival works in bounded chunks so request
                # audit writes wait at most one chunk.
                result = await asyncio.to_thread(self.components.audit.archive, self.components.layout.archive,
                                                 keep=keep)
                return {"status": "ok", **result}
            if command == "outcomes.archive":
                before = arguments.get("before") or int(time.time()) - self.config["retention"]["outcome_archive_age_seconds"]
                result = await asyncio.to_thread(self.components.outcomes.archive, self.components.layout.archive,
                                                 before=before,
                                                 include_uncertain=arguments.get("include_uncertain") is True)
                self.event("outcomes_archived", count=result["archived"], cutoff=result["cutoff"])
                return {"status": "ok", **result}
            if command == "outcomes.list":
                records = await asyncio.to_thread(self.components.outcomes.records, state=arguments.get("state"))
                return {"status": "ok", "records": records, "usage": self.components.outcomes.usage()}
            if command == "outcomes.verify_archives":
                result = await asyncio.to_thread(self.components.outcomes.verify_archives,
                                                 self.components.layout.archive)
                return {"status": "ok", **result}
            if command == "retention.run":
                name = arguments.get("store")
                if name not in ("outcomes", "audit", "vault", "settlement"):
                    return {"status": "error", "error": "unknown_retention_store"}
                status = self.run_retention(name) if name == "settlement" else await asyncio.to_thread(
                    self.run_retention, name)
                return {"status": "ok", "store": name, **status}
            return {"status": "error", "error": "unknown_admin_command"}
        except ApprovalError as error:
            return {"status": "error", "error": str(error)}
        except (OutcomeError, HostError, TaintError, SecurityHistoryError) as error:
            return {"status": "error", "error": str(error)}
        except Exception:
            return {"status": "error", "error": "admin_command_failed"}

    async def serve(self, *, install_signals=True):
        import signal
        await self.start()
        loop = asyncio.get_running_loop()
        installed = []
        if install_signals:
            for signum in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(signum, self.stop_event.set)
                installed.append(signum)
            if hasattr(signal, "SIGHUP"):
                loop.add_signal_handler(signal.SIGHUP, lambda: asyncio.ensure_future(self.reload()))
                installed.append(signal.SIGHUP)
        try:
            await self.stop_event.wait()
        finally:
            for signum in installed:
                loop.remove_signal_handler(signum)
            return await self.stop()
