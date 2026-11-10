"""Single-host protected orchestration. Bootstrap and callbacks are trusted.

Agents receive opaque leases and artifact handles, not caller-defined identities.
Workflow-wide sticky labels conservatively survive arbitrary summaries/handoffs.
State/budget admission is local to this coordinator, not a distributed database.
"""

import asyncio
from dataclasses import dataclass, field
import hashlib
import inspect
import json
import math
from pathlib import Path
from types import MappingProxyType
import secrets
import threading
import time
from typing import Mapping

from .contracts import Action, ControlResult, SecurityContext
from .intent import TaskBoundary, intent_control
from .runtime import AccessDenied, GuardError, GuardRuntime, Operation, Principal, Route
from .vault import Scope
from .privacy import Tokenizer
from .workflow_store import WorkflowStoreError

READ = "guard.artifact.read"
DELEGATE = "guard.delegate"
MEMORY_WRITE = "guard.memory.write"
MEMORY_READ = "guard.memory.read"
HANDOFF = "guard.handoff"
RECEIVE = "guard.receive"
INTERNAL = frozenset({READ, DELEGATE, MEMORY_WRITE, MEMORY_READ, HANDOFF, RECEIVE})


def canonical(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode()) > 1_048_576:
            raise ValueError()
        return encoded
    except Exception:
        raise AccessDenied("invalid_orchestration_payload") from None


@dataclass(frozen=True)
class Budget:
    calls: int = 100
    units: int = 10000
    parallelism: int = 4
    agents: int = 16
    depth: int = 4
    seconds: float = 300

    def __post_init__(self):
        for value in (self.calls, self.units, self.parallelism, self.agents, self.depth):
            if type(value) is not int or not 1 <= value <= 1_000_000:
                raise ValueError("invalid_workflow_budget")
        if type(self.seconds) not in (int, float) or not 0 < self.seconds <= 86400:
            raise ValueError("invalid_workflow_deadline")


@dataclass(frozen=True)
class Lease:
    agent_id: str
    credential: str = field(repr=False)


@dataclass(frozen=True)
class Admission:
    """Host-approved pin. ``capabilities`` (optional) declares what a Python
    component may do; undeclared capabilities found by the static check deny
    admission. Pinning and the check do not certify that code is benign."""
    path: str
    sha256: str
    capabilities: frozenset | None = None

    def read_verified(self):
        try:
            path = Path(self.path)
            if not path.is_file() or path.stat().st_size > 16_777_216:
                raise ValueError()
            with path.open('rb') as stream:
                content=stream.read(16_777_217)
            if len(content)>16_777_216 or hashlib.sha256(content).hexdigest() != self.sha256:
                raise ValueError()
        except Exception:
            raise AccessDenied("component_integrity_denied") from None
        if self.capabilities is not None:
            from .admission import undeclared
            try:
                extra = undeclared(content, self.capabilities)
            except Exception:
                extra = {"unknown"}
            if extra:
                raise AccessDenied("component_capability_denied")
        return content

    def verify(self):
        self.read_verified()


@dataclass(frozen=True)
class Tool:
    route: Route
    admission: Admission
    accepts: frozenset[str] = frozenset()
    produces: frozenset[str] = frozenset()
    units: int = 1
    approval: bool = False

    def __post_init__(self):
        if self.route.name in INTERNAL or type(self.units) is not int or self.units < 1:
            raise ValueError("invalid_tool")
        if self.route.prepare_payload is not None:
            raise ValueError("orchestration_transforms_require_explicit_adapter")
        for labels in (self.accepts, self.produces):
            if any(not isinstance(label, str) or not label or len(label) > 64 for label in labels):
                raise ValueError("invalid_data_label")
        object.__setattr__(self, "accepts", frozenset(self.accepts))
        object.__setattr__(self, "produces", frozenset(self.produces))
        self.admission.verify()


@dataclass(frozen=True)
class Artifact:
    handle: str
    labels: frozenset[str]
    origin: str


@dataclass
class _Agent:
    principal: Principal
    workflow: str
    parent: str | None
    depth: int
    revoked: bool = False
    mailbox: list = field(default_factory=list)


@dataclass
class _Workflow:
    budget: Budget
    deadline: float
    root: str
    task_controls: Mapping[str, object]
    calls: int = 0
    units: int = 0
    active: int = 0
    agents: int = 1
    labels: set = field(default_factory=set)
    artifacts: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    deliveries: set = field(default_factory=set)


class ProtectedOrchestrator:
    def __init__(self, *, tools: tuple[Tool, ...], controls: dict, vault, audit,
                 approvers: dict[str, frozenset[str]] | None = None, clock=time.monotonic,
                 task_boundary_factory=None, classifier=None, store=None,
                 wall_clock=time.time):
        """``classifier`` (sensitivity.Classifier) adds trusted level labels
        (internal/confidential/restricted) for arguments and tool results,
        including operator-declared context; tools must accept them."""
        self._tools = {tool.route.name: tool for tool in tools}
        if (len(self._tools) != len(tools) or not controls
                or {"orchestration", "task_boundary"} & controls.keys()):
            raise ValueError("invalid_orchestrator_registry")
        self._controls, self._vault, self._audit = dict(controls), vault, audit
        self._tools = MappingProxyType(self._tools)
        self._controls = MappingProxyType(self._controls)
        for name in controls:
            ControlResult(name,"bootstrap","bootstrap",Action.DENY)
        if not callable(audit) or inspect.iscoroutinefunction(audit) or any(not inspect.iscoroutinefunction(c) for c in controls.values()):
            raise ValueError("invalid_orchestration_callbacks")
        for tool in tools:
            if (any(name not in controls for name in tool.route.required_controls)
                    or {"orchestration", "task_boundary"} & set(tool.route.required_controls)):
                raise ValueError("missing_tool_control")
        if (task_boundary_factory is not None
                and (not callable(task_boundary_factory)
                     or inspect.iscoroutinefunction(task_boundary_factory)
                     or inspect.iscoroutinefunction(getattr(task_boundary_factory, "__call__", None)))):
            raise ValueError("synchronous_task_boundary_factory_required")
        self._tokenizer = Tokenizer(vault)
        self._classifier = classifier
        self._workflow_store = store
        self._clock = wall_clock if store is not None else clock
        self._clock_floor = None
        self._task_boundary_factory = task_boundary_factory
        self._agents, self._credentials, self._workflows, self._approvals = {}, {}, {}, {}
        self._inflight, self._interrupted = {}, []
        self._poisoned = False
        self._closed = False
        if any(not isinstance(key,str) or len(key)<32 for key in (approvers or {})):
            raise ValueError("invalid_approver_credential")
        self._approvers = {self._hash(key): frozenset(tenants) for key, tenants in (approvers or {}).items()}
        tenants = sorted({tool.route.tenant_id for tool in tools})
        if tenants:
            self._configure_vault_tenants(vault, tenants)
        self._tasks = {}
        self._lock = threading.RLock()
        if store is not None:
            if (not callable(getattr(store, "load", None))
                    or not callable(getattr(store, "save", None))
                    or not callable(getattr(store, "attach", None))
                    or not callable(getattr(store, "close", None))):
                raise ValueError("invalid_workflow_store")
            attached = False
            try:
                store.attach()
                attached = True
                snapshot = store.load()
                if snapshot.get("registry") is None:
                    store.save(self._snapshot())
                else:
                    self._restore(snapshot)
                    # Admissions left by a dead coordinator are evidence only.
                    # Their calls/units stay charged, but active slots are freed.
                    if self._inflight:
                        self._interrupted.extend(
                            {**record, "status": "interrupted"}
                            for record in self._inflight.values())
                        self._inflight.clear()
                    store.save(self._snapshot())
            except Exception:
                if attached:
                    store.close()
                raise

    def _registry(self):
        return {
            "policy": "orchestration-v1",
            "controls": sorted(self._controls),
            "task_boundary": self._task_boundary_factory is not None,
            "inspection": {"version": "orchestration-inspection-v1",
                           "classifier": self._classifier is not None,
                           "numeric_cards": "tokenize"},
            "internal": sorted(INTERNAL),
            "tools": [{
                "name": name,
                "tenant": tool.route.tenant_id,
                "operation": tool.route.operation,
                "resource": tool.route.resource,
                "destination": tool.route.destination,
                "required_controls": list(tool.route.required_controls),
                "component": tool.admission.sha256,
                "capabilities": (None if tool.admission.capabilities is None
                                 else sorted(tool.admission.capabilities)),
                "accepts": sorted(tool.accepts),
                "produces": sorted(tool.produces),
                "units": tool.units,
                "approval": tool.approval,
            } for name, tool in sorted(self._tools.items())],
        }

    @staticmethod
    def _artifact_record(artifact):
        return {"handle": artifact.handle, "labels": sorted(artifact.labels),
                "origin": artifact.origin}

    def _snapshot(self):
        agents = []
        for agent_id, agent in sorted(self._agents.items()):
            agents.append({
                "id": agent_id,
                "tenant": agent.principal.tenant_id,
                "principal": agent.principal.principal_id,
                "workflow": agent.workflow,
                "parent": agent.parent,
                "depth": agent.depth,
                "revoked": agent.revoked,
                "grants": sorted(agent.principal.allowed_routes),
                "mailbox": [self._artifact_record(item) for item in agent.mailbox],
            })
        credentials = [{"digest": digest.hex(), "agent": agent_id}
                       for digest, agent_id in sorted(self._credentials.items(), key=lambda item: item[0])]
        workflows = []
        for workflow_id, workflow in sorted(self._workflows.items()):
            artifacts = []
            for handle, (artifact, scope, token) in sorted(workflow.artifacts.items()):
                artifacts.append({
                    "artifact": self._artifact_record(artifact),
                    "scope": {"tenant": scope.tenant, "principal": scope.principal,
                              "workflow": scope.workflow, "operation": scope.operation},
                    "token": token,
                })
            workflows.append({
                "id": workflow_id,
                "budget": {name: getattr(workflow.budget, name)
                           for name in ("calls", "units", "parallelism", "agents", "depth", "seconds")},
                "deadline": workflow.deadline,
                "root": workflow.root,
                "calls": workflow.calls,
                "units": workflow.units,
                "active": workflow.active,
                "agents": workflow.agents,
                "labels": sorted(workflow.labels),
                "artifacts": artifacts,
                "memory": dict(sorted(workflow.memory.items())),
                "deliveries": [list(item) for item in sorted(workflow.deliveries)],
            })
        return {
            "version": 1,
            "registry": self._registry(),
            "agents": agents,
            "credentials": credentials,
            "workflows": workflows,
            "inflight": [dict(record) for _, record in sorted(self._inflight.items())],
            "interrupted": list(self._interrupted),
            "clock_floor": self._now(),
        }

    @staticmethod
    def _exact(record, keys):
        if type(record) is not dict or set(record) != set(keys):
            raise WorkflowStoreError("workflow_store_integrity_failed")

    def _restore(self, snapshot):
        try:
            self._exact(snapshot, {"version", "registry", "agents", "credentials", "workflows",
                                   "inflight", "interrupted", "clock_floor"})
            if snapshot["version"] != 1 or snapshot["registry"] != self._registry():
                raise WorkflowStoreError("workflow_registry_mismatch")
            floor = snapshot["clock_floor"]
            current = self._clock()
            if (type(floor) not in (int, float) or not math.isfinite(floor) or floor <= 0
                    or type(current) not in (int, float) or not math.isfinite(current)
                    or current < floor):
                raise WorkflowStoreError("workflow_clock_rollback")
            self._clock_floor = max(floor, current)
            if any(type(snapshot[name]) is not list for name in
                   ("agents", "credentials", "workflows", "inflight", "interrupted")):
                raise ValueError()

            agents = {}
            for record in snapshot["agents"]:
                self._exact(record, {"id", "tenant", "principal", "workflow", "parent", "depth",
                                     "revoked", "grants", "mailbox"})
                if (not isinstance(record["id"], str) or record["id"] in agents
                        or not isinstance(record["workflow"], str)
                        or (record["parent"] is not None and not isinstance(record["parent"], str))
                        or type(record["depth"]) is not int or record["depth"] < 0
                        or type(record["revoked"]) is not bool
                        or type(record["grants"]) is not list or type(record["mailbox"]) is not list):
                    raise ValueError()
                principal = Principal(record["tenant"], record["principal"], record["id"],
                                      frozenset(record["grants"]))
                if (not principal.allowed_routes <= (self._tools.keys() | INTERNAL)
                        or any(self._tools[name].route.tenant_id != principal.tenant_id
                               for name in principal.allowed_routes if name in self._tools)):
                    raise ValueError()
                mailbox = []
                for item in record["mailbox"]:
                    self._exact(item, {"handle", "labels", "origin"})
                    if (not isinstance(item["handle"], str) or not isinstance(item["origin"], str)
                            or type(item["labels"]) is not list
                            or any(not isinstance(label, str) for label in item["labels"])):
                        raise ValueError()
                    mailbox.append(Artifact(item["handle"], frozenset(item["labels"]), item["origin"]))
                agents[record["id"]] = _Agent(principal, record["workflow"], record["parent"],
                                                record["depth"], record["revoked"], mailbox)

            workflows = {}
            for record in snapshot["workflows"]:
                self._exact(record, {"id", "budget", "deadline", "root", "calls", "units", "active",
                                     "agents", "labels", "artifacts", "memory", "deliveries"})
                workflow_id = record["id"]
                if not isinstance(workflow_id, str) or workflow_id in workflows:
                    raise ValueError()
                self._exact(record["budget"], {"calls", "units", "parallelism", "agents",
                                               "depth", "seconds"})
                budget = Budget(**record["budget"])
                counters = (record["calls"], record["units"], record["active"], record["agents"])
                if (type(record["deadline"]) not in (int, float)
                        or not math.isfinite(record["deadline"]) or record["deadline"] <= 0
                        or record["deadline"] > snapshot["clock_floor"] + budget.seconds
                        or any(type(value) is not int or value < 0 for value in counters)
                        or record["calls"] > budget.calls or record["units"] > budget.units
                        or not 1 <= record["agents"] <= budget.agents
                        or type(record["labels"]) is not list or type(record["artifacts"]) is not list
                        or type(record["memory"]) is not dict or type(record["deliveries"]) is not list):
                    raise ValueError()
                if any(not isinstance(label, str) or not label or len(label) > 64
                       for label in record["labels"]):
                    raise ValueError()
                root = agents.get(record["root"])
                if root is None or root.workflow != workflow_id or root.parent is not None or root.depth != 0:
                    raise ValueError()
                task_controls = self._workflow_task_controls(
                    root.principal.tenant_id, root.principal.principal_id, workflow_id,
                    root.principal.allowed_routes)
                workflow = _Workflow(budget, record["deadline"], record["root"], task_controls,
                                     record["calls"], record["units"], 0, record["agents"],
                                     set(record["labels"]))
                for item in record["artifacts"]:
                    self._exact(item, {"artifact", "scope", "token"})
                    artifact_record, scope_record = item["artifact"], item["scope"]
                    self._exact(artifact_record, {"handle", "labels", "origin"})
                    self._exact(scope_record, {"tenant", "principal", "workflow", "operation"})
                    if (not isinstance(artifact_record["handle"], str)
                            or not isinstance(artifact_record["origin"], str)
                            or type(artifact_record["labels"]) is not list
                            or any(not isinstance(label, str) for label in artifact_record["labels"])):
                        raise ValueError()
                    artifact = Artifact(artifact_record["handle"],
                                        frozenset(artifact_record["labels"]), artifact_record["origin"])
                    scope = Scope(**scope_record)
                    if (artifact.handle in workflow.artifacts or scope.workflow != workflow_id
                            or scope.operation != artifact.handle or not isinstance(item["token"], str)
                            or artifact.origin not in agents or agents[artifact.origin].workflow != workflow_id):
                        raise ValueError()
                    origin = agents[artifact.origin]
                    if (scope.tenant != origin.principal.tenant_id
                            or scope.principal != origin.principal.principal_id):
                        raise ValueError()
                    workflow.artifacts[artifact.handle] = (artifact, scope, item["token"])
                workflow.memory = dict(record["memory"])
                if any(not isinstance(key, str) or handle not in workflow.artifacts
                       for key, handle in workflow.memory.items()):
                    raise ValueError()
                workflow.deliveries = set()
                for delivery in record["deliveries"]:
                    if (type(delivery) is not list or len(delivery) != 3
                            or delivery[0] not in agents or delivery[1] not in agents
                            or delivery[2] not in workflow.artifacts
                            or agents[delivery[0]].workflow != workflow_id
                            or agents[delivery[1]].workflow != workflow_id):
                        raise ValueError()
                    workflow.deliveries.add(tuple(delivery))
                workflows[workflow_id] = workflow

            for agent in agents.values():
                workflow = workflows.get(agent.workflow)
                if (workflow is None or (agent.parent is not None and (
                        agent.parent not in agents or agents[agent.parent].workflow != agent.workflow
                        or agent.depth != agents[agent.parent].depth + 1))
                        or agent.depth > (workflow.budget.depth if workflow else 0)):
                    raise ValueError()
                for item in agent.mailbox:
                    stored = workflow.artifacts.get(item.handle)
                    if stored is None or stored[0] != item:
                        raise ValueError()
            for workflow_id, workflow in workflows.items():
                if workflow.agents != sum(agent.workflow == workflow_id for agent in agents.values()):
                    raise ValueError()

            credentials = {}
            for record in snapshot["credentials"]:
                self._exact(record, {"digest", "agent"})
                digest = bytes.fromhex(record["digest"])
                if len(digest) != 32 or digest in credentials or record["agent"] not in agents:
                    raise ValueError()
                credentials[digest] = record["agent"]
            if len(credentials) != len(agents) or set(credentials.values()) != set(agents):
                raise ValueError()

            inflight = {}
            for record in snapshot["inflight"]:
                self._exact(record, {"id", "workflow", "agent", "route", "units", "admitted_at"})
                if (not isinstance(record["id"], str) or record["id"] in inflight
                        or record["workflow"] not in workflows
                        or record["agent"] not in agents or agents[record["agent"]].workflow != record["workflow"]
                        or record["route"] not in agents[record["agent"]].principal.allowed_routes
                        or type(record["units"]) is not int or record["units"] < 1
                        or record["units"] != (self._tools[record["route"]].units
                                               if record["route"] in self._tools else 1)
                        or type(record["admitted_at"]) not in (int, float)
                        or not math.isfinite(record["admitted_at"])):
                    raise ValueError()
                inflight[record["id"]] = dict(record)
            interrupted_ids = set()
            for record in snapshot["interrupted"]:
                self._exact(record, {"id", "workflow", "agent", "route", "units",
                                     "admitted_at", "status"})
                if (not isinstance(record["id"], str) or record["id"] in interrupted_ids
                        or record["status"] != "interrupted" or record["workflow"] not in workflows
                        or record["agent"] not in agents
                        or agents[record["agent"]].workflow != record["workflow"]
                        or record["route"] not in agents[record["agent"]].principal.allowed_routes
                        or type(record["units"]) is not int or record["units"] < 1
                        or record["units"] != (self._tools[record["route"]].units
                                               if record["route"] in self._tools else 1)
                        or type(record["admitted_at"]) not in (int, float)
                        or not math.isfinite(record["admitted_at"])):
                    raise ValueError()
                interrupted_ids.add(record["id"])
            for workflow_id, workflow in workflows.items():
                original = next(item for item in snapshot["workflows"] if item["id"] == workflow_id)
                if original["active"] != sum(
                        item["workflow"] == workflow_id for item in snapshot["inflight"]):
                    raise ValueError()

            self._agents, self._credentials, self._workflows = agents, credentials, workflows
            self._inflight = inflight
            self._interrupted = list(snapshot["interrupted"])
        except WorkflowStoreError:
            raise
        except Exception:
            raise WorkflowStoreError("workflow_store_integrity_failed") from None

    def _ensure_healthy(self):
        if self._closed or self._poisoned:
            raise GuardError("orchestration_storage_unavailable")

    def _now(self):
        now = self._clock()
        if self._workflow_store is None:
            return now
        if (type(now) not in (int, float) or not math.isfinite(now) or now <= 0
                or (self._clock_floor is not None and now < self._clock_floor)):
            self._poisoned = True
            raise GuardError("orchestration_clock_rollback")
        self._clock_floor = now
        return now

    def _persist(self):
        self._ensure_healthy()
        if self._workflow_store is None:
            return
        try:
            self._workflow_store.save(self._snapshot())
        except Exception:
            self._poisoned = True
            raise GuardError("orchestration_storage_unavailable") from None

    @staticmethod
    def _configure_vault_tenants(vault, tenants):
        result = vault.configure_tenants(tenants)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise ValueError("synchronous_vault_configuration_required")

    @staticmethod
    def _hash(credential):
        if not isinstance(credential, str):
            raise AccessDenied("invalid_agent_credential")
        return hashlib.sha256(credential.encode()).digest()

    def _emit(self, **event):
        try:
            result=self._audit(event)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):result.close()
                raise ValueError("async_audit_not_supported")
            if result is False:raise ValueError("audit_rejected")
        except Exception:
            raise GuardError("orchestration_audit_unavailable") from None

    def _workflow_task_controls(self, tenant, principal, workflow_id, grants):
        if self._task_boundary_factory is None:
            return MappingProxyType({})
        routes = tuple(self._tools[name].route for name in sorted(grants) if name in self._tools)
        try:
            boundaries = self._task_boundary_factory(tenant, principal, workflow_id, routes)
            if inspect.isawaitable(boundaries):
                if inspect.iscoroutine(boundaries):
                    boundaries.close()
                raise ValueError()
            if type(boundaries) is not tuple or any(type(item) is not TaskBoundary for item in boundaries):
                raise ValueError()
            expected = {route.name: route for route in routes}
            if len(boundaries) != len(expected):
                raise ValueError()
            controls = {}
            for boundary in boundaries:
                route = expected.get(boundary.route)
                if (route is None or boundary.route in controls
                        or boundary.tenant_id != tenant
                        or boundary.principal_id != principal
                        or boundary.workflow_id != workflow_id
                        or boundary.resource != route.resource
                        or boundary.destination != route.destination
                        or boundary.operations != frozenset({route.operation})):
                    raise ValueError()
                controls[boundary.route] = intent_control(boundary)
            if controls.keys() != expected.keys():
                raise ValueError()
            return MappingProxyType(controls)
        except Exception:
            raise ValueError("invalid_workflow_task_boundaries") from None

    def start(self, *, tenant: str, principal: str, grants: frozenset[str], budget=Budget()) -> Lease:
        """Trusted bootstrap only. Never expose this method as an agent tool."""
        with self._lock:
            self._ensure_healthy()
            if not grants <= (self._tools.keys() | INTERNAL):
                raise ValueError("unknown_workflow_grant")
            if any(self._tools[name].route.tenant_id != tenant for name in grants if name in self._tools):
                raise ValueError("cross_tenant_workflow_grant")
            agent_id = secrets.token_hex(16)
            workflow_id = secrets.token_hex(16)
            credential = secrets.token_urlsafe(32)
            identity = Principal(tenant, principal, agent_id, grants)
            self._configure_vault_tenants(self._vault, [tenant])
            task_controls = self._workflow_task_controls(tenant, principal, workflow_id, grants)
            self._emit(outcome="workflow_started", tenant_id=tenant, workflow_id=workflow_id, agent_id=agent_id)
            self._agents[agent_id] = _Agent(identity, workflow_id, None, 0)
            self._workflows[workflow_id] = _Workflow(
                budget, self._now()+budget.seconds, agent_id, task_controls)
            self._credentials[self._hash(credential)] = agent_id
            self._persist()
            return Lease(agent_id, credential)

    def _agent(self, credential, *, allow_inactive=False):
        self._ensure_healthy()
        agent_id = self._credentials.get(self._hash(credential))
        if agent_id is None:
            raise AccessDenied("invalid_agent_credential")
        agent = self._agents[agent_id]
        current = agent
        while current:
            if current.revoked and not allow_inactive:
                raise AccessDenied("agent_revoked")
            current = self._agents[current.parent] if current.parent else None
        if self._now() >= self._workflows[agent.workflow].deadline and not allow_inactive:
            raise AccessDenied("workflow_deadline")
        return agent

    def _artifact(self, agent, handle):
        item = self._workflows[agent.workflow].artifacts.get(handle)
        if item is None:
            raise AccessDenied("artifact_forbidden")
        return item

    def _store(self, agent, payload, *, untrusted=False):
        workflow = self._workflows[agent.workflow]
        if untrusted:
            workflow.labels.add("untrusted")
        self._inspection_payload(agent, payload)
        handle = secrets.token_hex(32)
        scope = Scope(agent.principal.tenant_id, agent.principal.principal_id, agent.workflow, handle)
        encoded = canonical(payload)
        token = self._vault.put(encoded, scope, ("orchestration-memory",), ttl=min(workflow.budget.seconds, 86400))
        artifact = Artifact(handle, frozenset(workflow.labels), agent.principal.agent_id)
        workflow.artifacts[handle] = (artifact, scope, token)
        return artifact

    def _inspection_payload(self, agent, payload):
        workflow = self._workflows[agent.workflow]
        encoded = canonical(payload)
        scope = Scope(agent.principal.tenant_id,agent.principal.principal_id,agent.workflow,secrets.token_hex(16))
        if "[[EGV:" in encoded:
            safe = {"protected_payload": self._vault.put(encoded,scope,("orchestration-inspection",))}
        else:
            safe = self._tokenizer.tokenize(payload,scope,("orchestration-inspection",),numeric_cards="tokenize")
        if canonical(safe) != encoded:
            workflow.labels.add("sensitive")
        if self._classifier is not None:
            try:
                level = self._classifier.classify(payload).level
            except Exception:
                raise AccessDenied("classification_failed") from None
            if level != "public":
                workflow.labels.add(level)
        return canonical(safe)

    def _open(self, agent, handle):
        artifact, scope, token = self._artifact(agent, handle)
        workflow = self._workflows[agent.workflow]
        workflow.labels.update(artifact.labels)
        return json.loads(self._vault.restore(token, scope, "orchestration-memory", consume=False))

    def _binding(self, agent, route, payload):
        tool = self._tools.get(route)
        return hashlib.sha256(canonical({"workflow": agent.workflow, "agent": agent.principal.agent_id,
                                         "tenant":agent.principal.tenant_id,"principal":agent.principal.principal_id,
                                         "route": route, "payload": payload,"policy":"orchestration-v1",
                                         "resource":tool.route.resource if tool else None,
                                         "destination":tool.route.destination if tool else None,
                                         "component":tool.admission.sha256 if tool else None}).encode()).hexdigest()

    def _check(self, credential, route_name, payload, approval=None, *, consume=False):
        agent = self._agent(credential)
        if route_name not in agent.principal.allowed_routes:
            raise AccessDenied("agent_scope_denied")
        workflow = self._workflows[agent.workflow]
        if route_name in self._tools:
            tool = self._tools[route_name]
            tool.admission.verify()
            if not workflow.labels <= tool.accepts:
                raise AccessDenied("information_flow_denied")
            if tool.approval:
                ticket = self._approvals.get(approval)
                if not ticket or ticket["binding"] != self._binding(agent, route_name, payload) or not ticket["approved"] or ticket["expires"] <= self._now():
                    raise AccessDenied("bound_approval_required")
                if consume:
                    del self._approvals[approval]
        return agent

    async def _invoke(self, credential, route_name, payload, callback, *, approval=None, internal=False):
        payload = json.loads(canonical(payload))
        dispatched = False
        with self._lock:
            agent = self._check(credential, route_name, payload, approval)
            workflow = self._workflows[agent.workflow]
            safe_payload = self._inspection_payload(agent,payload)
            # Inspection can add sticky labels.  Commit them even if the
            # second scope/flow check below denies this operation.
            self._persist()
            self._check(credential,route_name,payload,approval)
            units = self._tools[route_name].units if route_name in self._tools else 1
            if workflow.calls >= workflow.budget.calls or workflow.units+units > workflow.budget.units or workflow.active >= workflow.budget.parallelism:
                raise AccessDenied("shared_budget_exhausted")
            workflow.calls += 1
            workflow.units += units
            workflow.active += 1
            if route_name in self._tools:
                workflow.labels.update(self._tools[route_name].produces)
            task = asyncio.current_task()
            self._tasks.setdefault(agent.principal.agent_id, set()).add(task)
            admission_id = secrets.token_hex(16)
            self._inflight[admission_id] = {
                "id": admission_id, "workflow": agent.workflow,
                "agent": agent.principal.agent_id, "route": route_name,
                "units": units, "admitted_at": self._now(),
            }
            # Calls and units are charged before any control or transport can
            # dispatch.  A crash can never refund or replay this admission.
            try:
                self._persist()
            except Exception:
                # No callback was dispatched.  Clear only transient in-memory
                # occupancy so a poisoned coordinator can close.  Calls/units
                # remain charged in memory, and an ambiguously committed disk
                # admission is reconciled as interrupted during recovery.
                workflow.active -= 1
                self._tasks[agent.principal.agent_id].discard(task)
                self._inflight.pop(admission_id, None)
                raise

        async def final_control(operation):
            try:
                self._check(credential, route_name, payload, approval)
                allowed = True
            except AccessDenied:
                allowed = False
            return ControlResult("orchestration", operation.context.tenant_id, operation.context.operation_id,
                                 Action.ALLOW if allowed else Action.DENY)

        async def dispatch(operation):
            nonlocal dispatched
            self._check(credential, route_name, payload, approval, consume=True)
            dispatched = True
            return await callback(operation)

        def private_control(control):
            async def check(operation):
                safe_operation = Operation(operation.context,operation.route,operation.resource,operation.destination,
                                           safe_payload,operation.digest)
                return await control(safe_operation)
            return check

        def audit(event):
            self._emit(**{**event, "workflow_id": agent.workflow, "agent_id": agent.principal.agent_id,
                          "parent_agent_id": agent.parent, "labels": sorted(workflow.labels)})

        async def context_control(operation):
            # Other inspectors receive the actual workflow and agent identity.
            return await final_control(operation)

        template = self._tools[route_name].route if not internal else None
        required = tuple(template.required_controls) if template else tuple(self._controls)
        task_control = workflow.task_controls.get(route_name)
        if task_control is not None:
            required = (*required, "task_boundary")
        route = Route(route_name, template.operation if template else route_name,
                      template.resource if template else "workflow-state", template.destination if template else "local-coordinator",
                      agent.principal.tenant_id, (*required, "orchestration"), dispatch,
                      template.prepare_payload if template else None)
        runtime = GuardRuntime(credentials={credential: Principal(agent.principal.tenant_id, agent.principal.principal_id,
                                                                 agent.principal.agent_id, frozenset({route_name}))},
                               routes=(route,), controls={**{name:private_control(c) for name,c in self._controls.items()},
                                                         **({"task_boundary": task_control} if task_control else {}),
                                                         "orchestration": context_control}, audit=audit,
                               policy_version="orchestration-v1",
                               context_factory=lambda principal, registered: SecurityContext(principal.tenant_id, principal.principal_id,
                                   principal.agent_id, agent.workflow, secrets.token_hex(16), registered.operation, "orchestration-v1"))
        try:
            remaining = workflow.deadline-self._now()
            return await asyncio.wait_for(runtime.execute(credential, route_name, payload), max(0, remaining))
        finally:
            with self._lock:
                workflow.active -= 1
                self._tasks[agent.principal.agent_id].discard(task)
                self._inflight.pop(admission_id, None)
                try:
                    self._persist()
                except GuardError:
                    if dispatched:
                        # The callback may have made an irreversible external
                        # change, but its final local state was not committed.
                        raise GuardError("orchestration_outcome_unknown") from None
                    raise

    async def execute(self, credential, route_name, payload, *, approval=None) -> Artifact:
        if route_name not in self._tools:
            raise AccessDenied("tool_not_admitted")
        async def callback(operation):
            value = await self._tools[route_name].route.transport(operation)
            self._agent(credential)  # Cancellation/revocation cannot release a late result.
            return self._store(self._agent(credential), value)
        return await self._invoke(credential, route_name, payload, callback, approval=approval)

    async def read(self, credential, handle):
        async def callback(operation):
            return self._open(self._agent(credential), handle)
        return await self._invoke(credential, READ, {"handle": handle}, callback, internal=True)

    async def delegate(self, credential, grants: frozenset[str]) -> Lease:
        grants = frozenset(grants)
        async def callback(operation):
            parent = self._agent(credential)
            workflow = self._workflows[parent.workflow]
            if not grants <= parent.principal.allowed_routes or parent.depth >= workflow.budget.depth or workflow.agents >= workflow.budget.agents:
                raise AccessDenied("delegation_denied")
            child_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
            principal = Principal(parent.principal.tenant_id, parent.principal.principal_id, child_id, grants)
            self._agents[child_id] = _Agent(principal, parent.workflow, parent.principal.agent_id, parent.depth+1)
            self._credentials[self._hash(token)] = child_id
            workflow.agents += 1
            return Lease(child_id, token)
        return await self._invoke(credential, DELEGATE, {"grants": sorted(grants)}, callback, internal=True)

    async def memory_write(self, credential, key, payload):
        if not isinstance(key, str) or not key or len(key)>128:
            raise AccessDenied("invalid_memory_key")
        snapshot = json.loads(canonical(payload))
        async def callback(operation):
            agent = self._agent(credential)
            artifact = self._store(agent, snapshot, untrusted=True)
            self._workflows[agent.workflow].memory[key] = artifact.handle
            return artifact
        return await self._invoke(credential, MEMORY_WRITE, {"key": key, "value": snapshot}, callback, internal=True)

    async def memory_read(self, credential, key):
        async def callback(operation):
            agent = self._agent(credential)
            handle = self._workflows[agent.workflow].memory.get(key)
            if handle is None:
                raise AccessDenied("memory_not_found")
            return self._artifact(agent, handle)[0]
        return await self._invoke(credential, MEMORY_READ, {"key": key}, callback, internal=True)

    async def handoff(self, credential, recipient_id, handle):
        async def callback(operation):
            agent = self._agent(credential)
            recipient = self._agents.get(recipient_id)
            if recipient is None or recipient.workflow != agent.workflow or recipient.revoked:
                raise AccessDenied("handoff_forbidden")
            artifact = self._artifact(agent, handle)[0]
            delivery = (agent.principal.agent_id,recipient_id,handle)
            if delivery in self._workflows[agent.workflow].deliveries:
                raise AccessDenied("handoff_replay_denied")
            self._workflows[agent.workflow].deliveries.add(delivery)
            recipient.mailbox.append(artifact)
            return True
        return await self._invoke(credential, HANDOFF, {"recipient": recipient_id, "handle": handle}, callback, internal=True)

    async def receive(self, credential):
        async def callback(operation):
            agent = self._agent(credential)
            items, agent.mailbox = tuple(agent.mailbox), []
            return items
        return await self._invoke(credential, RECEIVE, {}, callback, internal=True)

    def request_approval(self, credential, route_name, payload, *, seconds=60):
        with self._lock:
            agent = self._agent(credential)
            if route_name not in agent.principal.allowed_routes or route_name not in self._tools or not 0 < seconds <= 300:
                raise AccessDenied("approval_request_denied")
            ticket = secrets.token_urlsafe(32)
            self._approvals = {key:value for key,value in self._approvals.items()
                               if value["expires"] > self._now()}
            if len(self._approvals)>=1024:
                raise AccessDenied("approval_capacity")
            safe_payload = self._inspection_payload(agent,payload)
            self._approvals[ticket] = {
                "binding": self._binding(agent,route_name,payload),
                "tenant": agent.principal.tenant_id, "route":route_name,
                "resource":self._tools[route_name].route.resource,
                "destination":self._tools[route_name].route.destination,
                "safe_payload":safe_payload,
                "expires": min(self._now()+seconds,self._workflows[agent.workflow].deadline),
                "approved": False,
            }
            self._persist()  # Sticky inspection labels, not this transient ticket.
            self._emit(outcome="approval_requested", tenant_id=agent.principal.tenant_id,
                       workflow_id=agent.workflow,
                       action_digest=self._approvals[ticket]["binding"])
            return ticket

    def review(self, approver_credential, ticket):
        with self._lock:
            self._ensure_healthy()
            record = self._approvals.get(ticket)
            if not record or record["tenant"] not in self._approvers.get(self._hash(approver_credential), ()) or record["expires"]<=self._now():
                raise AccessDenied("approval_forbidden")
            return {"action_digest":record["binding"],"route":record["route"],"resource":record["resource"],
                    "destination":record["destination"],"payload":json.loads(record["safe_payload"])}

    def approve(self, approver_credential, ticket):
        with self._lock:
            self._ensure_healthy()
            record = self._approvals.get(ticket)
            if not record or record["tenant"] not in self._approvers.get(self._hash(approver_credential), ()) or record["expires"] <= self._now():
                raise AccessDenied("approval_forbidden")
            self._emit(outcome="approval_granted", tenant_id=record["tenant"], action_digest=record["binding"])
            record["approved"] = True

    def cancel(self, credential):
        with self._lock:
            agent = self._agent(credential,allow_inactive=True)
            # Revocation is effective even if cancellation callbacks are ignored.
            agent.revoked = True
            descendants = {agent.principal.agent_id}
            changed = True
            while changed:
                changed = False
                for identity, state in self._agents.items():
                    if state.parent in descendants and identity not in descendants:
                        descendants.add(identity); changed = True
            for identity in descendants:
                self._agents[identity].revoked = True
            self._persist()
            for identity in descendants:
                for task in tuple(self._tasks.get(identity, ())):
                    if task is not asyncio.current_task():
                        task.cancel()
            self._emit(outcome="agent_subtree_revoked", tenant_id=agent.principal.tenant_id,
                       workflow_id=agent.workflow, agent_id=agent.principal.agent_id)

    def usage(self, credential):
        with self._lock:
            agent = self._agent(credential,allow_inactive=True)
            workflow = self._workflows[agent.workflow]
            return {"calls":workflow.calls,"units":workflow.units,"active":workflow.active,
                    "agents":workflow.agents,"labels":sorted(workflow.labels)}

    def close(self):
        """Persist and release exclusive ownership after all work is quiescent."""
        with self._lock:
            if self._closed:
                return
            if any(workflow.active for workflow in self._workflows.values()):
                raise GuardError("orchestration_work_active")
            if not self._poisoned:
                self._persist()
            self._closed = True
            if self._workflow_store is not None:
                self._workflow_store.close()
