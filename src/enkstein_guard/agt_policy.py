"""Strict local compiler for optional AGT conditional route policies."""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
from types import MappingProxyType

from .contracts import Action, ControlResult, SecurityContext
from .runtime import Operation


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_ROUTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_FIELD_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_AGT_DISTRIBUTION = "agent-governance-toolkit-control-plane"
_AGT_VERSION = "5.0.0"


class AGTPolicyError(Exception):
    """Fixed, non-sensitive AGT policy failure."""


@dataclass(frozen=True)
class _LocalCondition:
    path: tuple[str, ...]
    operator: str
    value: bool | int | float | str


def _invalid():
    raise AGTPolicyError("agt_policy_invalid")


def _identifier(value, pattern):
    if type(value) is not str or pattern.fullmatch(value) is None:
        _invalid()
    return value


def _exact_object(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _invalid()
    return value


def _condition_value(value, operator):
    if value is None or type(value) not in (bool, int, float, str):
        _invalid()
    if type(value) is float and not math.isfinite(value):
        _invalid()
    if type(value) is str and len(value) > 256:
        _invalid()
    if operator in ("lte", "gte") and type(value) not in (int, float):
        _invalid()
    return value


def _agent_registry(agents):
    if type(agents) is not list:
        _invalid()
    registry = {}
    identities = set()
    for agent in agents:
        if type(agent) is not dict:
            _invalid()
        identifier = _identifier(agent.get("id"), _ID)
        tenant = _identifier(agent.get("tenant"), _ID)
        principal = _identifier(agent.get("principal"), _ID)
        granted = agent.get("routes")
        if (type(granted) is not list
                or any(type(route) is not str or _ROUTE.fullmatch(route) is None
                       for route in granted)
                or len(set(granted)) != len(granted)
                or identifier in registry
                or (tenant, principal, identifier) in identities):
            _invalid()
        identities.add((tenant, principal, identifier))
        registry[identifier] = (tenant, principal, frozenset(granted))
    return registry


def _route_registry(routes):
    if type(routes) is not list:
        _invalid()
    registry = {}
    for route in routes:
        if type(route) is not dict:
            _invalid()
        name = _identifier(route.get("name"), _ROUTE)
        tenant = _identifier(route.get("tenant"), _ID)
        operation = route.get("operation")
        selected = route.get("policy_engine")
        if (type(operation) is not str or not operation or len(operation) > 256
                or (selected is not None
                    and (type(selected) is not str or _ID.fullmatch(selected) is None))
                or name in registry):
            _invalid()
        registry[name] = (tenant, operation, selected)
    return registry


def validate_policy_engine(definition, *, agents, routes):
    """Validate one AGT definition without importing the optional SDK."""
    definition = _exact_object(definition, ("name", "kind", "tenant", "bindings"))
    name = _identifier(definition["name"], _ID)
    tenant = _identifier(definition["tenant"], _ID)
    if definition["kind"] != "agt" or type(definition["kind"]) is not str:
        _invalid()
    agent_registry = _agent_registry(agents)
    route_registry = _route_registry(routes)
    bindings = definition["bindings"]
    if type(bindings) is not list or not 1 <= len(bindings) <= 256:
        _invalid()

    normalized_bindings = []
    pairs = set()
    for binding in bindings:
        binding = _exact_object(binding, ("agent", "route", "conditions"))
        agent_name = _identifier(binding["agent"], _ID)
        route_name = _identifier(binding["route"], _ROUTE)
        pair = (agent_name, route_name)
        if pair in pairs:
            _invalid()
        pairs.add(pair)
        agent = agent_registry.get(agent_name)
        route = route_registry.get(route_name)
        if (agent is None or route is None
                or agent[0] != tenant or route[0] != tenant
                or route_name not in agent[2]
                or route[1] == "security.assess"
                or route[2] != name):
            _invalid()
        conditions = binding["conditions"]
        if type(conditions) is not list or not 1 <= len(conditions) <= 16:
            _invalid()
        normalized_conditions = []
        for condition in conditions:
            condition = _exact_object(condition, ("field", "operator", "value"))
            field = condition["field"]
            if type(field) is not str:
                _invalid()
            parts = field.split(".")
            if (not 1 <= len(parts) <= 8
                    or any(_FIELD_SEGMENT.fullmatch(part) is None
                           or "__" in part for part in parts)):
                _invalid()
            operator = condition["operator"]
            if type(operator) is not str or operator not in ("eq", "lte", "gte"):
                _invalid()
            value = _condition_value(condition["value"], operator)
            normalized_conditions.append({
                "field": ".".join(parts),
                "operator": operator,
                "value": value,
            })
        normalized_bindings.append({
            "agent": agent_name,
            "route": route_name,
            "conditions": normalized_conditions,
        })

    normalized = {
        "name": name,
        "kind": "agt",
        "tenant": tenant,
        "bindings": normalized_bindings,
    }
    return json.loads(json.dumps(normalized, separators=(",", ":"), allow_nan=False))


def _role(tenant, principal, agent):
    return json.dumps([tenant, principal, agent], separators=(",", ":"))


def _local_conditions(definition, agents):
    registry = _agent_registry(agents)
    result = {}
    for binding in definition["bindings"]:
        tenant, principal, _ = registry[binding["agent"]]
        key = (tenant, principal, binding["agent"], binding["route"])
        result[key] = tuple(
            _LocalCondition(
                tuple(condition["field"].split(".")),
                condition["operator"],
                condition["value"],
            )
            for condition in binding["conditions"]
        )
    return MappingProxyType(result)


def _matches(payload, conditions):
    if type(payload) is not dict:
        return False
    for condition in conditions:
        actual = payload
        for part in condition.path:
            if type(actual) is not dict or part not in actual:
                return False
            actual = actual[part]
        if actual is None or type(actual) is not type(condition.value):
            return False
        if type(actual) is float and not math.isfinite(actual):
            return False
        if type(actual) not in (bool, int, float, str):
            return False
        if condition.operator == "eq" and actual != condition.value:
            return False
        if condition.operator == "lte" and actual > condition.value:
            return False
        if condition.operator == "gte" and actual < condition.value:
            return False
    return True


def _load_sdk():
    try:
        from importlib import metadata
        version = metadata.version(_AGT_DISTRIBUTION)
    except Exception:
        raise AGTPolicyError("agt_policy_sdk_unavailable") from None
    if version != _AGT_VERSION:
        raise AGTPolicyError("agt_policy_sdk_incompatible")
    try:
        from agent_control_plane.policy_engine import (
            Condition,
            ConditionalPermission,
            PolicyEngine,
        )
    except Exception:
        raise AGTPolicyError("agt_policy_sdk_incompatible") from None
    return PolicyEngine, Condition, ConditionalPermission


def build_policy_control(definition, *, agents, routes):
    """Build a required async ``agt.<name>`` control from trusted configuration."""
    normalized = validate_policy_engine(definition, agents=agents, routes=routes)
    try:
        agent_snapshot = json.loads(json.dumps(agents, separators=(",", ":"), allow_nan=False))
        route_snapshot = json.loads(json.dumps(routes, separators=(",", ":"), allow_nan=False))
    except Exception:
        raise AGTPolicyError("agt_policy_invalid") from None
    normalized = validate_policy_engine(
        normalized,
        agents=agent_snapshot,
        routes=route_snapshot,
    )
    local_conditions = _local_conditions(normalized, agent_snapshot)
    control_name = "agt." + normalized["name"]
    PolicyEngine, Condition, ConditionalPermission = _load_sdk()

    agent_registry = _agent_registry(agent_snapshot)
    role_routes = {}
    try:
        engine = PolicyEngine()
        for binding in normalized["bindings"]:
            tenant, principal, _ = agent_registry[binding["agent"]]
            role = _role(tenant, principal, binding["agent"])
            role_routes.setdefault(role, []).append(binding["route"])
        for role, route_names in role_routes.items():
            engine.add_constraint(role, list(route_names))
        for binding in normalized["bindings"]:
            tenant, principal, _ = agent_registry[binding["agent"]]
            role = _role(tenant, principal, binding["agent"])
            conditions = [
                Condition(
                    "args." + condition["field"],
                    condition["operator"],
                    condition["value"],
                )
                for condition in binding["conditions"]
            ]
            if any(
                    compiled.attribute_path != "args." + configured["field"]
                    or compiled.operator != configured["operator"]
                    or type(compiled.value) is not type(configured["value"])
                    or compiled.value != configured["value"]
                    for compiled, configured in zip(
                        conditions, binding["conditions"], strict=True)):
                raise ValueError()
            permission = ConditionalPermission(binding["route"], conditions)
            if (permission.tool_name != binding["route"]
                    or permission.conditions != conditions
                    or permission.require_all is not True):
                raise ValueError()
            engine.add_conditional_permission(role, permission)
        engine.freeze()
        mapping_proxy = type(MappingProxyType({}))
        if (engine.is_frozen is not True
                or type(engine.state_permissions) is not mapping_proxy
                or type(engine.conditional_permissions) is not mapping_proxy
                or type(engine.agent_contexts) is not mapping_proxy
                or set(engine.state_permissions) != set(role_routes)
                or set(engine.conditional_permissions) != set(role_routes)
                or engine.agent_contexts
                or not callable(getattr(engine, "check_violation", None))
                or not callable(getattr(engine, "is_shadow_mode", None))):
            raise ValueError()
        for role, route_names in role_routes.items():
            if (engine.state_permissions.get(role) != frozenset(route_names)
                    or type(engine.conditional_permissions.get(role)) is not tuple
                    or engine.is_shadow_mode(role) is not False):
                raise ValueError()
        from .engines import agt_control
        vendor_control = agt_control(engine, name=control_name)
    except Exception:
        raise AGTPolicyError("agt_policy_sdk_incompatible") from None

    async def check(operation):
        if type(operation) is not Operation or type(operation.context) is not SecurityContext:
            raise AGTPolicyError("agt_policy_runtime_failed")
        context = operation.context
        conditions = local_conditions.get((
            context.tenant_id,
            context.principal_id,
            context.agent_id,
            operation.route,
        ))
        denied = ControlResult(
            control_name,
            context.tenant_id,
            context.operation_id,
            Action.DENY,
        )
        if conditions is None:
            return denied
        try:
            payload = operation.payload()
        except Exception:
            return denied
        if not _matches(payload, conditions):
            return denied
        try:
            result = await vendor_control(operation)
            if (type(result) is not ControlResult
                    or result.control_id != control_name
                    or result.tenant_id != context.tenant_id
                    or result.operation_id != context.operation_id
                    or result.action not in (Action.ALLOW, Action.DENY)):
                raise ValueError()
            return result
        except Exception:
            raise AGTPolicyError("agt_policy_runtime_failed") from None

    check.__name__ = control_name
    return check
