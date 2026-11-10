"""Deterministic, operator-configured task boundaries for admitted operations.

This control checks immutable request facts and an exact JSON object shape.  It
does not infer intent, consult caller-defined code, or establish business truth.
"""

from dataclasses import dataclass, field
import math
from types import MappingProxyType
from typing import Mapping

from .contracts import Action, ControlResult, SecurityContext
from .runtime import Operation


_KINDS = frozenset({"str", "int", "bool"})


def _bounded_string(value: object, label: str) -> str:
    if (type(value) is not str or not value or len(value) > 256
            or value != value.strip() or not value.isprintable()):
        raise ValueError(f"invalid_{label}")
    return value


def _matches_kind(value: object, kind: str) -> bool:
    return ((kind == "str" and type(value) is str)
            or (kind == "int" and type(value) is int)
            or (kind == "bool" and type(value) is bool))


@dataclass(frozen=True)
class FieldRule:
    """One scalar leaf in an exact, dictionary-only payload schema."""

    path: tuple[str, ...]
    kind: str
    required: bool = True
    choices: frozenset[str | int | bool] | None = None
    minimum: int | None = None
    maximum: int | None = None
    max_length: int | None = None

    def __post_init__(self) -> None:
        if type(self.path) is not tuple or not self.path:
            raise ValueError("invalid_field_path")
        for part in self.path:
            _bounded_string(part, "field_path")
        if type(self.kind) is not str or self.kind not in _KINDS:
            raise ValueError("invalid_field_kind")
        if type(self.required) is not bool:
            raise ValueError("invalid_required_flag")

        choices = self.choices
        if choices is not None:
            if type(choices) not in (tuple, list, set, frozenset):
                raise ValueError("invalid_field_choices")
            choice_items = tuple(choices)
            if not choice_items or any(not _matches_kind(item, self.kind) for item in choice_items):
                raise ValueError("invalid_field_choices")
            try:
                frozen_choices = frozenset(choice_items)
            except TypeError:
                raise ValueError("invalid_field_choices") from None
            object.__setattr__(self, "choices", frozen_choices)

        if self.kind == "int":
            for limit in (self.minimum, self.maximum):
                if limit is not None and type(limit) is not int:
                    raise ValueError("invalid_integer_range")
            if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
                raise ValueError("invalid_integer_range")
            if self.max_length is not None:
                raise ValueError("invalid_string_limit")
        elif self.kind == "str":
            if self.minimum is not None or self.maximum is not None:
                raise ValueError("invalid_integer_range")
            if self.max_length is not None and (type(self.max_length) is not int or self.max_length < 0):
                raise ValueError("invalid_string_limit")
        elif any(value is not None for value in (self.minimum, self.maximum, self.max_length)):
            raise ValueError("invalid_field_constraint")

        if self.choices is not None:
            for choice in self.choices:
                if not self.accepts(choice):
                    raise ValueError("choice_outside_field_constraints")

    def accepts(self, value: object) -> bool:
        if not _matches_kind(value, self.kind):
            return False
        if self.choices is not None and value not in self.choices:
            return False
        if self.kind == "str":
            return self.max_length is None or len(value) <= self.max_length
        if self.kind == "int":
            return ((self.minimum is None or value >= self.minimum)
                    and (self.maximum is None or value <= self.maximum))
        return True


def _freeze_schema(node: dict) -> Mapping:
    return MappingProxyType({key: value if type(value) is FieldRule else _freeze_schema(value)
                             for key, value in node.items()})


def _schema_for(rules: tuple[FieldRule, ...]) -> Mapping:
    root: dict = {}
    for rule in rules:
        node = root
        for part in rule.path[:-1]:
            existing = node.get(part)
            if type(existing) is FieldRule:
                raise ValueError("conflicting_field_paths")
            if existing is None:
                existing = {}
                node[part] = existing
            node = existing
        leaf = rule.path[-1]
        if leaf in node:
            raise ValueError("duplicate_or_conflicting_field_path")
        node[leaf] = rule
    return _freeze_schema(root)


@dataclass(frozen=True)
class TaskBoundary:
    """Exact trusted-host binding and payload rules for one bounded task."""

    tenant_id: str
    principal_id: str
    workflow_id: str
    route: str
    resource: str
    destination: str
    operations: frozenset[str]
    fields: tuple[FieldRule, ...] = ()
    _schema: Mapping = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        for label in ("tenant_id", "principal_id", "workflow_id", "route", "resource", "destination"):
            _bounded_string(getattr(self, label), label)

        if type(self.operations) not in (tuple, list, set, frozenset):
            raise ValueError("invalid_operations")
        operations = tuple(self.operations)
        if not operations:
            raise ValueError("invalid_operations")
        for operation in operations:
            _bounded_string(operation, "operation")
        frozen_operations = frozenset(operations)

        if type(self.fields) not in (tuple, list):
            raise ValueError("invalid_field_rules")
        fields = tuple(self.fields)
        if any(type(rule) is not FieldRule for rule in fields):
            raise ValueError("invalid_field_rules")

        # Reuse the public context contract as well as the stricter host-config
        # string checks above, so identifier length and shape stay aligned.
        for operation in frozen_operations:
            SecurityContext(self.tenant_id, self.principal_id, "task-boundary",
                            self.workflow_id, "task-boundary", operation, "task-boundary")

        object.__setattr__(self, "operations", frozen_operations)
        object.__setattr__(self, "fields", fields)
        object.__setattr__(self, "_schema", _schema_for(fields))


def _has_required(schema: Mapping) -> bool:
    return any((value.required if type(value) is FieldRule else _has_required(value))
               for value in schema.values())


def _valid_json_value(value: object) -> bool:
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(_valid_json_value(item) for item in value)
    if type(value) is dict:
        return all(type(key) is str and _valid_json_value(item) for key, item in value.items())
    return False


def _valid_payload(payload: object, schema: Mapping) -> bool:
    if type(payload) is not dict or any(type(key) is not str for key in payload):
        return False
    if set(payload) - set(schema):
        return False
    for name, expected in schema.items():
        if name not in payload:
            required = expected.required if type(expected) is FieldRule else _has_required(expected)
            if required:
                return False
            continue
        value = payload[name]
        if type(expected) is FieldRule:
            if not expected.accepts(value):
                return False
        elif not _valid_payload(value, expected):
            return False
    return True


def intent_control(boundary: TaskBoundary, name: str = "task_boundary"):
    """Return an async GuardRuntime control bound to an immutable snapshot."""

    if type(boundary) is not TaskBoundary:
        raise ValueError("invalid_task_boundary")
    _bounded_string(name, "control_name")
    ControlResult(name, boundary.tenant_id, "task-boundary", Action.DENY)

    tenant_id = boundary.tenant_id
    principal_id = boundary.principal_id
    workflow_id = boundary.workflow_id
    route = boundary.route
    resource = boundary.resource
    destination = boundary.destination
    operations = frozenset(boundary.operations)
    schema = boundary._schema

    async def control(operation: Operation) -> ControlResult:
        context = operation.context
        allowed = False
        if type(operation) is Operation and type(context) is SecurityContext:
            try:
                SecurityContext(context.tenant_id, context.principal_id, context.agent_id,
                                context.workflow_id, context.operation_id, context.operation,
                                context.policy_version)
                payload = operation.payload()
                allowed = (_valid_json_value(payload)
                           and context.tenant_id == tenant_id
                           and context.principal_id == principal_id
                           and context.workflow_id == workflow_id
                           and context.operation in operations
                           and operation.route == route
                           and operation.resource == resource
                           and operation.destination == destination
                           and _valid_payload(payload, schema))
            except (TypeError, ValueError, RecursionError):
                allowed = False
        return ControlResult(name, context.tenant_id, context.operation_id,
                             Action.ALLOW if allowed else Action.DENY)

    return control
