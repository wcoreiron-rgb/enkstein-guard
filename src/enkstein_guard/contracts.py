"""Version 1 decision aggregation contract; does not execute or authorize tools.

Inputs must come from trusted adapters. Tenant labels are not authentication.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

CONTRACT_VERSION = "1.0"


class Action(str, Enum):
    ALLOW = "allow"
    MONITOR = "monitor"
    MASK = "mask"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class Status(str, Enum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


def _identifier(value: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("Invalid contract identifier")


@dataclass(frozen=True)
class SecurityContext:
    tenant_id: str
    principal_id: str
    agent_id: str
    workflow_id: str
    operation_id: str
    operation: str
    policy_version: str

    def __post_init__(self) -> None:
        for value in vars(self).values():
            _identifier(value)


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    tenant_id: str
    operation_id: str
    action: Action
    status: Status = Status.OK

    def __post_init__(self) -> None:
        for value in (self.control_id, self.tenant_id, self.operation_id):
            _identifier(value)
        if not isinstance(self.action, Action) or not isinstance(self.status, Status):
            raise ValueError("Unknown action or control status")


@dataclass(frozen=True)
class CombinedDecision:
    action: Action
    reason_codes: tuple[str, ...]
    controls: tuple[str, ...]
    degraded: bool
    contract_version: str = CONTRACT_VERSION


def combine_results(
    context: SecurityContext,
    results: Iterable[ControlResult],
    *,
    required_controls: Iterable[str],
) -> CombinedDecision:
    """Deny absent required controls, failed required controls and bad binding.

    Every successful deny wins, including from optional controls. Allow results
    are recommendations only: gateways must separately authenticate, authorize,
    apply masks, validate approval and enforce execution constraints.
    """
    required = frozenset(required_controls)
    for name in required:
        _identifier(name)
    items = tuple(results)
    reasons: set[str] = set()
    seen: set[str] = set()
    actions: list[Action] = []
    degraded = False
    for item in items:
        if not isinstance(item, ControlResult):
            raise ValueError("Invalid control result")
        if item.control_id in seen:
            reasons.add("duplicate_control")
        seen.add(item.control_id)
        if item.tenant_id != context.tenant_id or item.operation_id != context.operation_id:
            reasons.add("context_mismatch")
        if item.status != Status.OK:
            degraded = True
            if item.control_id in required:
                reasons.add("required_control_failed")
            continue
        actions.append(item.action)
    if not required:
        reasons.add("required_controls_unspecified")
    if required - seen:
        reasons.add("required_control_missing")
    rank = {action: index for index, action in enumerate(Action)}
    action = Action.DENY if reasons else max(actions, key=rank.__getitem__, default=Action.DENY)
    if not reasons:
        reasons.add("control_denied" if action == Action.DENY else "controls_evaluated")
    return CombinedDecision(action, tuple(sorted(reasons)), tuple(sorted(seen)), degraded)
