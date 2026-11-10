"""Contextual, non-authoritative AI security control."""
from __future__ import annotations

import hashlib
import inspect
import json
import math
import re

from .contracts import Action, ControlResult, SecurityContext, Status
from .privacy import TOKEN, Tokenizer
from .runtime import Operation
from .security_assessment import (
    MAX_CONTEXT_BYTES, AssessmentError, InspectionBoundaryError,
    SecurityAssessment, parse_assessment,
)
from .security_context import HistoryRecord, SecurityHistoryError, SecurityHistoryStore
from .vault import Scope


_DIGEST = re.compile(r"[0-9a-f]{64}")
_LEVELS = frozenset({"unknown", "public", "internal", "confidential", "restricted"})
_LABELS = frozenset({"sensitive", "untrusted", "internal", "confidential", "restricted"})
_FAILURE_ACTIONS = {"deny": Action.DENY, "require_approval": Action.REQUIRE_APPROVAL}
_SEQUENCE_THRESHOLD = 3


def _canonical(value, maximum=MAX_CONTEXT_BYTES):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False)
    if len(encoded.encode()) > maximum:
        raise ValueError("ai_security_context_too_large")
    return encoded


def _ref(kind, *values):
    # Correlation handle only; pseudonymous, not guaranteed anonymous.
    material = _canonical(["ai-security-ref-v1", kind, *values], maximum=4096)
    return kind + ":" + hashlib.sha256(material.encode()).hexdigest()


def _opaque_native_references(value, depth=0):
    """Redact native vault refs in the AI inspection copy without restoring.

    A well-formed reference is only an opaque correlation marker here, never
    evidence that this inspection scope or destination was authorized to use
    the underlying value. Malformed ``[[EGV:`` text is intentionally retained
    so the ordinary tokenizer rejects it below.
    """
    if depth > 40:
        raise ValueError("ai_security_context_too_deep")
    if isinstance(value, str):
        return TOKEN.sub(
            lambda match: "protected-reference:"
            + hashlib.sha256(match.group(0).encode()).hexdigest(), value)
    if type(value) is list:
        return [_opaque_native_references(item, depth + 1) for item in value]
    if type(value) is dict:
        result = {}
        for key, item in value.items():
            protected_key = (_opaque_native_references(key, depth + 1)
                             if isinstance(key, str) else key)
            if protected_key in result:
                raise ValueError("ai_security_context_key_collision")
            result[protected_key] = _opaque_native_references(item, depth + 1)
        return result
    return value


def action_digest(operation):
    """Bind an assessment to trusted execution metadata and payload digest."""
    if (type(operation) is not Operation or type(operation.context) is not SecurityContext
            or type(operation.digest) is not str or _DIGEST.fullmatch(operation.digest) is None):
        raise ValueError("invalid_ai_security_operation")
    context = operation.context
    binding = {
        "tenant": context.tenant_id,
        "principal": context.principal_id,
        "agent": context.agent_id,
        "workflow": context.workflow_id,
        "operation_id": context.operation_id,
        "policy": context.policy_version,
        "route": operation.route,
        "resource": operation.resource,
        "destination": operation.destination,
        "operation_digest": operation.digest,
    }
    return hashlib.sha256(_canonical(binding).encode()).hexdigest()


class AISecurityControl:
    """Tokenize context, obtain a bound assessment, and return one control vote."""

    def __init__(self, *, analyzer, inspector_operation_for, tokenizer, history,
                 context_for=None, confidence_threshold=0.7,
                 failure_action="deny", name="ai_security"):
        analyze = getattr(analyzer, "analyze", None)
        if (not inspect.iscoroutinefunction(analyze)
                or not callable(inspector_operation_for)
                or inspect.iscoroutinefunction(inspector_operation_for)
                or type(tokenizer) is not Tokenizer
                or not callable(getattr(history, "recent", None))
                or not callable(getattr(history, "record", None))
                or (context_for is not None and (not callable(context_for)
                    or inspect.iscoroutinefunction(context_for)))
                or type(confidence_threshold) not in (int, float)
                or not math.isfinite(confidence_threshold)
                or not 0 <= confidence_threshold <= 1
                or failure_action not in _FAILURE_ACTIONS
                or type(name) is not str or not name or len(name) > 256):
            raise ValueError("invalid_ai_security_control")
        self._analyzer = analyzer
        self._inspector_operation_for = inspector_operation_for
        self._tokenizer = tokenizer
        self._history = history
        self._context_for = context_for
        self._confidence_threshold = confidence_threshold
        self._failure_action = _FAILURE_ACTIONS[failure_action]
        self.name = name

    def _result(self, operation, action, status=Status.OK):
        return ControlResult(self.name, operation.context.tenant_id,
                             operation.context.operation_id, action, status)

    def _sensitivity(self, operation):
        value = {} if self._context_for is None else self._context_for(operation)
        if value is None:
            value = {}
        if type(value) is not dict or set(value) - {"level", "labels"}:
            raise ValueError("invalid_ai_security_context")
        level = value.get("level", "unknown")
        labels = value.get("labels", ())
        if (type(level) is not str or level not in _LEVELS
                or type(labels) not in (list, tuple, frozenset)
                or any(type(label) is not str or label not in _LABELS for label in labels)
                or len(labels) != len(set(labels)) or len(labels) > len(_LABELS)):
            raise ValueError("invalid_ai_security_context")
        return {"level": level, "labels": sorted(labels)}

    @staticmethod
    def _history_context(records):
        if type(records) is not tuple or len(records) > 16:
            raise SecurityHistoryError("security_history_invalid_result")
        result = []
        for item in records:
            if type(item) is not HistoryRecord:
                raise SecurityHistoryError("security_history_invalid_result")
            # Real actor/tenant/workflow identifiers remain local.
            result.append({
                "route": item.route,
                "decision": item.decision,
                "risk": item.risk,
                "confidence": item.confidence,
                "signals": list(item.signals),
                "action": item.action,
                "action_ref": _ref("action", item.action_digest),
            })
        return result

    @staticmethod
    def _validated_assessment(value, digest):
        if type(value) is not SecurityAssessment:
            raise AssessmentError()
        return parse_assessment({
            "schema_version": value.schema_version,
            "action_digest": value.action_digest,
            "decision": value.decision,
            "risk": value.risk,
            "confidence": value.confidence,
            "signals": list(value.signals),
        }, action_digest=digest)

    @staticmethod
    def _decision(assessment, prior_denials, confidence_threshold, failure_action):
        if assessment.decision == "deny" or assessment.risk == "critical":
            action = Action.DENY
        elif assessment.decision == "require_approval" or assessment.risk == "high":
            action = Action.REQUIRE_APPROVAL
        else:
            action = Action.ALLOW
        if action == Action.ALLOW and assessment.confidence < confidence_threshold:
            action = failure_action
        if prior_denials >= _SEQUENCE_THRESHOLD and action == Action.ALLOW:
            action = Action.REQUIRE_APPROVAL
        return action

    @staticmethod
    def _sequence_assessment(assessment, prior_denials):
        if prior_denials < _SEQUENCE_THRESHOLD or "suspicious_sequence" in assessment.signals:
            return assessment
        return parse_assessment({
            "schema_version": assessment.schema_version,
            "action_digest": assessment.action_digest,
            "decision": assessment.decision,
            "risk": assessment.risk,
            "confidence": assessment.confidence,
            "signals": [*assessment.signals, "suspicious_sequence"],
        }, action_digest=assessment.action_digest)

    async def __call__(self, operation):
        # Local context/vault/history failures always deny. Only assessment
        # failures are eligible for the explicit configured fallback action.
        try:
            digest = action_digest(operation)
            recent = self._history.recent(operation, limit=16)
            history_context = self._history_context(recent)
            internal = self._inspector_operation_for(operation)
            if (type(internal) is not Operation or type(internal.context) is not SecurityContext
                    or internal.context.tenant_id != operation.context.tenant_id
                    or internal.route == operation.route
                    or internal.context.principal_id != "guard-security"
                    or internal.context.agent_id != "guard-security"
                    or internal.context.operation != "security.assess"
                    or json.loads(internal.payload_json) != {}):
                raise ValueError("invalid_ai_security_inspector_operation")
            context = operation.context
            tenant_ref = _ref("tenant", context.tenant_id)
            actor_ref = _ref("actor", context.tenant_id, context.principal_id, context.agent_id)
            workflow_ref = _ref("workflow", context.tenant_id, context.workflow_id)
            visible = {
                "actor_ref": actor_ref,
                "tenant_ref": tenant_ref,
                "workflow_ref": workflow_ref,
                "task": {
                    "operation": context.operation,
                    "policy": context.policy_version,
                    "route": operation.route,
                    "resource": operation.resource,
                    "destination": operation.destination,
                },
                "sensitivity": self._sensitivity(operation),
                "recent_decisions": history_context,
                "target_payload": operation.payload(),
            }
            scope = Scope(
                context.tenant_id, context.principal_id, context.workflow_id,
                _ref("inspection", context.agent_id, context.operation_id),
            )
            inspection_visible = _opaque_native_references(visible)
            sanitized = self._tokenizer.tokenize(
                inspection_visible, scope, (internal.destination,), allow_references=False,
                numeric_cards="tokenize")
            sanitized = json.loads(_canonical(sanitized))
            prior_denials = sum(item.action == Action.DENY.value for item in recent)
        except Exception:
            return self._result(operation, Action.DENY, Status.ERROR)

        try:
            # Keep the real trusted internal context for local broker credential
            # scope. ChatSecurityAnalyzer sends only ``sanitized`` in its model
            # request body; Operation.context remains in-process metadata.
            value = await self._analyzer.analyze(internal, sanitized, digest)
            assessment = self._validated_assessment(value, digest)
        except InspectionBoundaryError:
            # A deterministic local inspection control refused the internal
            # model call. Approval fallback cannot weaken that boundary.
            return self._result(operation, Action.DENY, Status.ERROR)
        except Exception:
            return self._result(operation, self._failure_action)

        try:
            assessment = self._sequence_assessment(assessment, prior_denials)
            action = self._decision(assessment, prior_denials,
                                    self._confidence_threshold, self._failure_action)
            self._history.record(operation, assessment, action)
            return self._result(operation, action)
        except Exception:
            return self._result(operation, Action.DENY, Status.ERROR)
