"""Bound, non-authoritative AI security assessment protocol.

The analyzer can recommend only a fixed decision/risk/signal tuple bound to an
existing action digest. It cannot execute, rewrite, authorize, or grant tools.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import inspect
import json
import math
import re

from .contracts import SecurityContext
from .model_responses import (
    MAX_ENVELOPE_BYTES,
    _CHOICE_FIELDS,
    _MESSAGE_FIELDS,
    _OUTER_FIELDS,
    _metadata_allowed,
    _nonfinite,
    _unique_object,
    _utf8_size,
    _validate_json_tree,
)
from .runtime import Operation


ASSESSMENT_SCHEMA_VERSION = 1
MAX_ASSESSMENT_BYTES = 16_384
MAX_CONTEXT_BYTES = 32_768
MAX_SIGNALS = 16
MAX_COMPLETION_TOKENS = 512

DECISIONS = frozenset({"allow", "deny", "require_approval"})
RISKS = frozenset({"low", "medium", "high", "critical"})
SIGNALS = frozenset({
    "prompt_injection",
    "data_exfiltration",
    "credential_theft",
    "privilege_escalation",
    "destructive_action",
    "untrusted_instruction",
    "tool_misuse",
    "policy_evasion",
    "suspicious_sequence",
})

_DIGEST = re.compile(r"[0-9a-f]{64}")
_ASSESSMENT_FIELDS = frozenset({"schema_version", "action_digest", "decision", "risk", "confidence", "signals"})

_SYSTEM_MESSAGE = """You are a security assessment classifier, not an executor.
Return exactly one JSON object and no prose. The object must have exactly:
schema_version (integer 1), action_digest (the supplied lowercase digest),
decision (allow, deny, or require_approval), risk (low, medium, high, or critical),
confidence (finite number from 0 through 1), and signals (a unique JSON list using
only: prompt_injection, data_exfiltration, credential_theft, privilege_escalation,
destructive_action, untrusted_instruction, tool_misuse, policy_evasion,
suspicious_sequence). Do not return tools, identities, permissions, rewritten
payloads, instructions, explanations, or any additional fields."""


class AssessmentError(Exception):
    """Fixed public failure for an invalid or unavailable assessment."""

    def __init__(self):
        super().__init__("assessment_invalid")


class InspectionBoundaryError(AssessmentError):
    """An internal deterministic inspection boundary refused dispatch.

    Unlike model uncertainty, this cannot be satisfied by approval fallback.
    """


def _valid_digest(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


@dataclass(frozen=True)
class SecurityAssessment:
    schema_version: int
    action_digest: str
    decision: str
    risk: str
    confidence: int | float
    signals: tuple[str, ...]

    def __post_init__(self):
        if (type(self.schema_version) is not int or self.schema_version != ASSESSMENT_SCHEMA_VERSION
                or not _valid_digest(self.action_digest)
                or type(self.decision) is not str or self.decision not in DECISIONS
                or type(self.risk) is not str or self.risk not in RISKS
                or type(self.confidence) not in (int, float) or not math.isfinite(self.confidence)
                or not 0 <= self.confidence <= 1
                or type(self.signals) is not tuple or len(self.signals) > MAX_SIGNALS
                or any(type(signal) is not str or signal not in SIGNALS for signal in self.signals)
                or len(set(self.signals)) != len(self.signals)
                or (self.risk != "low" and not self.signals)):
            raise AssessmentError()


def _bounded_json(value, maximum):
    _validate_json_tree(value)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    if _utf8_size(encoded) > maximum:
        raise ValueError()
    return encoded


def parse_assessment(value, *, action_digest):
    """Parse an exact assessment dictionary and bind it to ``action_digest``."""
    try:
        if not _valid_digest(action_digest) or type(value) is not dict:
            raise ValueError()
        _bounded_json(value, MAX_ASSESSMENT_BYTES)
        if set(value) != _ASSESSMENT_FIELDS or value["action_digest"] != action_digest:
            raise ValueError()
        if type(value["signals"]) is not list:
            raise ValueError()
        return SecurityAssessment(
            schema_version=value["schema_version"],
            action_digest=value["action_digest"],
            decision=value["decision"],
            risk=value["risk"],
            confidence=value["confidence"],
            signals=tuple(value["signals"]),
        )
    except AssessmentError:
        raise
    except Exception:
        raise AssessmentError() from None


def _response_content(value):
    _validate_json_tree(value)
    if type(value) is not dict or set(value) - _OUTER_FIELDS or "choices" not in value:
        raise ValueError()
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if _utf8_size(encoded) > MAX_ENVELOPE_BYTES or not _metadata_allowed(value):
        raise ValueError()
    choices = value["choices"]
    if type(choices) is not list or len(choices) != 1:
        raise ValueError()
    choice = choices[0]
    if (type(choice) is not dict or set(choice) - _CHOICE_FIELDS
            or not {"index", "message", "finish_reason"} <= set(choice)
            or type(choice["index"]) is not int or choice["index"] != 0
            or choice["finish_reason"] != "stop"
            or ("logprobs" in choice and choice["logprobs"] is not None)):
        raise ValueError()
    message = choice["message"]
    if (type(message) is not dict or set(message) - _MESSAGE_FIELDS
            or not {"role", "content"} <= set(message) or message["role"] != "assistant"
            or type(message["content"]) is not str
            or ("refusal" in message and message["refusal"] not in (None, ""))):
        raise ValueError()
    content = message["content"]
    if not content or _utf8_size(content) > MAX_ASSESSMENT_BYTES:
        raise ValueError()
    return content


class ChatSecurityAnalyzer:
    """Call one trusted, fixed chat provider and parse its bound assessment."""

    def __init__(self, provider, *, timeout=1.5):
        model = getattr(provider, "model", None)
        call = getattr(provider, "call", None)
        if (type(model) is not str or not model or len(model) > 128
                or not inspect.iscoroutinefunction(call)
                or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30):
            raise AssessmentError()
        self.provider = provider
        self.model = model
        self.timeout = timeout

    async def analyze(self, operation, context, action_digest):
        try:
            if (type(operation) is not Operation or type(operation.context) is not SecurityContext
                    or operation.context.operation != "security.assess" or operation.resource != self.model
                    or not _valid_digest(operation.digest)
                    or not _valid_digest(action_digest) or type(context) is not dict):
                raise ValueError()
            context_json = _bounded_json(context, MAX_CONTEXT_BYTES)
            user_json = json.dumps({"action_digest": action_digest, "context": json.loads(context_json)},
                                   ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
            request = {
                "messages": [
                    {"role": "system", "content": _SYSTEM_MESSAGE},
                    {"role": "user", "content": user_json},
                ],
                "model": self.model,
                "stream": False,
                "temperature": 0,
                "max_tokens": MAX_COMPLETION_TOKENS,
                "response_format": {"type": "json_object"},
            }
            payload_json = _bounded_json(request, MAX_CONTEXT_BYTES + 16_384)
            inspector_operation = Operation(
                operation.context,
                operation.route,
                operation.resource,
                operation.destination,
                payload_json,
                operation.digest,
            )
            response = await asyncio.wait_for(self.provider.call(inspector_operation), timeout=self.timeout)
            content = _response_content(response)
            value = json.loads(content, object_pairs_hook=_unique_object, parse_constant=_nonfinite)
            return parse_assessment(value, action_digest=action_digest)
        except AssessmentError:
            raise
        except Exception:
            raise AssessmentError() from None

