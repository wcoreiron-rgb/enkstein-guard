"""Strict adapter for one supported chat-completions response envelope.

The provider response is untrusted. This module unwraps only a completed,
single-choice assistant response whose content is the documented extractive
JSON object. Provider metadata is validated but never returned.
"""

from __future__ import annotations

import json
import math


MAX_CONTENT_BYTES = 65_536
MAX_ENVELOPE_BYTES = 131_072
MAX_JSON_DEPTH = 20
MAX_JSON_NODES = 4_096
MAX_CITATIONS = 16

_OUTER_FIELDS = frozenset({
    "choices", "id", "object", "created", "model", "usage", "service_tier", "system_fingerprint",
})
_CHOICE_FIELDS = frozenset({"index", "message", "finish_reason", "logprobs"})
_MESSAGE_FIELDS = frozenset({"role", "content", "refusal"})


class ModelResponseError(Exception):
    """A model response did not match the one supported safe envelope."""

    def __init__(self):
        super().__init__("model_response_invalid")


def _utf8_size(value):
    if type(value) is not str:
        raise ValueError()
    return len(value.encode("utf-8"))


def _validate_json_tree(value, depth=0, nodes=None):
    """Require bounded, exact built-in JSON types (no subclasses/objects)."""
    if nodes is None:
        nodes = [0, 0]
    nodes[0] += 1
    if depth > MAX_JSON_DEPTH or nodes[0] > MAX_JSON_NODES:
        raise ValueError()
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise ValueError()
            _validate_json_tree(key, depth + 1, nodes)
            _validate_json_tree(child, depth + 1, nodes)
        return
    if type(value) is list:
        for child in value:
            _validate_json_tree(child, depth + 1, nodes)
        return
    if type(value) is str:
        # Reject oversized trees before json.dumps can allocate a large copy.
        if len(value) > MAX_ENVELOPE_BYTES:
            raise ValueError()
        nodes[1] += _utf8_size(value)
        if nodes[1] > MAX_ENVELOPE_BYTES:
            raise ValueError()
        return
    if type(value) is int:
        if value.bit_length() > 4096:
            raise ValueError()
        return
    if value is None or type(value) is bool:
        return
    if type(value) is float and math.isfinite(value):
        return
    raise ValueError()


def _unique_object(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError()
        value[key] = child
    return value


def _nonfinite(_value):
    raise ValueError()


def _metadata_allowed(value):
    if "id" in value and (type(value["id"]) is not str or not value["id"] or _utf8_size(value["id"]) > 256):
        return False
    if "object" in value and value["object"] != "chat.completion":
        return False
    if "created" in value and (type(value["created"]) is not int or not 0 <= value["created"] <= 2**63 - 1):
        return False
    if "model" in value and (type(value["model"]) is not str or not value["model"]
                              or _utf8_size(value["model"]) > 256):
        return False
    if "usage" in value and type(value["usage"]) is not dict:
        return False
    for name in ("service_tier", "system_fingerprint"):
        item = value.get(name)
        if name in value and item is not None and (type(item) is not str or _utf8_size(item) > 256):
            return False
    return True


def _extract(value):
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
    if (type(message) is not dict or set(message) - _MESSAGE_FIELDS or not {"role", "content"} <= set(message)
            or message["role"] != "assistant" or type(message["content"]) is not str
            or ("refusal" in message and message["refusal"] not in (None, ""))):
        raise ValueError()
    content = message["content"]
    if not content or _utf8_size(content) > MAX_CONTENT_BYTES:
        raise ValueError()

    answer = json.loads(content, object_pairs_hook=_unique_object, parse_constant=_nonfinite)
    _validate_json_tree(answer)
    if type(answer) is not dict or set(answer) != {"answer", "citations"}:
        raise ValueError()
    if type(answer["answer"]) is not str or not answer["answer"]:
        raise ValueError()
    citations = answer["citations"]
    if type(citations) is not list or not 1 <= len(citations) <= MAX_CITATIONS:
        raise ValueError()
    for citation in citations:
        if (type(citation) is not dict or set(citation) != {"doc_id", "quote"}
                or type(citation["doc_id"]) is not str or not citation["doc_id"]
                or type(citation["quote"]) is not str or not citation["quote"]):
            raise ValueError()
    return answer


def extract_chat_answer(value):
    """Return only the strict extractive JSON content from a provider envelope.

    All invalid, incomplete, ambiguous, or unsupported responses fail with the
    same fixed error so provider-controlled values never become diagnostics.
    """
    try:
        return _extract(value)
    except Exception:
        raise ModelResponseError() from None

