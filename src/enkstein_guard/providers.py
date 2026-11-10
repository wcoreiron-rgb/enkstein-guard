"""Non-streaming HTTPS chat-completions transport with vault-brokered API key.

No SDK monkeypatching, provider fallback, redirects or dynamic caller endpoints.
Use `provider.call` as the model transport in PrivateAI, never as a raw agent tool.
"""

import asyncio
import json
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .runtime import AccessDenied, RejectedBeforeDispatch, UnavailableBeforeDispatch
from .blocking import BoundedBlockingTransport


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Agent-supplied request bodies are limited to text chat fields. Fields that make
# the provider fetch URLs, run hosted tools, store data or return media (image or
# file parts, web search, hosted tool types, store/metadata, audio) would move
# data to destinations Guard never authorized, so they are refused before dispatch.
CHAT_FIELDS = frozenset({"messages", "model", "stream", "temperature", "top_p", "max_tokens", "max_completion_tokens",
                         "stop", "seed", "response_format", "presence_penalty", "frequency_penalty", "tools",
                         "tool_choice", "parallel_tool_calls", "reasoning_effort"})
_ROLES = frozenset({"system", "developer", "user", "assistant", "tool"})
_MESSAGE_FIELDS = frozenset({"role", "content", "name", "tool_calls", "tool_call_id", "refusal"})


def failure_code(error):
    """Fixed reason code for a failed provider call (never exception text)."""
    import socket
    import ssl
    from urllib.error import HTTPError, URLError
    from .egress import EgressDenied
    cause = error.reason if isinstance(error, URLError) and not isinstance(error, HTTPError) else error
    if isinstance(cause, EgressDenied):
        return "egress_" + str(cause).removeprefix("egress_")[:40]
    if isinstance(error, HTTPError):
        return "provider_http_%d" % error.code if 100 <= error.code <= 599 else "provider_http_error"
    if isinstance(cause, ssl.SSLError):
        return "provider_tls_failed"
    if isinstance(cause, (TimeoutError, socket.timeout)):
        return "provider_timeout"
    if isinstance(cause, OSError):
        return "provider_connection_failed"
    if isinstance(error, ValueError):
        return "provider_response_invalid"
    return "provider_failed"


def _short(value, maximum=256):
    return isinstance(value, str) and 0 < len(value) <= maximum


def _number(value, low, high):
    return type(value) in (int, float) and low <= value <= high


def _text_content(content):
    if content is None or isinstance(content, str):
        return True
    if type(content) is not list or len(content) > 256:
        return False
    for part in content:
        if type(part) is not dict:
            return False
        if part.get("type") == "text" and set(part) == {"type", "text"} and isinstance(part["text"], str):
            continue
        if part.get("type") == "refusal" and set(part) == {"type", "refusal"} and isinstance(part["refusal"], str):
            continue
        return False
    return True


def _function_tool(tool):
    if type(tool) is not dict or set(tool) != {"type", "function"} or tool["type"] != "function":
        return False
    function = tool["function"]
    return (type(function) is dict and set(function) <= {"name", "description", "parameters", "strict"}
            and _short(function.get("name"), 128) and isinstance(function.get("description", ""), str)
            and type(function.get("parameters", {})) is dict and type(function.get("strict", False)) is bool)


def chat_request_allowed(payload):
    """True when an agent-supplied chat body uses only text chat fields."""
    if type(payload) is not dict or not set(payload) <= CHAT_FIELDS:
        return False
    messages = payload.get("messages")
    if type(messages) is not list or not 1 <= len(messages) <= 512:
        return False
    for message in messages:
        if (type(message) is not dict or not set(message) <= _MESSAGE_FIELDS or message.get("role") not in _ROLES
                or not _text_content(message.get("content"))):
            return False
        if "name" in message and not _short(message["name"], 128):
            return False
        if "tool_call_id" in message and not _short(message["tool_call_id"]):
            return False
        if "refusal" in message and not (message["refusal"] is None or isinstance(message["refusal"], str)):
            return False
        for call in message.get("tool_calls", []) if type(message.get("tool_calls", [])) is list else [None]:
            if (type(call) is not dict or set(call) != {"id", "type", "function"} or call["type"] != "function"
                    or not _short(call["id"]) or type(call["function"]) is not dict
                    or set(call["function"]) != {"name", "arguments"} or not _short(call["function"]["name"], 128)
                    or not isinstance(call["function"]["arguments"], str)):
                return False
    checks = {"temperature": lambda v: _number(v, 0, 2), "top_p": lambda v: _number(v, 0, 1),
              "max_tokens": lambda v: type(v) is int and 1 <= v <= 1_000_000,
              "max_completion_tokens": lambda v: type(v) is int and 1 <= v <= 1_000_000,
              "presence_penalty": lambda v: _number(v, -2, 2), "frequency_penalty": lambda v: _number(v, -2, 2),
              "seed": lambda v: type(v) is int, "parallel_tool_calls": lambda v: type(v) is bool,
              "reasoning_effort": lambda v: v in ("minimal", "low", "medium", "high"),
              "stop": lambda v: _short(v, 512) or (type(v) is list and len(v) <= 4 and all(_short(s, 512) for s in v)),
              "response_format": lambda v: type(v) is dict and (
                  (set(v) == {"type"} and v["type"] in ("text", "json_object"))
                  or (set(v) == {"type", "json_schema"} and v["type"] == "json_schema" and type(v["json_schema"]) is dict)),
              "tools": lambda v: type(v) is list and len(v) <= 128 and all(_function_tool(t) for t in v),
              "tool_choice": lambda v: v in ("none", "auto", "required") or (
                  type(v) is dict and set(v) == {"type", "function"} and v["type"] == "function"
                  and type(v["function"]) is dict and set(v["function"]) == {"name"} and _short(v["function"]["name"], 128))}
    return all(check(payload[name]) for name, check in checks.items() if name in payload)


class BrokeredChatProvider:
    def __init__(self, *, endpoint, allowed_hosts, model, broker, credential_name,
                 timeout=20, max_response_bytes=1_048_576, authentication="bearer",
                 egress=None, ssl_context=None, max_concurrent_calls=16):
        """``egress`` (EgressClient) tunnels connections through the independent
        egress proxy; ``ssl_context`` overrides the default trust store (for a
        private CA). Neither changes the fixed endpoint or disables verification."""
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or parsed.hostname not in frozenset(allowed_hosts)
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.port not in (None, 443) or not parsed.path.endswith("/chat/completions")):
            raise ValueError("invalid_provider_endpoint")
        if not isinstance(model, str) or not model or len(model) > 128:
            raise ValueError("invalid_provider_model")
        if type(timeout) not in (int, float) or not 0 < timeout <= 120:
            raise ValueError("invalid_provider_timeout")
        if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 16_777_216:
            raise ValueError("invalid_response_limit")
        if authentication not in {"bearer", "x-api-key"}:
            raise ValueError("invalid_provider_authentication")
        self._authentication = authentication
        self.destination = parsed.hostname
        self.model = model
        self._endpoint = endpoint
        self._broker, self._credential_name = broker, credential_name
        self._timeout, self._max_response_bytes = timeout, max_response_bytes
        # Disable environment proxy routing: it can otherwise receive API keys.
        from .egress import opener
        self._blocking = BoundedBlockingTransport(max_concurrent_calls)
        self._opener = opener(egress, ssl_context)
        self.egress = egress

    async def call(self, operation):
        if operation.destination != self.destination or operation.resource != self.model:
            raise RejectedBeforeDispatch("provider_binding_mismatch")
        async def send(credential, payload):
            if payload.get("model", self.model) != self.model or payload.get("stream", False) is not False:
                raise RejectedBeforeDispatch("provider_override_denied")
            if not chat_request_allowed(payload):
                raise RejectedBeforeDispatch("provider_request_not_allowed")
            body = dict(payload, model=self.model, stream=False)
            return await self._blocking.run(self._request, credential, body)
        return await self._broker.invoke(self._credential_name, operation, send)

    def _request(self, credential, payload):
        headers = {"Content-Type": "application/json"}
        if self._authentication == "bearer":
            headers["Authorization"] = "Bearer " + credential
        else:
            headers["X-API-Key"] = credential
        request = Request(self._endpoint, data=json.dumps(payload, allow_nan=False).encode(),
                          headers=headers,
                          method="POST")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status != 200:
                    raise ValueError()
                raw = response.read(self._max_response_bytes + 1)
                if len(raw) > self._max_response_bytes:
                    raise ValueError()
                result = json.loads(raw)
                if type(result) is not dict:
                    raise ValueError()
                return result
        except Exception as error:
            from .egress import ConnectFailed
            if isinstance(error, ConnectFailed):
                # Tunnel or TLS setup failed: the request never left Guard.
                raise UnavailableBeforeDispatch(error.code) from None
            failure = AccessDenied("provider_failed_outcome_unknown")
            failure.reason_code = failure_code(error)
            raise failure from None
