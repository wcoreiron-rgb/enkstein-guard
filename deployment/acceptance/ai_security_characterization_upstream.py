"""Counters-only TLS upstream for AI-security characterization.

This fixture deliberately does not retain request bodies or header values. It
publishes only bounded cumulative counters in an atomically replaced JSON file.
"""

import asyncio
import hashlib
import json
import os
import ssl

from ai_security_upstream import ASSESSMENT_MODEL, BUSINESS_MODEL, _reply


STATS = "/capture/ai-security-characterization-stats.json"
SCHEMA = "enkstein-ai-security-characterization-upstream-v1"
MAX_HEADER_BYTES = 32 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_HEADERS = 64
MAX_HEADER_HASHES_PER_KIND = 16
KINDS = ("inspection", "business", "unknown")


def empty_stats():
    return {
        "schema": SCHEMA,
        "sequence": 0,
        "requests": 0,
        "inspection": 0,
        "business": 0,
        "unknown": 0,
        "models": {ASSESSMENT_MODEL: 0, BUSINESS_MODEL: 0, "unknown": 0},
        "header_hashes": {kind: {} for kind in KINDS},
    }


def parse_request_head(head):
    """Parse a bounded HTTP request head without retaining it."""
    if type(head) is not bytes or not head.endswith(b"\r\n\r\n"):
        raise ValueError("invalid_request_head")
    if len(head) > MAX_HEADER_BYTES:
        raise ValueError("request_headers_too_large")
    try:
        lines = head.decode("latin-1").split("\r\n")
        method, path, version = lines[0].split(" ", 2)
    except (UnicodeError, ValueError):
        raise ValueError("invalid_request_line") from None
    if method != "POST" or path != "/v1/chat/completions" or version != "HTTP/1.1":
        raise ValueError("invalid_method_or_path")
    header_lines = [line for line in lines[1:] if line]
    if len(header_lines) > MAX_HEADERS:
        raise ValueError("too_many_headers")
    headers = {}
    for line in header_lines:
        if ":" not in line:
            raise ValueError("invalid_header")
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if not key or key in headers:
            raise ValueError("invalid_header")
        headers[key] = value.strip()
    raw_length = headers.get("content-length")
    try:
        length = int(raw_length) if raw_length is not None else -1
    except ValueError:
        raise ValueError("invalid_content_length") from None
    if length < 2 or length > MAX_BODY_BYTES:
        raise ValueError("invalid_content_length")
    return length, headers


def classify(body):
    model = body.get("model") if type(body) is dict else None
    if model == ASSESSMENT_MODEL:
        return "inspection", ASSESSMENT_MODEL
    if model == BUSINESS_MODEL:
        return "business", BUSINESS_MODEL
    return "unknown", "unknown"


class CounterStore:
    def __init__(self, path=STATS):
        self.path = path
        self.value = empty_stats()
        self._write()

    def _write(self):
        encoded = json.dumps(self.value, sort_keys=True, separators=(",", ":")).encode()
        temporary = self.path + ".tmp-%d" % os.getpid()
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def record(self, kind, model, header_value):
        if kind not in KINDS or model not in (ASSESSMENT_MODEL, BUSINESS_MODEL, "unknown"):
            raise ValueError("invalid_counter_classification")
        digest = hashlib.sha256(header_value.encode()).hexdigest() if header_value else "missing"
        buckets = self.value["header_hashes"][kind]
        if digest not in buckets and len(buckets) >= MAX_HEADER_HASHES_PER_KIND:
            digest = "other"
        buckets[digest] = buckets.get(digest, 0) + 1
        self.value["sequence"] += 1
        self.value["requests"] += 1
        self.value[kind] += 1
        self.value["models"][model] += 1
        self._write()


def response(status, payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    reason = b"OK" if status == 200 else b"Bad Request"
    return (b"HTTP/1.1 %d " % status + reason
            + b"\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
              b"Connection: close\r\n\r\n" % len(encoded) + encoded)


async def handle(reader, writer, counters):
    kind = model = "unknown"
    api_key = ""
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        length, headers = parse_request_head(head)
        api_key = headers.get("x-api-key", "")
        body_bytes = await asyncio.wait_for(reader.readexactly(length), 10)
        body = json.loads(body_bytes)
        kind, model = classify(body)
        if kind == "unknown":
            raise ValueError("unsupported_synthetic_model")
        payload = _reply(body)
        status = 200
    except Exception as error:
        payload = {"error": type(error).__name__}
        status = 400
        kind = model = "unknown"
    try:
        # A response is never released before its cumulative counter is durable.
        counters.record(kind, model, api_key)
        writer.write(response(status, payload))
        await writer.drain()
    except Exception:
        # Counter persistence failure must not produce an uncounted success.
        pass
    finally:
        writer.close()


async def main():
    counters = CounterStore()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("/upstream/cert.pem", "/upstream/key.pem")
    server = await asyncio.start_server(
        lambda reader, writer: handle(reader, writer, counters),
        "0.0.0.0", 443, ssl=context, backlog=64, limit=MAX_HEADER_BYTES + 1)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
