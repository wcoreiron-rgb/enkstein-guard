"""Synthetic TLS chat-completions upstream for container acceptance only.

Never a real provider. Modes (UPSTREAM_MODE):
- capture (default): records method, path, header names, a SHA-256 of the
  API-key header and the request body to /capture/requests.jsonl.
- count: keeps bounded counters only (for capacity and soak runs) and writes
  /capture/stats.json every second: requests, requests per marker, duplicate
  markers. A marker is the text after "rid:" in the last user message, so the
  harness can prove a request was executed at most once.
A user message starting with "delay_ms:<n>" is answered after n milliseconds.
"""
import asyncio
import hashlib
import json
import os
import re
import ssl
import time

MODE = os.environ.get("UPSTREAM_MODE", "capture")
STATS = {"requests": 0, "markers": 0, "duplicate_markers": 0, "max_executions_per_marker": 0,
         "started": time.time(), "updated": None}
SEEN = {}
MARKER = re.compile(r"rid:([A-Za-z0-9_-]{8,128})")
DELAY = re.compile(r"^delay_ms:(\d{1,6})")


def text_of(body):
    try:
        content = body["messages"][-1]["content"]
    except Exception:
        return ""
    if isinstance(content, list):
        return " ".join(part.get("text", "") for part in content if isinstance(part, dict))
    return content if isinstance(content, str) else ""


async def handle(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.lower()] = value
        body = json.loads(await reader.readexactly(int(headers.get("content-length", "0"))) or b"{}")
        text = text_of(body)
        delay = DELAY.match(text)
        if delay:
            await asyncio.sleep(int(delay[1]) / 1000)
        STATS["requests"] += 1
        if MODE == "count":
            for marker in MARKER.findall(text):
                STATS["markers"] += 1
                if marker in SEEN:
                    STATS["duplicate_markers"] += 1
                SEEN[marker] = SEEN.get(marker, 0) + 1
                STATS["max_executions_per_marker"] = max(STATS["max_executions_per_marker"], SEEN[marker])
                if len(SEEN) > 2_000_000:
                    SEEN.clear()
        else:
            record = {"method": method, "path": path, "header_names": sorted(headers),
                      "api_key_sha256": hashlib.sha256(headers.get("x-api-key", "").encode()).hexdigest(),
                      "body": body}
            with open("/capture/requests.jsonl", "a") as stream:
                stream.write(json.dumps(record) + "\n")
        reply = json.dumps({"choices": [{"message": {"role": "assistant", "content": "synthetic upstream reply"}}]}).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                     % len(reply) + reply)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def publish():
    while True:
        await asyncio.sleep(1)
        STATS["updated"] = time.time()
        temporary = "/capture/stats.json.tmp"
        with open(temporary, "w") as stream:
            json.dump({**STATS, "unique_markers": len(SEEN)}, stream)
        os.replace(temporary, "/capture/stats.json")


async def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("/upstream/cert.pem", "/upstream/key.pem")
    server = await asyncio.start_server(handle, "0.0.0.0", 443, ssl=context, backlog=512)
    if MODE == "count":
        asyncio.ensure_future(publish())
    async with server:
        await server.serve_forever()


asyncio.run(main())
