"""Synthetic TLS upstream for AI-security production-profile acceptance only.

It serves two fixed models on one host, records only synthetic request bodies
and header hashes, and never contacts an external service.
"""

import asyncio
import hashlib
import json
import ssl


CAPTURE = "/capture/ai-security-requests.jsonl"
ASSESSMENT_MODEL = "synthetic-security"
BUSINESS_MODEL = "synthetic-model"


def _assessment(body):
    user = json.loads(body["messages"][1]["content"])
    digest = user["action_digest"]
    context = json.dumps(user["context"], sort_keys=True)
    value = {"schema_version": 1, "action_digest": digest, "decision": "allow",
             "risk": "low", "confidence": 1, "signals": []}
    if "scenario:deny" in context:
        value.update(decision="deny", risk="high", signals=["policy_evasion"])
    elif "scenario:critical" in context:
        value.update(risk="critical", signals=["suspicious_sequence"])
    elif "scenario:malformed" in context:
        value["permissions"] = ["execute"]
    elif "scenario:low-confidence" in context:
        value["confidence"] = 0.1
    return value


def _reply(body):
    model = body.get("model")
    if model == ASSESSMENT_MODEL:
        content = json.dumps(_assessment(body), separators=(",", ":"))
    elif model == BUSINESS_MODEL:
        content = "synthetic business response"
    else:
        raise ValueError("unsupported_synthetic_model")
    return {"id": "chatcmpl-ai-security-acceptance", "object": "chat.completion", "created": 1,
            "model": model, "choices": [{"index": 0,
                "message": {"role": "assistant", "content": content, "refusal": None},
                "finish_reason": "stop", "logprobs": None}]}


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
        model = body.get("model")
        record = {"kind": "inspection" if model == ASSESSMENT_MODEL else "business",
                  "model": model, "method": method, "path": path,
                  "header_names": sorted(headers),
                  "api_key_sha256": hashlib.sha256(headers.get("x-api-key", "").encode()).hexdigest(),
                  "body": body}
        with open(CAPTURE, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")
        encoded = json.dumps(_reply(body), separators=(",", ":")).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                     b"Connection: close\r\n\r\n" % len(encoded) + encoded)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("/upstream/cert.pem", "/upstream/key.pem")
    server = await asyncio.start_server(handle, "0.0.0.0", 443, ssl=context, backlog=64)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())

