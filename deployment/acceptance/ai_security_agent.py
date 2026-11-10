"""Networkless untrusted-agent driver for synthetic AI-security acceptance."""

import asyncio
import json
import os
from pathlib import Path
import socket
import sys

from enkstein_guard.outcomes import new_request_id
from enkstein_guard.service import guarded_request


SOCKET = "/run/guard/guard.sock"


async def call(route, payload):
    token = Path("/run/agent-token").read_text().strip()
    try:
        return await guarded_request(SOCKET, token, route, payload, request_id=new_request_id(), timeout=30)
    except Exception as error:
        return {"status": "client_error", "error": type(error).__name__}


async def main():
    tenant = sys.argv[1]
    other = "b" if tenant == "a" else "a"
    checks, statuses = {}, {}
    statuses["benign"] = (await call(tenant + ".business", {
        "messages": [{"role": "user", "content": "scenario:benign synthetic request"}]}))["status"]
    if tenant == "a":
        # Validate benign privacy before three recorded denials trigger
        # the independently tested sequence-risk approval escalation.
        statuses["sensitive"] = (await call(tenant + ".business", {"messages": [{
            "role": "user", "content": "scenario:sensitive card 4111111111111111 key sk-" + "Z" * 32
        }]}))["status"]
        for scenario in ("deny", "critical", "malformed", "low-confidence"):
            statuses[scenario] = (await call(tenant + ".business", {
                "messages": [{"role": "user", "content": "scenario:%s synthetic request" % scenario}]}))["status"]
        checks["deny_critical_malformed_low_confidence_blocked"] = all(
            statuses[name] == "denied" for name in ("deny", "critical", "malformed", "low-confidence"))
        checks["sensitive_valid_request_allowed"] = statuses["sensitive"] == "ok"
    statuses["internal"] = (await call(tenant + ".security.inspect", {
        "messages": [{"role": "user", "content": "forged internal call"}]}))["status"]
    statuses["cross_tenant"] = (await call(other + ".business", {
        "messages": [{"role": "user", "content": "forged cross-tenant call"}]}))["status"]
    checks["benign_allowed"] = statuses["benign"] == "ok"
    checks["internal_inspector_not_agent_callable"] = statuses["internal"] == "denied"
    checks["cross_tenant_route_denied"] = statuses["cross_tenant"] == "denied"
    checks["egress_socket_absent"] = not Path("/run/guard-egress").exists()
    checks["guard_state_absent"] = not Path("/state").exists() and not Path("/state-keys").exists()
    checks["direct_network_denied"] = True
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=2).close()
        checks["direct_network_denied"] = False
    except OSError:
        pass
    print(json.dumps({"tenant": tenant, "uid": os.getuid(), "checks": checks, "statuses": statuses}))


if __name__ == "__main__":
    asyncio.run(main())

