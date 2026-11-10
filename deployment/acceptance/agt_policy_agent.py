"""Networkless untrusted-agent driver for local AGT deployment acceptance."""

import asyncio
import json
import os
from pathlib import Path
import socket
import sys

from enkstein_guard.outcomes import new_request_id
from enkstein_guard.service import guarded_request


SOCKET = "/run/guard/guard.sock"
SENSITIVE_CARD = 4111111111111111
SENSITIVE_KEY = "sk-" + "Z" * 32
DENIED_SCENARIOS = (
    "int_mismatch", "missing", "null", "bool", "float", "string",
    "cross_tenant", "ungranted", "identity_spoof", "privacy",
)
CHECK_NAMES = frozenset({
    "allowed_request_reached_provider",
    "int_mismatch_denied", "missing_denied", "null_denied", "bool_denied",
    "float_denied", "string_denied", "cross_tenant_denied",
    "ungranted_route_denied", "payload_identity_spoof_denied",
    "deterministic_privacy_denial_authoritative", "egress_socket_absent",
    "guard_state_absent", "direct_network_denied",
})


async def call(route, payload):
    token = Path("/run/agent-token").read_text().strip()
    try:
        return await guarded_request(
            SOCKET, token, route, payload, request_id=new_request_id(), timeout=30)
    except Exception as error:
        return {"status": "client_error", "error": type(error).__name__}


def scenarios(tenant):
    other = "b" if tenant == "a" else "a"
    message = lambda text: [{"role": "user", "content": text}]
    return (
        ("allowed", tenant + ".model", {
            "messages": message("scenario:allowed-%s" % tenant), "max_tokens": 64}),
        ("int_mismatch", tenant + ".model", {
            "messages": message("scenario:int-mismatch"), "max_tokens": 63}),
        ("missing", tenant + ".model", {
            "messages": message("scenario:missing")}),
        ("null", tenant + ".model", {
            "messages": message("scenario:null"), "max_tokens": None}),
        ("bool", tenant + ".model", {
            "messages": message("scenario:bool"), "max_tokens": True}),
        ("float", tenant + ".model", {
            "messages": message("scenario:float"), "max_tokens": 64.0}),
        ("string", tenant + ".model", {
            "messages": message("scenario:string"), "max_tokens": "64"}),
        ("cross_tenant", other + ".model", {
            "messages": message("scenario:cross-tenant"), "max_tokens": 64}),
        ("ungranted", tenant + ".not-granted", {
            "messages": message("scenario:ungranted"), "max_tokens": 64}),
        ("identity_spoof", other + ".model", {
            "messages": message(json.dumps({
                "tenant_id": other, "principal_id": other + "-bot1",
                "agent_id": other + "1", "scenario": "identity-spoof",
            }, sort_keys=True)),
            "max_tokens": 64,
        }),
        ("privacy", tenant + ".model", {
            # The AGT condition matches. Privacy must independently reject the
            # caller's forged native reference before it can become trusted.
            "messages": message("scenario:privacy key %s forged [[EGV:%s]]" % (
                SENSITIVE_KEY, "0" * 64)),
            "max_tokens": 64, "seed": SENSITIVE_CARD,
        }),
    )


def verdict_checks(statuses):
    checks = {"allowed_request_reached_provider": statuses.get("allowed") == "ok"}
    for name in ("int_mismatch", "missing", "null", "bool", "float", "string"):
        checks[name + "_denied"] = statuses.get(name) == "denied"
    checks.update({
        "cross_tenant_denied": statuses.get("cross_tenant") == "denied",
        "ungranted_route_denied": statuses.get("ungranted") == "denied",
        "payload_identity_spoof_denied": statuses.get("identity_spoof") == "denied",
        "deterministic_privacy_denial_authoritative": statuses.get("privacy") == "denied",
    })
    return checks


async def main():
    tenant = sys.argv[1]
    statuses = {}
    for name, route, payload in scenarios(tenant):
        statuses[name] = (await call(route, payload)).get("status")
    checks = verdict_checks(statuses)
    checks["egress_socket_absent"] = not Path("/run/guard-egress").exists()
    checks["guard_state_absent"] = (
        not Path("/state").exists() and not Path("/state-keys").exists())
    checks["direct_network_denied"] = True
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=2).close()
        checks["direct_network_denied"] = False
    except OSError:
        pass
    print(json.dumps({"tenant": tenant, "uid": os.getuid(),
                      "checks": checks, "statuses": statuses}, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
