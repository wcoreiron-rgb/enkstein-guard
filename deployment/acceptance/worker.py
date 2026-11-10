"""Checks run inside an untrusted, network-disabled Linux container."""
import asyncio
import json
import os
from pathlib import Path
import socket
import uuid
from enkstein_guard.service import guarded_request


async def main():
    checks = {}
    token = Path("/run/agent-token").read_text().strip()
    request_id = str(uuid.uuid4())
    result = await guarded_request("/run/guard/guard.sock", token, "read-a", {"email":"synthetic@example.com"}, request_id=request_id)
    repeated = await guarded_request("/run/guard/guard.sock", token, "read-a", {"email":"synthetic@example.com"}, request_id=request_id)
    checks["duplicate_execution_suppressed"] = repeated["status"] == "completed_no_replay"
    persistent = await guarded_request("/run/guard/guard.sock", token, "read-a", {"kind":"restart-fixture"},
                                       request_id="persistent-restart-request-a-123")
    expected = "completed_no_replay" if os.environ.get("EG_TEST_RESTART") == "1" else "ok"
    checks["durable_duplicate_state_correct"] = persistent["status"] == expected
    checks["authorized_work_continues"] = result["status"] == "ok"
    checks["pii_tokenized"] = "synthetic@example.com" not in json.dumps(result) and "[[EGV:" in json.dumps(result)
    checks["cross_tenant_denied"] = (await guarded_request("/run/guard/guard.sock", token, "read-b", {}))["status"] == "denied"
    checks["forged_identity_denied"] = (await guarded_request("/run/guard/guard.sock", "invalid", "read-a", {}))["status"] == "denied"
    checks["unknown_tool_denied"] = (await guarded_request("/run/guard/guard.sock", token, "delete-all", {}))["status"] == "denied"
    checks["guard_keys_not_mounted"] = not Path("/state/vault-key").exists() and not Path("/run/guard-secrets/registry.json").exists()
    try:
        with socket.create_connection(("1.1.1.1",443), timeout=1):
            checks["direct_network_denied"] = False
    except OSError:
        checks["direct_network_denied"] = True
    try:
        Path("/run/guard/guard.sock").unlink()
        checks["socket_replacement_denied"] = False
    except OSError:
        checks["socket_replacement_denied"] = True
    try:
        Path("/unauthorized-write").write_text("test")
        checks["root_filesystem_readonly"] = False
    except OSError:
        checks["root_filesystem_readonly"] = True
    checks["nonroot"] = os.getuid() != 0
    status = dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    checks["no_effective_capabilities"] = int(status["CapEff"].strip(),16) == 0
    checks["privilege_escalation_disabled"] = status["NoNewPrivs"].strip() == "1"
    checks["memory_limit_active"] = Path("/sys/fs/cgroup/memory.max").read_text().strip() == str(256*1024*1024)
    checks["pid_limit_active"] = Path("/sys/fs/cgroup/pids.max").read_text().strip() == "64"
    print(json.dumps(checks,sort_keys=True))
    if not all(checks.values()):
        raise SystemExit(1)

asyncio.run(main())
