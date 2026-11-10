"""Run synthetic Linux boundary acceptance; never contact business APIs.

Run from project root after building enkstein-guard:local. Cleans only its own
Compose project and volumes. Output excludes credentials and payloads.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT / "tools"))
import evidence  # noqa: E402
LOCAL = ROOT / ".local-deploy"
LOCAL.mkdir(exist_ok=True, mode=0o700)
RUN = LOCAL / secrets.token_hex(8)
RUN.mkdir(mode=0o700)
secret_dir = RUN / "secrets"
secret_dir.mkdir(mode=0o755)
token = secrets.token_urlsafe(48)
# Outer RUN remains operator-only. Mounted files must be readable by the
# container's nonroot UID; only selected files enter each container.
registry = secret_dir / "registry.json"
registry.write_text(json.dumps({token: {"tenant_id":"a", "principal_id":"fixture-user", "agent_id":"fixture-agent", "allowed_routes":["read-a","read-b"]}}))
registry.chmod(0o444)
peers=secret_dir/"peers.json"
peers.write_text(json.dumps({"11001":["a","fixture-user","fixture-agent"]}))
peers.chmod(0o444)
agent_token = RUN / "agent-token"
agent_token.write_text(token)
agent_token.chmod(0o444)
test_image=os.environ.get("GUARD_TEST_IMAGE","enkstein-guard:local")
env = {**os.environ, "GUARD_IMAGE":test_image, "GUARD_BOOTSTRAP_DIR": str(ROOT/"deployment/acceptance"),
       "GUARD_SECRETS_DIR": str(secret_dir), "GUARD_AGENT_IMAGE":test_image,
       "GUARD_AGENT_TOKEN_FILE":str(agent_token)}
project = "egtest" + secrets.token_hex(6)
base = ["docker","compose","-p",project,"-f",str(ROOT/"deployment/compose.yaml")]

def compose(*args, check=True):
    result = subprocess.run([*base,*args],env=env,capture_output=True,text=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr.replace(token, "[redacted]"))
    return result

report = {}
try:
    compose("up","-d","guard")
    guard = compose("ps","-q","guard").stdout.strip()
    for attempt in range(60):
        probe = subprocess.run(["docker","exec",guard,"python","-c",
            "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/guard/guard.sock'); s.close()"],capture_output=True)
        if probe.returncode == 0:
            break
        time.sleep(.5)
    else:
        raise RuntimeError("guard_start_failed")
    def worker(restarted=False):
        result = compose("run","--rm","--no-deps","-e","EG_TEST_RESTART="+("1" if restarted else "0"),"-v",str(ROOT/"deployment/acceptance/worker.py")+":/worker.py:ro",
                         "--entrypoint","python","agent","/worker.py")
        return json.loads(result.stdout.strip().splitlines()[-1])
    report["initial"] = worker()
    # Force an ungraceful stop, then verify stale-socket and persisted-state
    # recovery with the same volume and keys. No business writes are performed.
    compose("kill","-s","SIGKILL","guard")
    compose("up","-d","guard")
    for attempt in range(60):
        probe = subprocess.run(["docker","exec",guard,"python","-c",
            "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/guard/guard.sock'); s.close()"],capture_output=True)
        if probe.returncode == 0:
            break
        time.sleep(.5)
    else:
        raise RuntimeError("guard_restart_failed")
    report["after_forced_restart"] = worker(restarted=True)
    checkpoint = subprocess.run(["docker","exec",guard,"python","-c",
        "import json; from enkstein_guard.audit import DurableAudit; print(json.dumps(DurableAudit('/state/audit.sqlite3','/state/audit-key').verify()))"],capture_output=True,text=True,check=True)
    report["durable_audit_checkpoint"] = json.loads(checkpoint.stdout)
    report["passed"] = all(report["initial"].values()) and all(report["after_forced_restart"].values())
    report["image"]=test_image
    report["image_id"]=subprocess.run(["docker","image","inspect","-f","{{.Id}}",test_image],capture_output=True,text=True).stdout.strip()
    report["evidence"]=evidence.header("container-isolation",image_info=evidence.image(test_image))
    (Path(os.environ.get("GUARD_EVIDENCE_DIR",evidence.EVIDENCE_DIR))/"container-isolation.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
finally:
    compose("down","--volumes","--remove-orphans",check=False)
    peers.unlink(missing_ok=True)
    registry.unlink(missing_ok=True)
    agent_token.unlink(missing_ok=True)
    secret_dir.rmdir()
    RUN.rmdir()
