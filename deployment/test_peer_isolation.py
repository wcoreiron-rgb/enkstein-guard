"""Execute two-UID flood/fairness and stolen-credential acceptance checks."""
import json,os,secrets,subprocess,time,selectors
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0,str(ROOT/"tools"))
import evidence  # noqa: E402
local=ROOT/".local-deploy";local.mkdir(exist_ok=True,mode=0o700)
run=local/secrets.token_hex(8);run.mkdir(mode=0o700)
secret_dir=run/"secrets";secret_dir.mkdir(mode=0o755)
a,b=secrets.token_urlsafe(48),secrets.token_urlsafe(48)
identities={a:{"tenant_id":"a","principal_id":"fixture-user","agent_id":"fixture-agent","allowed_routes":["read-a"]},
            b:{"tenant_id":"b","principal_id":"fixture-user-b","agent_id":"fixture-agent-b","allowed_routes":["read-b"]}}
registry=secret_dir/"registry.json";registry.write_text(json.dumps(identities));registry.chmod(0o444)
peers=secret_dir/"peers.json";peers.write_text(json.dumps({"11001":["a","fixture-user","fixture-agent"],"11002":["b","fixture-user-b","fixture-agent-b"]}));peers.chmod(0o444)
tokens=[]
for name,value in (("a",a),("b",b)):
    path=run/name;path.write_text(value);path.chmod(0o444);tokens.append(path)
image=os.environ.get("GUARD_TEST_IMAGE","enkstein-guard:readiness")
env={**os.environ,"GUARD_IMAGE":image,"GUARD_AGENT_IMAGE":image,"GUARD_SECRETS_DIR":str(secret_dir),
     "GUARD_BOOTSTRAP_DIR":str(ROOT/"deployment/acceptance"),"GUARD_AGENT_TOKEN_FILE":str(tokens[0])}
project="egpeer"+secrets.token_hex(6)
base=["docker","compose","-p",project,"-f",str(ROOT/"deployment/compose.yaml")]
def command(*args,token=None,check=True):
    setting={**env,"GUARD_AGENT_TOKEN_FILE":str(token or tokens[0])}
    result=subprocess.run([*base,*args],env=setting,capture_output=True,text=True)
    if check and result.returncode:raise RuntimeError(result.stderr.replace(a,"[redacted]").replace(b,"[redacted]"))
    return result
attacker=None
try:
    command("up","-d","guard")
    guard=command("ps","-q","guard").stdout.strip()
    for _ in range(60):
        probe=subprocess.run(["docker","exec",guard,"python","-c","import socket;s=socket.socket(socket.AF_UNIX);s.connect('/run/guard/guard.sock');s.close()"],capture_output=True)
        if probe.returncode==0:break
        time.sleep(.5)
    else:raise RuntimeError("guard_not_ready")
    attack_args=[*base,"run","--rm","--no-deps","-T","-v",str(ROOT/"deployment/acceptance/peer_attack.py")+":/attack.py:ro",
                 "-v",str(tokens[1])+":/run/stolen-token:ro","--entrypoint","python","agent","/attack.py"]
    attacker=subprocess.Popen(attack_args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    with selectors.DefaultSelector() as ready:
        ready.register(attacker.stdout,selectors.EVENT_READ)
        if not ready.select(timeout=30):
            raise RuntimeError("attacker_readiness_timeout")
        first=json.loads(attacker.stdout.readline())
    assert first["ready"] and first["stolen_credential_denied"],first
    legitimate=command("run","--rm","--no-deps","-T","--user","11002:10001","-v",
                       str(ROOT/"deployment/acceptance/peer_business.py")+":/business.py:ro","--entrypoint","python","agent","/business.py",token=tokens[1])
    business=json.loads(legitimate.stdout.strip().splitlines()[-1])
    remaining,error=attacker.communicate(timeout=15)
    if attacker.returncode:raise RuntimeError(error.replace(a,"[redacted]").replace(b,"[redacted]"))
    final=json.loads(remaining.strip().splitlines()[-1])
    report={"attacker_os_uid":11001,"legitimate_os_uid":11002,"attacker_quota_exhausted":first["ready"],
            **business,**final,"passed":business["other_tenant_work_continued"] and final["stolen_credential_denied"] and final["attack_cycles"]==3}
    report["image"]=image
    report["image_id"]=subprocess.run(["docker","image","inspect","-f","{{.Id}}",image],capture_output=True,text=True).stdout.strip()
    report["evidence"]=evidence.header("peer-isolation",image_info=evidence.image(image))
    (Path(os.environ.get("GUARD_EVIDENCE_DIR",evidence.EVIDENCE_DIR))/"peer-isolation.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
finally:
    if attacker is not None and attacker.poll() is None:
        attacker.terminate()
        try:attacker.communicate(timeout=10)
        except subprocess.TimeoutExpired:attacker.kill();attacker.communicate()
    command("down","--volumes","--remove-orphans",check=False)
    for path in [registry,peers,*tokens]:path.unlink(missing_ok=True)
    secret_dir.rmdir();run.rmdir()
