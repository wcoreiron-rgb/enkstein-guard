"""Disposable legacy-to-candidate vault recovery drill; no production data."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument("--old-python",required=True)
parser.add_argument("--new-python",required=True)
parser.add_argument("--output",required=True)
args=parser.parse_args()
old=str(Path(args.old_python).absolute())
new=str(Path(args.new_python).absolute())

def version(python):
    return subprocess.run([python,"-c","from importlib.metadata import version; print(version('enkstein-guard'))"],capture_output=True,text=True,check=True).stdout.strip()

with tempfile.TemporaryDirectory(prefix="eg-upgrade-") as temporary:
    creator="""import json,sys
from pathlib import Path
from enkstein_guard.vault import LocalVault,Scope
p=Path(sys.argv[1]);v=LocalVault.initialize(p/'data/v.sqlite3',p/'keys/key')
s=Scope('tenant','principal','workflow','operation')
print(json.dumps({'reference':v.put('synthetic-upgrade-secret',s,('sink',),ttl=300)}))
"""
    created=subprocess.run([old,"-c",creator,temporary],capture_output=True,text=True,check=True)
    reference=json.loads(created.stdout)["reference"]
    verifier="""import sys
from pathlib import Path
from enkstein_guard.vault import LocalVault,Scope
p=Path(sys.argv[1]);v=LocalVault(p/'data/v.sqlite3',p/'keys/key')
s=Scope('tenant','principal','workflow','operation')
assert v.restore(sys.argv[2],s,'sink',consume=False)=='synthetic-upgrade-secret'
v.rotate()
v=LocalVault(p/'data/v.sqlite3',p/'keys/key')
assert v.restore(sys.argv[2],s,'sink')=='synthetic-upgrade-secret'
"""
    subprocess.run([new,"-c",verifier,temporary,reference],capture_output=True,text=True,check=True)
    Path(args.output).write_text(json.dumps({"old_version":version(old),"new_version":version(new),
        "legacy_ciphertext_restored":True,"rotation_then_restart_restored":True,
        "synthetic_data_only":True},indent=2)+"\n")
    print("Legacy vault upgrade and rotation/restart drill passed")
