"""Scan an exact local image archive without giving the scanner Docker access.

Requires Docker and a populated scanner DB cache; --refresh-db downloads only
public vulnerability data. No application image is uploaded to a scanner service.
Exit 2 means high/critical findings remain; exit 1 means the scan did not finish.
"""
import argparse
import collections
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

SCANNER="aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"
CACHE="enkstein-trivy-cache:/root/.cache/trivy"

def run(*args):
    result = subprocess.run(args,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result

parser=argparse.ArgumentParser()
parser.add_argument("--image",default="enkstein-guard:security-review")
parser.add_argument("--output",default="verification/os-image-scan.json")
parser.add_argument("--refresh-db",action="store_true")
args=parser.parse_args()
output=Path(args.output).absolute()
output.parent.mkdir(parents=True,exist_ok=True)
identity=run("docker","image","inspect",args.image,"--format","{{.Id}}").stdout.strip()
if args.refresh_db:
    run("docker","run","--rm","--cap-drop","ALL","--security-opt","no-new-privileges","-v",CACHE,
        SCANNER,"image","--download-db-only","--no-progress")
with tempfile.TemporaryDirectory(prefix="guard-image-scan-",dir=str(output.parent)) as temporary:
    archive=Path(temporary)/"image.tar"
    run("docker","save","--output",str(archive),identity)
    archive.chmod(0o644)
    archive_hash=hashlib.sha256(archive.read_bytes()).hexdigest()
    output.write_text("")
    output.chmod(0o666)
    command=["docker","run","--rm","--network","none","--read-only","--cap-drop","ALL",
        "--security-opt","no-new-privileges","--memory","2g","--pids-limit","128",
        "--tmpfs","/tmp:rw,nosuid,noexec,size=256m","-v",str(archive)+":/image.tar:ro",
        "-v",str(output)+":/result.json","-v",CACHE,SCANNER,"image","--input","/image.tar",
        "--skip-db-update","--offline-scan","--skip-version-check","--scanners","vuln",
        "--format","json","--output","/result.json","--no-progress"]
    try:
        scanned=run(*command)
    finally:
        output.chmod(0o644)
    output.with_suffix(".log").write_text(scanned.stderr)
report=json.loads(output.read_text())
counts=collections.Counter(v["Severity"] for group in report.get("Results",[]) for v in group.get("Vulnerabilities",[]))
provenance={"image_id":identity,"scanner_image":SCANNER,"archive_sha256":archive_hash,
            "report_sha256":hashlib.sha256(output.read_bytes()).hexdigest(),
            "scanned_at":datetime.now(timezone.utc).isoformat(),"network_during_scan":"none",
            "ignored_unfixed":False,"severity_counts":dict(counts),
            "gate":"blocked_high_findings" if counts["HIGH"]+counts["CRITICAL"] else "no_high_critical_findings",
            "trivy_reported_image_id":report.get("Metadata",{}).get("ImageID"),
            "evidence":evidence.header("image-scan",image_info=evidence.image(identity))}
output.with_suffix(".provenance.json").write_text(json.dumps(provenance,indent=2)+"\n")
print(json.dumps(provenance,indent=2))
raise SystemExit(2 if counts["HIGH"]+counts["CRITICAL"] else 0)
