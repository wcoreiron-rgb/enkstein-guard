"""Build and hash-lock the supported Linux ARM64 (glibc) deployment wheelhouse.

Run inside the project development environment. Downloads public dependencies;
does not publish or deploy anything. Keep runtime pins aligned with audited data.
Pass --guard-wheel to lock an already reviewed wheel instead of rebuilding it,
so the glibc and musl locks reference the same artifact.
"""
import argparse
import email
import hashlib
from pathlib import Path
import subprocess
import shutil
import sys
import tomllib
import zipfile

root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/"tools"))
from release_wheels import AGT_NAME, optional_agt_wheel, preserve_wheelhouse
parser=argparse.ArgumentParser()
parser.add_argument("--guard-wheel",type=Path)
parser.add_argument("--agt-wheel",type=Path,help="exact reviewed local AGT 5.0.0 wheel only")
args=parser.parse_args()
agt_wheel=optional_agt_wheel(args.agt_wheel,root)
project=tomllib.loads((root/"pyproject.toml").read_text())["project"]
output=root/"dist/deployment"
output.mkdir(parents=True,exist_ok=True)
if args.guard_wheel:
    wheel=args.guard_wheel.resolve()
    if not wheel.is_file():
        raise SystemExit("guard wheel does not exist")
else:
    subprocess.run([sys.executable,"-m","pip","wheel","--no-deps","--wheel-dir",str(output),str(root)],check=True)
    wheel=output/("enkstein_guard-"+project["version"]+"-py3-none-any.whl")
vendor=root/"dist/vendor-linux-arm64"
if agt_wheel is not None and agt_wheel.is_relative_to(vendor):
    raise ValueError("agt_wheel_must_be_outside_active_vendor")
vendor.mkdir(parents=True,exist_ok=True)
preserve_wheelhouse(root,vendor,root/"deployment/requirements-linux-arm64.txt")
for stale in vendor.glob("*.whl"):
    stale.unlink()
pins=["cffi==2.1.1","cryptography==50.0.2","pip==26.2.1","pycparser==3.11"]
subprocess.run([sys.executable,"-m","pip","download","--only-binary=:all:","--platform","manylinux_2_34_aarch64",
               "--platform","manylinux2014_aarch64","--python-version","3.12","--implementation","cp",
               "--abi","cp312","--abi","abi3","--dest",str(vendor),*pins],check=True)
if agt_wheel is not None:
    shutil.copy2(agt_wheel,vendor/agt_wheel.name)
    optional_agt_wheel(vendor/agt_wheel.name,root)
records=[]
for path in [*vendor.glob("*.whl"),wheel]:
    with zipfile.ZipFile(path) as archive:
        name=next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        metadata=email.message_from_bytes(archive.read(name))
    records.append((metadata["Name"],metadata["Version"],hashlib.sha256(path.read_bytes()).hexdigest()))
normalized=[name.lower().replace("_","-") for name,_,_ in records]
if len(set(normalized))!=len(records):
    raise ValueError("stale_or_duplicate_vendor_wheels; use a clean vendor directory")
expected={pin.split("==",1)[0] for pin in pins}|{"enkstein-guard"}
if agt_wheel is not None:
    expected.add(AGT_NAME)
if set(normalized)!=expected:
    raise ValueError("unexpected_wheel_set")
(root/"deployment/requirements-linux-arm64.txt").write_text("".join(
    f"{name}=={version} --hash=sha256:{digest}\n" for name,version,digest in sorted(records)))
print("Wheel and hash-locked Linux ARM64 dependencies prepared; image build and acceptance still required")
