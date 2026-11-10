"""Prepare the hash-locked Python 3.12 musllinux ARM64 wheelhouse.

Downloads public wheels only; it does not publish or deploy anything. The guard
wheel must already exist so the candidate always installs a reviewed artifact.
"""
import argparse
import email
import hashlib
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import evidence  # noqa: E402
from release_wheels import AGT_NAME, optional_agt_wheel, preserve_wheelhouse  # noqa: E402
DEFAULT_GUARD_WHEEL = evidence.WHEEL
PINS = (
    "cffi==2.1.1",
    "cryptography==50.0.2",
    "pip==26.2.1",
    "pycparser==3.11",
)


def metadata(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        message = email.message_from_bytes(archive.read(metadata_name))
    return message["Name"], message["Version"]


parser = argparse.ArgumentParser()
parser.add_argument(
    "--agt-wheel", type=Path,
    help="include only the exact reviewed local AGT 5.0.0 wheel (no index resolution)",
)
parser.add_argument(
    "--guard-wheel",
    type=Path,
    default=DEFAULT_GUARD_WHEEL,
    help="reviewed guard wheel to include in the generated hash lock",
)
parser.add_argument(
    "--build",
    action="store_true",
    help="build only the isolated enkstein-guard:alpine-candidate tag",
)
args = parser.parse_args()
agt_wheel = optional_agt_wheel(args.agt_wheel, ROOT)
guard_wheel = args.guard_wheel.resolve()
if not guard_wheel.is_file():
    raise SystemExit(f"guard wheel does not exist: {guard_wheel}")
try:
    guard_wheel_relative = guard_wheel.relative_to(ROOT)
except ValueError as error:
    raise SystemExit("guard wheel must be inside the project root") from error

vendor = ROOT / "dist/vendor-linux-musl-arm64"
if agt_wheel is not None and agt_wheel.is_relative_to(vendor):
    raise ValueError("agt_wheel_must_be_outside_active_vendor")
vendor.mkdir(parents=True, exist_ok=True)
preserve_wheelhouse(ROOT, vendor)
for stale in (*vendor.glob("*.whl"), vendor / "requirements.txt"):
    stale.unlink(missing_ok=True)

subprocess.run(
    [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--only-binary=:all:",
        "--platform",
        "musllinux_1_2_aarch64",
        "--python-version",
        "3.12",
        "--implementation",
        "cp",
        "--abi",
        "cp312",
        "--abi",
        "abi3",
        "--dest",
        str(vendor),
        *PINS,
    ],
    check=True,
)

if agt_wheel is not None:
    shutil.copy2(agt_wheel, vendor / agt_wheel.name)
    optional_agt_wheel(vendor / agt_wheel.name, ROOT)
wheels = [*sorted(vendor.glob("*.whl")), guard_wheel]
records = []
for wheel in wheels:
    name, version = metadata(wheel)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    records.append((name, version, digest))

normalized_names = [name.lower().replace("_", "-") for name, _, _ in records]
if len(set(normalized_names)) != len(records):
    raise ValueError("stale_or_duplicate_vendor_wheels")
expected = {pin.split("==", 1)[0] for pin in PINS} | {"enkstein-guard"}
if agt_wheel is not None:
    expected.add(AGT_NAME)
if set(normalized_names) != expected:
    raise ValueError(f"unexpected_wheel_set: {sorted(normalized_names)}")

(vendor / "requirements.txt").write_text(
    "".join(
        f"{name}=={version} --hash=sha256:{digest}\n"
        for name, version, digest in sorted(records, key=lambda row: row[0].lower())
    )
)
print(f"Prepared {len(records)} SHA-locked wheels for Python 3.12 musllinux ARM64")
print(f"Guard wheel: {guard_wheel.name}")

if args.build:
    dockerfile = ROOT / "deployment/Dockerfile.alpine"
    context_files = [dockerfile, guard_wheel, vendor / "requirements.txt", *vendor.glob("*.whl")]
    with tempfile.TemporaryDirectory(prefix="guard-alpine-build-") as context:
        for path in context_files:
            target = Path(context) / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        subprocess.run(["docker", "build", "-f", str(Path(context)/"deployment/Dockerfile.alpine"),
                        "--build-arg", f"GUARD_WHEEL={guard_wheel_relative}",
                        "-t", "enkstein-guard:alpine-candidate", context], check=True)
    print("Built enkstein-guard:alpine-candidate from the minimal candidate context")
