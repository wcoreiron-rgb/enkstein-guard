"""Release provenance and reproducibility evidence for a candidate.

Writes an unsigned in-toto-style statement binding the source tree, wheel,
dependency locks, container image and acceptance evidence by SHA-256, plus an
artifact manifest in the payload format verified by
``enkstein_guard.release.verify_artifacts``. It also rebuilds the wheel from
the source tree and compares archive members. Signing is a separate publisher
step (docs/release/publisher-signing-requirements.md); this tool never signs.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_tree():
    files = sorted(p for p in (ROOT / "src/enkstein_guard").rglob("*")
                   if p.is_file() and "__pycache__" not in p.parts)
    tree = hashlib.sha256()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        tree.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    for extra in ("pyproject.toml", "README.md", "LICENSE"):
        tree.update(extra.encode() + b"\0" + hashlib.sha256((ROOT / extra).read_bytes()).digest())
    return tree.hexdigest(), len(files)


def rebuild_matches(wheel):
    with tempfile.TemporaryDirectory(prefix="eg-rebuild-") as temporary:
        work = Path(temporary)
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copy(ROOT / name, work / name)
        shutil.copytree(ROOT / "src", work / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
        subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(work / "out"),
                        str(work)], check=True, capture_output=True)
        rebuilt = next((work / "out").glob("*.whl"))
        original, again = zipfile.ZipFile(wheel), zipfile.ZipFile(rebuilt)
        names = sorted(original.namelist())
        differing = [n for n in names if n in again.namelist() and original.read(n) != again.read(n)]
        return {"same_member_names": names == sorted(again.namelist()),
                "differing_members": differing,
                "package_members_identical": not [n for n in differing if not n.endswith(("RECORD", "WHEEL"))],
                "rebuilt_wheel_sha256": digest(rebuilt)}


def main():
    parser = argparse.ArgumentParser()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import evidence
    parser.add_argument("--wheel", default=str(evidence.WHEEL.relative_to(ROOT)))
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--output-dir", default="dist/release-%s" % evidence.VERSION)
    parser.add_argument("--evidence-dir", default=str(evidence.EVIDENCE_DIR.relative_to(ROOT)))
    args = parser.parse_args()
    wheel = ROOT / args.wheel
    output = ROOT / args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    tree, count = source_tree()
    # Reports, logs and the preserved acceptance configurations.
    evidence_files = sorted(p for p in (ROOT / args.evidence_dir).rglob("*") if p.is_file())
    locks = [ROOT / "dist/vendor-linux-musl-arm64/requirements.txt", ROOT / "deployment/requirements-linux-arm64.txt"]
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": wheel.name, "digest": {"sha256": digest(wheel)}},
                    {"name": args.image_tag, "digest": {"sha256": args.image_id.split(":", 1)[-1]}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "enkstein-guard/local-candidate-build/v1",
                "externalParameters": {"source_tree_sha256": tree, "source_files": count,
                                       "dockerfile_sha256": digest(ROOT / "deployment/Dockerfile.alpine"),
                                       "base_image": (ROOT / "deployment/Dockerfile.alpine").read_text().splitlines()[0].split()[1]},
                "resolvedDependencies": [{"uri": str(path.relative_to(ROOT)), "digest": {"sha256": digest(path)}} for path in locks]},
            "runDetails": {"builder": {"id": "local-operator-workstation (unattested)"},
                           "metadata": {"invocationId": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                                        "python": platform.python_version(), "platform": platform.platform()},
                           "byproducts": [{"name": str(p.relative_to(ROOT)), "digest": {"sha256": digest(p)}}
                                          for p in evidence_files]}},
        "signature_status": "unsigned: requires the publisher signing step; a local key is not publisher identity"}
    reproducibility = rebuild_matches(wheel)
    (output / "provenance.intoto.json").write_text(json.dumps(statement, indent=2) + "\n")
    (output / "reproducibility.json").write_text(json.dumps(reproducibility, indent=2) + "\n")
    # Copy release inputs into the bundle so a publisher signature over the
    # manifest can be verified against one directory (release.verify_artifacts).
    bundled = [(wheel, wheel.name), (locks[0], "requirements-linux-musl-arm64.txt"),
               (locks[1], "requirements-linux-arm64.txt")]
    for source, name in bundled:
        shutil.copyfile(source, output / name)
    artifacts = [output / name for _, name in bundled] + [output / "provenance.intoto.json",
                                                          output / "reproducibility.json"]
    payload = {"schema_version": 1, "artifacts": sorted(({"name": p.name, "bytes": p.stat().st_size, "sha256": digest(p)}
                                                         for p in artifacts), key=lambda r: r["name"])}
    (output / "manifest-unsigned.json").write_text(json.dumps({"payload": payload, "signature": None}, indent=2) + "\n")
    print(json.dumps({"wheel_sha256": digest(wheel), "source_tree_sha256": tree, **reproducibility}))
    return 0 if reproducibility["package_members_identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
