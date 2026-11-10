"""Bind the candidate's container acceptance evidence to one image ID.

Reads every container report in the candidate's evidence directory, requires
each to name the expected image ID (directly or in its evidence header), to
show that the package installed in the image equals the release wheel, and to
have passed; checks that the build lock pins the release wheel; optionally
copies the build/acceptance log; and writes container-acceptance-run.json with
the SHA-256 of each file. Exit 1 on any missing, unbound or failed report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

ROOT = evidence.ROOT
MUSL_LOCK = ROOT / "dist/vendor-linux-musl-arm64/requirements.txt"
DOCKERFILE = ROOT / "deployment/Dockerfile.alpine"
TARGETS = {"operational-acceptance-container.json": "docs/operations/capacity-targets.json",
           "production-capacity.json": "docs/operations/capacity-targets-production.json",
           "production-soak.json": "docs/operations/soak-targets.json"}
REPORTS = ("container-production-profile.json", "container-isolation.json", "peer-isolation.json",
           "alpine-os-scan.provenance.json", "operational-acceptance-container.json", "production-capacity.json",
           "production-soak.json", "production-disk-full.json")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def defined_ids(path):
    return {item["id"] for item in json.loads((ROOT / path).read_text())["targets"]}


def passed(name, record):
    if name == "alpine-os-scan.provenance.json":
        return record.get("gate") == "no_high_critical_findings"
    if record.get("verdicts") is not None:
        # Verdicts must cover every target the report's definition file names.
        defined = TARGETS.get(name)
        if defined is not None and set(record["verdicts"]) != defined_ids(defined):
            return False
        return record.get("passed") is True and all(v["passed"] for v in record["verdicts"].values())
    return record.get("passed") is True and "error" not in record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--image-tag", default=evidence.IMAGE_TAG)
    parser.add_argument("--host", required=True)
    parser.add_argument("--build-log", help="log of tools/run_container_acceptance.sh to copy into the evidence")
    parser.add_argument("--note", action="append", default=[])
    args = parser.parse_args()
    directory = evidence.EVIDENCE_DIR
    problems, entries = [], {}
    wheel_sha = digest(evidence.WHEEL)
    if not re.search(r"^enkstein-guard==\S+ --hash=sha256:%s$" % wheel_sha, MUSL_LOCK.read_text(), re.M):
        problems.append("musl lock does not pin the release wheel")
    log = None
    if args.build_log:
        log = Path(args.build_log).read_text()
        if args.image_id not in log or "container_acceptance_status=0" not in log:
            problems.append("build log does not show this image ID and a passing acceptance run")
        shutil.copyfile(args.build_log, directory / "container-acceptance-run.log")
    for name in REPORTS:
        path = directory / name
        if not path.exists():
            problems.append("missing " + name)
            continue
        record = json.loads(path.read_text())
        header = record.get("evidence") or {}
        recorded = record.get("image_id") or (header.get("image") or {}).get("id")
        matches_wheel = (header.get("candidate") or {}).get("installed_matches_wheel")
        binding = "matches" if recorded == args.image_id else "not_recorded" if recorded is None else "mismatch"
        if binding != "matches":
            problems.append("%s image binding %s (%s)" % (name, binding, recorded))
        if matches_wheel is not True:
            problems.append("%s: installed package not shown equal to the release wheel" % name)
        if not passed(name, record):
            problems.append(name + " did not pass")
        entries[name] = {"sha256": digest(path), "image_id": recorded, "binding": binding,
                         "installed_matches_wheel": matches_wheel, "passed": passed(name, record)}
    scan = directory / "alpine-os-scan.json"
    if scan.exists():
        provenance = json.loads((directory / "alpine-os-scan.provenance.json").read_text())
        if provenance.get("report_sha256") != digest(scan):
            problems.append("alpine-os-scan.json does not match its provenance record")
        entries["alpine-os-scan.json"] = {"sha256": digest(scan), "image_id": provenance.get("image_id"),
                                          "binding": "via alpine-os-scan.provenance.json",
                                          "passed": entries.get("alpine-os-scan.provenance.json", {}).get("passed")}
    if log is not None:
        entries["container-acceptance-run.log"] = {"sha256": digest(directory / "container-acceptance-run.log"),
                                                   "image_id": args.image_id, "binding": "build output",
                                                   "passed": "container_acceptance_status=0" in log}
    record = {
        "evidence": evidence.header("container-acceptance-run"),
        "image_tag": args.image_tag, "image_id": args.image_id,
        "built_from": {"wheel": str(evidence.WHEEL.relative_to(ROOT)), "wheel_sha256": wheel_sha,
                       "musl_lock_sha256": digest(MUSL_LOCK), "dockerfile_sha256": digest(DOCKERFILE),
                       "binding": "tools/build_candidate_image.sh refuses a wheel not pinned in the musl lock; the "
                                  "image installs with pip --require-hashes; every report's in-image probe shows the "
                                  "installed package files equal to the wheel's"},
        "host": args.host,
        "runner": "tools/run_container_acceptance.sh, tools/run_operational_acceptance_container.sh and "
                  "deployment/test_production_{capacity,soak,disk_full}.py",
        "evidence_files": entries, "problems": problems,
        "overall_status": "passed" if not problems else "failed", "notes": args.note}
    (directory / "container-acceptance-run.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"overall_status": record["overall_status"], "problems": problems}))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
