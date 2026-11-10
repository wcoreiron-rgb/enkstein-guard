"""Check that every report in the candidate's evidence directory is bound to
the exact candidate: version, release wheel, installed package equal to the
wheel, the current source/test/tool/deployment/definition revision, a
dependency inventory and an environment record; container reports must also
name the expected image and show its installed package equal to the wheel.

Reports from the locked deployment environments (Linux glibc venv, the
runtime image) must also match their hash lock exactly. Writes
evidence-check.json with every report's SHA-256, so later changes are
detectable. No exemptions. Exit 1 on any problem.
Usage: python tools/verify_evidence.py --image-id sha256:...
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

CONTAINER = {"container-production-profile.json", "container-isolation.json", "peer-isolation.json",
             "alpine-os-scan.provenance.json", "operational-acceptance-container.json", "production-capacity.json",
             "production-soak.json", "production-disk-full.json"}
CONFIGURED = {"container-production-profile.json", "operational-acceptance-container.json", "production-capacity.json",
              "production-soak.json", "production-disk-full.json"}
# The raw Trivy output is bound by its provenance file; the snapshot verdict and
# the register check are written after this check.
NOT_REPORTS = {"evidence-check.json", "alpine-os-scan.json", "register-check.json", "release-snapshot-check.json"}
LOCKED = CONTAINER | {"linux-core-tests.json", "attack-scenarios.json", "unlabelled-detection-evaluation.json",
                      "upgrade-rollback-drill-rc5.json", "upgrade-rollback-drill-rc1.json"}
# Reports about other reports: they run no candidate code, so the installed
# package check does not apply; version, wheel and revision still do.
META = {"container-acceptance-run.json"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    directory = evidence.EVIDENCE_DIR
    current = evidence.revision()
    wheel_sha = evidence.sha256_file(evidence.WHEEL)
    wheel_package = evidence.wheel_package_digest(evidence.WHEEL)["sha256"]
    results, problems = {}, []
    for path in sorted(directory.glob("*.json")):
        if path.name in NOT_REPORTS:
            continue
        issues = []
        try:
            report = json.loads(path.read_text())
        except ValueError:
            problems.append(path.name + ": not JSON")
            continue
        header = report.get("evidence") if isinstance(report, dict) else None
        if not isinstance(header, dict) or header.get("schema") != evidence.SCHEMA:
            issues.append("no evidence header")
        else:
            candidate = header.get("candidate") or {}
            if candidate.get("version") != evidence.VERSION:
                issues.append("version %s" % candidate.get("version"))
            if candidate.get("wheel_sha256") != wheel_sha:
                issues.append("wheel hash differs from the release wheel")
            if candidate.get("installed_matches_wheel") is not True and path.name not in META:
                issues.append("installed package not equal to the release wheel")
            for part in ("source", "tests", "tools", "deployment", "definitions"):
                if (header.get("revision") or {}).get(part, {}).get("sha256") != current[part]["sha256"]:
                    issues.append("stale %s revision" % part)
            dependencies = header.get("dependencies") or {}
            if not dependencies.get("python"):
                issues.append("no dependency inventory")
            if path.name in LOCKED and not (dependencies.get("lock") or {}).get("matches_lock"):
                issues.append("dependencies differ from the hash lock")
            if not header.get("environment"):
                issues.append("no environment record")
            if path.name in CONFIGURED and not header.get("configuration"):
                issues.append("no configuration hash")
            for item in header.get("configuration") or []:
                # The exact configuration is kept next to the reports; its hash
                # must be the one recorded.
                copy = directory / str(item.get("preserved") or "")
                if path.name in CONFIGURED and not item.get("preserved"):
                    issues.append("configuration %s not preserved" % item.get("name"))
                elif item.get("preserved") and (not copy.is_file() or evidence.sha256_file(copy) != item.get("sha256")):
                    issues.append("preserved configuration %s differs from the recorded hash" % item.get("name"))
            if path.name in CONTAINER:
                image = header.get("image") or {}
                if image.get("id") != args.image_id:
                    issues.append("image %s" % image.get("id"))
                if (image.get("installed_package") or {}).get("sha256") != wheel_package:
                    issues.append("image package not equal to the release wheel")
        results[path.name] = {"bound": not issues, "issues": issues, "sha256": evidence.sha256_file(path)}
        problems += ["%s: %s" % (path.name, issue) for issue in issues]
    report = {"evidence": evidence.header("evidence-check"), "directory": str(directory.relative_to(evidence.ROOT)),
              "image_id": args.image_id, "wheel_sha256": wheel_sha, "wheel_package_sha256": wheel_package,
              "revision": current, "reports": results, "problems": problems, "passed": bool(results) and not problems}
    (directory / "evidence-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "reports": len(results), "problems": problems[:20]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
