"""Check docs/cli-production-readiness.md against the candidate's evidence.

Consistency, not acceptance: every cited path exists; the counts and verdict
fractions written in the register are the ones in the reports (the register
must quote them in the fixed phrases below); the run record is current and
bound to the cited image; every report is identity-bound (evidence-check);
the packaged OWASP/ATLAS mapping matches the Linux reports. Whether every
target passed is reported separately under "acceptance". Exit 1 on any
consistency problem. Requires PyYAML for the mapping check.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

ROOT = evidence.ROOT
EVIDENCE = evidence.EVIDENCE_DIR
CORE = ("linux-core-tests.json", "macos-core-tests.json", "macos-optional-sdk-tests.json")
REQUIRED = CORE + ("attack-scenarios.json", "macos-attack-scenarios.json", "unlabelled-detection-evaluation.json",
                   "upgrade-rollback-drill-rc5.json", "upgrade-rollback-drill-rc1.json",
                   "container-production-profile.json", "container-isolation.json", "peer-isolation.json",
                   "production-disk-full.json", "alpine-os-scan.provenance.json",
                   "operational-acceptance-container.json", "production-capacity.json", "production-soak.json",
                   "container-acceptance-run.json", "evidence-check.json", "release-snapshot-check.json")


def load(name):
    return json.loads((EVIDENCE / name).read_text())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    text = (ROOT / "docs/cli-production-readiness.md").read_text()
    problems, checks, acceptance = [], {}, {}
    cited = set(re.findall(r"`([A-Za-z0-9_./-]+\.(?:json|md|py|log|yaml|yml|txt|sh|sha256))(?:::[A-Za-z_]+)?`", text))
    for path in sorted(cited):
        candidates = [ROOT / path, EVIDENCE / path, ROOT / "docs" / path, ROOT / "src/enkstein_guard" / path,
                      ROOT / "deployment" / path, ROOT / "tools" / path]
        if not any(candidate.exists() for candidate in candidates):
            problems.append("missing cited path: " + path)
    missing = [name for name in REQUIRED if not (EVIDENCE / name).exists()]
    checks["all required reports present"] = not missing
    problems += ["missing report: " + name for name in missing]
    if missing:
        return finish(cited, checks, acceptance, problems)
    for name in CORE:
        report = load(name)
        counts = report["counts"]
        checks["%s quoted in register" % name] = counts["summary"] in text
        acceptance[name] = report["successful"] and counts["failed"] == counts["error"] == 0
    attack, macos_attack = load("attack-scenarios.json"), load("macos-attack-scenarios.json")
    checks["attack summary quoted in register"] = attack["summary"] in text
    checks["macOS attack outcomes equal Linux"] = (
        {k: v["outcome"] for k, v in macos_attack["scenarios"].items()}
        == {k: v["outcome"] for k, v in attack["scenarios"].items()})
    gaps = text.split("## Confirmed gaps", 1)[1].split("\n## ", 1)[0] if "## Confirmed gaps" in text else ""
    checks["register lists every confirmed gap"] = (len(re.findall(r"^\d+\. ", gaps, re.M))
                                                    == attack["counts"]["gap_confirmed"])
    # Confirmed gaps are not accepted: only a run without gaps would be.
    acceptance["attack scenarios"] = attack["gate"] == "scoped_scenarios_passed"
    for name, phrase in (("container-production-profile.json", "production-profile checks"),
                         ("production-disk-full.json", "disk-full checks")):
        report = load(name)
        passed, total = sum(bool(v) for v in report["checks"].values()), len(report["checks"])
        # An aborted harness lists only the checks it reached; its fraction is
        # not a result, so the register cannot cite it.
        checks["%s harness completed" % name] = "error" not in report
        checks["%s fraction quoted" % name] = "%d/%d %s" % (passed, total, phrase) in text
        acceptance[name] = report["passed"] is True and "error" not in report
    for name, phrase, definition in (
            ("operational-acceptance-container.json", "development-profile targets met", "capacity-targets.json"),
            ("production-capacity.json", "production capacity targets met", "capacity-targets-production.json"),
            ("production-soak.json", "soak targets met", "soak-targets.json")):
        report = load(name)
        # Fractions count every defined target; a target without a verdict
        # (group not run, harness aborted) counts as not met.
        defined = [item["id"] for item in json.loads((ROOT / "docs/operations" / definition).read_text())["targets"]]
        verdicts = report.get("verdicts") or {}
        passed, total = sum(bool((verdicts.get(target) or {}).get("passed")) for target in defined), len(defined)
        checks["%s verdicts cover every defined target" % name] = set(verdicts) == set(defined)
        checks["%s fraction quoted" % name] = "%d/%d %s" % (passed, total, phrase) in text
        acceptance[name] = passed == total and report.get("passed") is True
    for name in ("upgrade-rollback-drill-rc5.json", "upgrade-rollback-drill-rc1.json",
                 "container-isolation.json", "peer-isolation.json"):
        acceptance[name] = load(name)["passed"] is True
    acceptance["image scan"] = load("alpine-os-scan.provenance.json")["gate"] == "no_high_critical_findings"
    run = load("container-acceptance-run.json")
    checks["container run record passed"] = run["overall_status"] == "passed" and not run["problems"]
    checks["container run record is current"] = all(digest(EVIDENCE / name) == entry["sha256"]
                                                    for name, entry in run["evidence_files"].items())
    checks["image ID cited in register"] = run["image_id"] in text
    checks["wheel hash cited in register"] = evidence.sha256_file(evidence.WHEEL) in text
    identity = load("evidence-check.json")
    checks["evidence identity check passed"] = identity["passed"] is True
    # tools/verify_release_snapshot.py, given the candidate explicitly (no discovery).
    snapshot = load("release-snapshot-check.json")
    checks["release snapshot verifier passed"] = (
        snapshot.get("passed") is True and (snapshot.get("candidate") or {}).get("image_id") == run["image_id"]
        and (snapshot.get("candidate") or {}).get("wheel_sha256") == evidence.sha256_file(evidence.WHEEL))
    reports = {path.name for path in EVIDENCE.glob("*.json")} - {"evidence-check.json", "alpine-os-scan.json",
                                                                 "register-check.json", "release-snapshot-check.json"}
    checks["evidence identity check covers every report"] = reports <= set(identity["reports"])
    checks["evidence identity check is current"] = all(
        (EVIDENCE / name).exists() and digest(EVIDENCE / name) == entry.get("sha256")
        for name, entry in identity["reports"].items() if name != "register-check.json")
    mapping = subprocess.run([sys.executable, str(ROOT / "tools/build_framework_mapping.py"),
                              "--attack-report", str(EVIDENCE / "attack-scenarios.json"),
                              "--core-report", str(EVIDENCE / "linux-core-tests.json"), "--check"],
                             capture_output=True, text=True)
    checks["packaged mapping matches linux reports"] = mapping.returncode == 0
    preserved = EVIDENCE / "rc1-evidence-preserved.sha256"
    if preserved.exists():
        lines = [line.split() for line in preserved.read_text().splitlines() if line.strip()]
        checks["0.5.0rc1 evidence unchanged"] = all(
            digest(ROOT / "verification/cli-v1" / name) == value for value, name in lines)
    return finish(cited, checks, acceptance, problems)


def finish(cited, checks, acceptance, problems):
    problems = problems + ["inconsistent: " + name for name, ok in checks.items() if not ok]
    report = {"evidence": evidence.header("register-check"), "cited_paths": len(cited), "checks": checks,
              "acceptance": acceptance, "all_accepted": bool(acceptance) and all(acceptance.values()),
              "problems": problems, "passed": not problems}
    (EVIDENCE / "register-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "all_accepted": report["all_accepted"], "problems": problems}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
