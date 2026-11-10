"""Build the packaged, versioned OWASP/ATLAS control-to-scenario mappings.

Inputs: docs/security/control-mapping-v2.json (controls and residual risk),
the pinned framework sources under verification/references (names and hashes),
and an executed attack-scenario report (outcomes). Scenario membership comes
from each scenario's own tags. ATLAS IDs are validated against the pinned
dataset; unknown IDs fail the build. Output never marks a category or technique
as fully accepted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PREVENTED, BENIGN, GAP = "prevented_in_scenario", "benign_allowed", "gap_confirmed"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atlas_names(path):
    import yaml
    data = yaml.safe_load(Path(path).read_bytes())
    names = {}

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("id"), str) and node["id"].startswith("AML.T") and "name" in node:
                names[node["id"]] = node["name"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(data)
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-report", required=True)
    parser.add_argument("--core-report", required=True, help="tools/verify_scenarios.py output for component tests")
    parser.add_argument("--check", action="store_true",
                        help="verify the packaged mapping equals the mapping generated from these reports")
    args = parser.parse_args()
    spec = json.loads((ROOT / "docs/security/control-mapping-v2.json").read_text())
    report = json.loads(Path(args.attack_report).read_text())
    core = json.loads(Path(args.core_report).read_text())
    previous = json.loads((ROOT / "src/enkstein_guard/coverage.json").read_text())
    import re
    package_version = re.search(r'__version__ = "([^"]+)"', (ROOT / "src/enkstein_guard/__init__.py").read_text())[1]
    for label, source in (("attack", report), ("core", core)):
        if args.check and source["version"] != package_version:
            raise SystemExit("%s report was produced by %s, not %s" % (label, source["version"], package_version))
    # Fail closed: a mapping is never generated from failed, errored or changed
    # scenarios, or from component tests that did not pass.
    unexpected = {sid: rec["outcome"] for sid, rec in report["scenarios"].items()
                  if rec["outcome"] not in (PREVENTED, BENIGN, GAP)}
    if unexpected or any(report["counts"].get(k, 0) for k in ("failed", "error", "gap_probe_changed_requires_review",
                                                              "skipped")):
        raise SystemExit("attack report contains unexpected outcomes; review before mapping: %s" % sorted(unexpected))
    if not core.get("successful"):
        raise SystemExit("core report is not successful; review before mapping")
    names = {row["id"]: row["name"] for row in previous["requirements"]}
    references = ROOT / "verification/references"
    manifest = {item["file"]: item for item in json.loads((references / "owasp-source-manifest.json").read_text())}
    for name, item in manifest.items():
        if sha(references / name) != item["sha256"]:
            raise SystemExit("pinned OWASP source hash mismatch: " + name)
    atlas_source = json.loads((references / "atlas-source.json").read_text())
    if sha(references / "ATLAS.yaml") != atlas_source["sha256"]:
        raise SystemExit("pinned ATLAS dataset hash mismatch")
    techniques = atlas_names(references / "ATLAS.yaml")
    scenarios = report["scenarios"]
    for scenario_id, record in scenarios.items():
        for technique in record.get("atlas", []):
            if technique not in techniques:
                raise SystemExit("unknown ATLAS technique in scenario %s: %s" % (scenario_id, technique))
    rows = []
    for requirement_id, item in spec["owasp"].items():
        linked = {sid: rec for sid, rec in scenarios.items() if requirement_id in rec.get("owasp", [])}
        outcomes = sorted({rec["outcome"] for rec in linked.values()})
        if not linked:
            raise SystemExit("no executed scenario for " + requirement_id)
        rows.append({
            "id": requirement_id, "name": names[requirement_id], "owner": "Guard runtime",
            "controls": item["controls"],
            "control_names": [spec["controls"][c]["name"] for c in item["controls"]],
            "acceptance": next(r["acceptance"] for r in previous["requirements"] if r["id"] == requirement_id),
            "acceptance_test_id": next(r["acceptance_test_id"] for r in previous["requirements"] if r["id"] == requirement_id),
            "status": "gap_confirmed" if GAP in outcomes else "scoped_evidence_only",
            "executed_tests": sorted(sid.split(".", 1)[1] if sid.count(".") > 2 else sid for sid in linked),
            "scenarios": [{"id": sid, "kind": rec.get("kind"), "outcome": rec["outcome"], "scope": rec.get("scope")}
                          for sid, rec in sorted(linked.items())],
            "counts": {o: sum(rec["outcome"] == o for rec in linked.values()) for o in (PREVENTED, BENIGN, GAP)},
            "residual_risk": item["residual_risk"],
            "full_category_acceptance": False})
    atlas_rows = []
    for technique, item in spec["atlas"].items():
        if technique not in techniques:
            raise SystemExit("unknown ATLAS technique in mapping: " + technique)
        linked = {sid: rec for sid, rec in scenarios.items() if technique in rec.get("atlas", [])}
        outcomes = {rec["outcome"] for rec in linked.values()}
        component = {name: core["tests"].get(name, "not_executed") for name in item["component_tests"]}
        not_passed = sorted(name for name, result in component.items() if result != "passed")
        if not_passed:
            raise SystemExit("component tests for %s did not pass in the core report: %s" % (technique, not_passed))
        status = ("scope_limitation" if not item["controls"] else "gap_confirmed" if GAP in outcomes
                  else "scenario_and_component_evidence" if linked and component
                  else "scenario_evidence" if linked else "component_evidence" if component else "not_exercised")
        atlas_rows.append({"id": technique, "name": techniques[technique], "status": status,
                           "controls": item["controls"], "tests": item["component_tests"],
                           "component_test_results": component,
                           "scenarios": [{"id": sid, "outcome": rec["outcome"]} for sid, rec in sorted(linked.items())],
                           "note": item.get("note", ""),
                           "limitation": "Selected local scenarios and component tests only; no full technique prevention claim."})
    coverage = {
        "schema_version": 2, "mapping_version": spec["mapping_version"],
        "product_version": package_version, "frameworks": previous["frameworks"],
        "sources": {"owasp": [{"file": k, "sha256": v["sha256"], "source": v["source"]} for k, v in manifest.items()],
                    "atlas": {"commit": atlas_source["commit"], "path": atlas_source["path"],
                              "sha256": atlas_source["sha256"], "content_version": atlas_source["content_version"]}},
        "controls": spec["controls"], "requirements": rows,
        "mitre_atlas": {"source": "https://atlas.mitre.org/", "status": "selected_scenario_mapping",
                        "content_version": atlas_source["content_version"],
                        "techniques": sorted(r["id"] for r in atlas_rows), "component_mapping": "atlas-evidence.json",
                        "note": "Selected techniques with executed scenarios/component tests. Full technique validation is not claimed."},
        "evidence": {"report": str((evidence.EVIDENCE_DIR / "attack-scenarios.json").relative_to(ROOT)),
                     "scenario_outcomes_sha256": hashlib.sha256(json.dumps(
                         {sid: rec["outcome"] for sid, rec in sorted(scenarios.items())}, sort_keys=True).encode()).hexdigest(),
                     "scenario_count": report["scenario_count"], "counts": report["counts"], "gate": report["gate"],
                     "note": "Scenario execution does not establish full category protection. Expected failures are confirmed gaps."},
        "statement": spec["statement"]}
    atlas = {"schema_version": 2, "source": "https://github.com/mitre-atlas/atlas-data", "commit": atlas_source["commit"],
             "path": atlas_source["path"], "sha256": atlas_source["sha256"], "content_version": atlas_source["content_version"],
             "techniques": atlas_rows}
    outputs = {ROOT / "src/enkstein_guard/coverage.json": json.dumps(coverage, indent=2) + "\n",
               ROOT / "src/enkstein_guard/atlas-evidence.json": json.dumps(atlas, indent=2) + "\n"}
    if args.check:
        mismatched = [path.name for path, text in outputs.items() if path.read_text() != text]
        print(json.dumps({"packaged_mapping_matches_reports": not mismatched, "mismatched": mismatched}))
        return 1 if mismatched else 0
    for path, text in outputs.items():
        path.write_text(text)
    print(json.dumps({"requirements": len(rows), "gap_confirmed": sum(r["status"] == "gap_confirmed" for r in rows),
                      "atlas_techniques": len(atlas_rows)}))


if __name__ == "__main__":
    raise SystemExit(main())
