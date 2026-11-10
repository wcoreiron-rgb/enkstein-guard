import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "tools/verify_release_snapshot.py"
IMAGE_ID = "sha256:" + "a" * 64
CONFIG_ID = "sha256:" + "b" * 64
REVISION = {name: hashlib.sha256(name.encode()).hexdigest()
            for name in ("source", "tests", "tools", "deployment", "definitions")}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory_digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


class ReleaseSnapshotVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "dist").mkdir()
        (self.root / "verification").mkdir()
        self.wheel = self.root / "dist/demo_pkg-1.2.3-py3-none-any.whl"
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("demo_pkg/__init__.py", '__version__ = "1.2.3"\n')
            archive.writestr("demo_pkg/runtime.py", "VALUE = 1\n")
            archive.writestr("demo_pkg-1.2.3.dist-info/METADATA", "Name: demo-pkg\nVersion: 1.2.3\n")
        self.package_sha = self.package_digest()
        self.lock = self.root / "dist/requirements.txt"
        self.lock.write_text(
            "demo-pkg==1.2.3 --hash=sha256:%s\n" % ("1" * 64)
            + "pip==26.0 --hash=sha256:%s\n" % ("2" * 64)
            + "runtime-dep==4.5 --hash=sha256:%s\n" % ("3" * 64)
        )
        self.report = self.root / "verification/report.json"
        self.scan = self.root / "verification/scan.json"
        self.scan_provenance = self.root / "verification/scan.provenance.json"
        self.write_fixture()

    def package_digest(self):
        entries = []
        with zipfile.ZipFile(self.wheel) as archive:
            for name in archive.namelist():
                if name.startswith("demo_pkg/") and not name.endswith("/"):
                    entries.append((name, archive.read(name)))
        result = hashlib.sha256()
        for name, content in sorted(entries):
            result.update(("%s\0%s\n" % (name, hashlib.sha256(content).hexdigest())).encode())
        return result.hexdigest()

    def dependencies(self):
        rows = [{"name": "demo-pkg", "versions": ["1.2.3"]},
                {"name": "runtime-dep", "versions": ["4.5"]}]
        return {"python": rows, "inventory_sha256": inventory_digest(rows), "shadowed": [],
                "lock": {"lock": "dist/requirements.txt", "lock_sha256": digest(self.lock), "pinned": 3,
                         "mismatched": [], "absent": ["pip"], "not_in_lock": [], "matches_lock": True}}

    def header(self, name, *, configured=True):
        dependencies = self.dependencies()
        image_dependencies = {key: dependencies[key] for key in ("python", "inventory_sha256", "shadowed")}
        return {"schema": "enkstein-guard.evidence/v1", "report": name, "generated_at": "2030-01-01T00:00:00Z",
                "candidate": {"version": "1.2.3", "wheel": "dist/" + self.wheel.name,
                              "wheel_sha256": digest(self.wheel), "wheel_package_sha256": self.package_sha,
                              "installed_package_sha256": self.package_sha, "installed_location": "/site/demo_pkg",
                              "installed_matches_wheel": True},
                "image": {"reference": IMAGE_ID, "id": IMAGE_ID, "tags": [], "repo_digests": [],
                          "installed_package": {"sha256": self.package_sha, "version": "1.2.3", "files": 2,
                                                "location": "/site/demo_pkg"},
                          "dependencies": image_dependencies},
                "configuration": ([{"name": "guard.json", "sha256": "c" * 64,
                                    "policy_version": "cfg-test"}] if configured else []),
                "dependencies": dependencies,
                "revision": {name: {"sha256": value, "files": 1} for name, value in REVISION.items()},
                "environment": {"system": "Linux", "machine": "aarch64"}}

    def write_fixture(self):
        self.report.write_text(json.dumps({"passed": True, "checks": {"ready": True},
                                          "evidence": self.header("production")}, indent=2) + "\n")
        raw = {"ArtifactName": "/image.tar", "ArtifactType": "container_image",
               "Metadata": {"ImageID": CONFIG_ID},
               "Results": [{"Target": "alpine", "Vulnerabilities": []},
                           {"Target": "Python", "Vulnerabilities": None}]}
        self.scan.write_text(json.dumps(raw, indent=2) + "\n")
        provenance = {"image_id": IMAGE_ID, "scanner_image": "scanner@sha256:" + "d" * 64,
                      "archive_sha256": "e" * 64, "report_sha256": digest(self.scan),
                      "scanned_at": "2030-01-01T00:00:00Z", "network_during_scan": "none",
                      "ignored_unfixed": False, "severity_counts": {}, "gate": "no_high_critical_findings",
                      "trivy_reported_image_id": CONFIG_ID,
                      "evidence": self.header("image-scan", configured=False)}
        self.scan_provenance.write_text(json.dumps(provenance, indent=2) + "\n")

    def command(self):
        command = [sys.executable, str(VERIFIER), "--root", str(self.root), "--version", "1.2.3",
                   "--package", "demo_pkg", "--wheel", str(self.wheel), "--image-id", IMAGE_ID,
                   "--scan-report", str(self.scan), "--scan-provenance", str(self.scan_provenance),
                   "--report", str(self.report), "--lock", str(self.lock),
                   "--allow-build-pip-absence", str(self.lock)]
        for name, value in REVISION.items():
            command += ["--revision", "%s=%s" % (name, value)]
        return command

    def run_verifier(self):
        result = subprocess.run(self.command(), cwd=self.root, capture_output=True, text=True)
        self.assertTrue(result.stdout.strip(), result.stderr)
        return result, json.loads(result.stdout)

    def rewrite_report(self, mutate):
        report = json.loads(self.report.read_text())
        mutate(report)
        self.report.write_text(json.dumps(report, indent=2) + "\n")

    def test_valid_explicit_snapshot_passes(self):
        result, verdict = self.run_verifier()
        self.assertEqual(result.returncode, 0, verdict)
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["problems"], [])

    def test_tampered_raw_scan_is_rejected(self):
        raw = json.loads(self.scan.read_text())
        raw["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-test", "Severity": "HIGH"}]
        self.scan.write_text(json.dumps(raw, indent=2) + "\n")
        result, verdict = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(verdict["passed"])
        self.assertTrue(any("raw scan report SHA-256" in item for item in verdict["problems"]))
        self.assertTrue(any("high/critical" in item for item in verdict["problems"]))

    def test_missing_runtime_dependency_is_rejected_even_if_report_claims_match(self):
        def remove_runtime(report):
            dependencies = report["evidence"]["dependencies"]
            dependencies["python"] = [row for row in dependencies["python"] if row["name"] != "runtime-dep"]
            dependencies["inventory_sha256"] = inventory_digest(dependencies["python"])
            dependencies["lock"]["absent"] = ["pip", "runtime-dep"]
            image = report["evidence"]["image"]["dependencies"]
            image["python"] = dependencies["python"]
            image["inventory_sha256"] = dependencies["inventory_sha256"]
        self.rewrite_report(remove_runtime)
        result, verdict = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any("missing locked runtime dependencies: runtime-dep" in item
                            for item in verdict["problems"]))

    def test_current_lock_hash_mismatch_is_rejected(self):
        self.lock.write_text(self.lock.read_text() + "# changed after evidence generation\n")
        result, verdict = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any("recorded dependency lock hash" in item for item in verdict["problems"]))

    def test_missing_image_binding_is_rejected(self):
        self.rewrite_report(lambda report: report["evidence"].__setitem__("image", None))
        result, verdict = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any("missing image binding" in item for item in verdict["problems"]))

    def test_missing_configuration_binding_is_rejected(self):
        self.rewrite_report(lambda report: report["evidence"].__setitem__("configuration", []))
        result, verdict = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any("missing required configuration binding" in item for item in verdict["problems"]))


if __name__ == "__main__":
    unittest.main()
