#!/usr/bin/env python3
"""Fail-closed verification of an explicitly supplied release snapshot.

This verifier intentionally discovers nothing.  The caller supplies the candidate
identity, every release report, every dependency lock, and the raw/provenance image
scan pair.  It writes no files and emits one JSON verdict to stdout.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile


SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_PARTS = ("source", "tests", "tools", "deployment", "definitions")
SCHEMA = "enkstein-guard.release-snapshot-verdict/v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized(name: str) -> str:
    return name.lower().replace("_", "-")


def _inventory_digest(rows: list[dict]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def _wheel_package_digest(wheel: Path, package: str) -> str:
    prefix = package.rstrip("/") + "/"
    entries: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith(prefix) and not name.endswith("/"):
                entries.append((name, archive.read(name)))
    if not entries:
        raise ValueError("wheel contains no files under package %s" % package)
    digest = hashlib.sha256()
    for name, content in sorted(entries):
        digest.update(("%s\0%s\n" % (name, hashlib.sha256(content).hexdigest())).encode())
    return digest.hexdigest()


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else root / path).resolve()


def _load_json(path: Path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _parse_lock(path: Path) -> dict[str, str]:
    pinned: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", stripped)
        if not match or "--hash=sha256:" not in stripped:
            raise ValueError("%s:%d is not a hash-pinned requirement" % (path, number))
        name, version = _normalized(match.group(1)), match.group(2)
        if name in pinned and pinned[name] != version:
            raise ValueError("%s pins %s more than once with different versions" % (path, name))
        pinned[name] = version
    if not pinned:
        raise ValueError("%s contains no pinned requirements" % path)
    return pinned


class SnapshotVerifier:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.root = args.root.resolve()
        self.problems: list[str] = []
        self.checks: dict[str, bool] = {}
        self.wheel_sha256 = ""
        self.wheel_package_sha256 = ""
        self.locks: dict[Path, dict] = {}
        self.expected_revision: dict[str, str] = {}

    def problem(self, context: str, message: str) -> None:
        self.problems.append("%s: %s" % (context, message))

    def require(self, condition: bool, context: str, message: str) -> bool:
        if not condition:
            self.problem(context, message)
            return False
        return True

    def prepare(self) -> bool:
        if not self.require(self.root.is_dir(), "inputs", "root is not a directory"):
            return False
        for label, path in (("wheel", self.args.wheel), ("scan report", self.args.scan_report),
                            ("scan provenance", self.args.scan_provenance)):
            self.require(path.is_file(), "inputs", "%s does not exist: %s" % (label, path))
        for path in self.args.report:
            self.require(path.is_file(), "inputs", "release report does not exist: %s" % path)
        for path in self.args.lock:
            self.require(path.is_file(), "inputs", "dependency lock does not exist: %s" % path)
        if self.problems:
            return False
        if not IMAGE_ID.fullmatch(self.args.image_id):
            self.problem("inputs", "image ID must be sha256:<64 lowercase hex>")
        try:
            self.wheel_sha256 = _sha256(self.args.wheel)
            self.wheel_package_sha256 = _wheel_package_digest(self.args.wheel, self.args.package)
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            self.problem("wheel", str(error))
        for value in self.args.revision:
            if "=" not in value:
                self.problem("inputs", "revision must be NAME=SHA256: %s" % value)
                continue
            name, digest = value.split("=", 1)
            if name in self.expected_revision:
                self.problem("inputs", "duplicate revision binding: %s" % name)
            elif name not in REVISION_PARTS or not SHA256.fullmatch(digest):
                self.problem("inputs", "invalid revision binding: %s" % value)
            else:
                self.expected_revision[name] = digest
        if set(self.expected_revision) != set(REVISION_PARTS):
            self.problem("inputs", "revision bindings must name exactly: %s" % ", ".join(REVISION_PARTS))
        allowed_pip = {path.resolve() for path in self.args.allow_build_pip_absence}
        supplied_locks = {path.resolve() for path in self.args.lock}
        if not allowed_pip <= supplied_locks:
            self.problem("inputs", "build-only pip absence was declared for an unsupplied lock")
        for path in supplied_locks:
            try:
                self.locks[path] = {"sha256": _sha256(path), "pinned": _parse_lock(path),
                                    "allow_pip_absence": path in allowed_pip}
            except (OSError, ValueError) as error:
                self.problem("lock", str(error))
        return not self.problems

    def validate_candidate(self, header: dict, context: str) -> None:
        candidate = header.get("candidate")
        if not isinstance(candidate, dict):
            self.problem(context, "missing candidate binding")
            return
        expected = {
            "version": self.args.version,
            "wheel_sha256": self.wheel_sha256,
            "wheel_package_sha256": self.wheel_package_sha256,
            "installed_package_sha256": self.wheel_package_sha256,
            "installed_matches_wheel": True,
        }
        for key, value in expected.items():
            if candidate.get(key) != value:
                self.problem(context, "candidate.%s does not match the supplied wheel" % key)
        wheel_name = candidate.get("wheel")
        if not isinstance(wheel_name, str) or Path(wheel_name).name != self.args.wheel.name:
            self.problem(context, "candidate wheel path does not name the supplied wheel")

    def validate_revision(self, header: dict, context: str) -> None:
        revision = header.get("revision")
        if not isinstance(revision, dict):
            self.problem(context, "missing revision binding")
            return
        for part, expected in self.expected_revision.items():
            value = revision.get(part)
            if not isinstance(value, dict) or value.get("sha256") != expected:
                self.problem(context, "revision.%s does not match the explicit snapshot" % part)
            if not isinstance(value, dict) or not isinstance(value.get("files"), int) or value.get("files") <= 0:
                self.problem(context, "revision.%s has no positive file count" % part)

    def inventory(self, dependencies: dict, context: str) -> dict[str, str] | None:
        rows = dependencies.get("python") if isinstance(dependencies, dict) else None
        if not isinstance(rows, list) or not rows:
            self.problem(context, "missing Python dependency inventory")
            return None
        installed: dict[str, str] = {}
        canonical_rows: list[dict] = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                self.problem(context, "malformed dependency inventory row")
                return None
            versions = row.get("versions")
            name = _normalized(row["name"])
            if not isinstance(versions, list) or len(versions) != 1 or not isinstance(versions[0], str):
                self.problem(context, "dependency %s must have exactly one installed version" % name)
                return None
            if name in installed:
                self.problem(context, "duplicate dependency inventory row for %s" % name)
                return None
            installed[name] = versions[0]
            canonical_rows.append({"name": name, "versions": [versions[0]]})
        canonical_rows.sort(key=lambda row: row["name"])
        if dependencies.get("inventory_sha256") != _inventory_digest(canonical_rows):
            self.problem(context, "dependency inventory digest is invalid")
        if dependencies.get("shadowed") not in ([], None):
            self.problem(context, "shadowed dependency versions are present")
        return installed

    def validate_dependencies(self, header: dict, context: str) -> None:
        dependencies = header.get("dependencies")
        installed = self.inventory(dependencies, context)
        if installed is None:
            return
        lock_record = dependencies.get("lock")
        if not isinstance(lock_record, dict) or not isinstance(lock_record.get("lock"), str):
            self.problem(context, "missing dependency lock binding")
            return
        lock_path = _resolve(self.root, lock_record["lock"])
        lock = self.locks.get(lock_path)
        if lock is None:
            self.problem(context, "report references an unsupplied dependency lock: %s" % lock_record["lock"])
            return
        if lock_record.get("lock_sha256") != lock["sha256"]:
            self.problem(context, "recorded dependency lock hash does not match the current lock")
        if lock_record.get("pinned") != len(lock["pinned"]):
            self.problem(context, "recorded dependency pin count is invalid")
        missing = sorted(set(lock["pinned"]) - set(installed))
        permitted = ["pip"] if lock["allow_pip_absence"] else []
        unexpected_missing = sorted(set(missing) - set(permitted))
        mismatched = sorted(name for name, version in lock["pinned"].items()
                            if name in installed and installed[name] != version)
        extra = sorted(set(installed) - set(lock["pinned"]))
        if unexpected_missing:
            self.problem(context, "missing locked runtime dependencies: %s" % ", ".join(unexpected_missing))
        if mismatched:
            self.problem(context, "installed dependency versions differ from the lock: %s" % ", ".join(mismatched))
        if extra:
            self.problem(context, "installed dependencies are absent from the lock: %s" % ", ".join(extra))
        if lock_record.get("absent") != missing:
            self.problem(context, "recorded absent dependency list is invalid")
        if lock_record.get("mismatched") != mismatched:
            self.problem(context, "recorded mismatched dependency list is invalid")
        if lock_record.get("not_in_lock") != extra:
            self.problem(context, "recorded extra dependency list is invalid")
        if lock_record.get("matches_lock") is not True or unexpected_missing or mismatched or extra:
            self.problem(context, "dependency lock verdict is not a strict match")

    def validate_image(self, header: dict, context: str) -> None:
        image = header.get("image")
        if not isinstance(image, dict):
            self.problem(context, "missing image binding")
            return
        if image.get("id") != self.args.image_id:
            self.problem(context, "image ID does not match the explicit snapshot")
        installed = image.get("installed_package")
        if not isinstance(installed, dict) or installed.get("sha256") != self.wheel_package_sha256:
            self.problem(context, "image package does not match the supplied wheel")
        if not isinstance(installed, dict) or installed.get("version") != self.args.version:
            self.problem(context, "image package version does not match the candidate")
        image_dependencies = image.get("dependencies")
        header_dependencies = header.get("dependencies")
        image_inventory = self.inventory(image_dependencies, context + ".image")
        header_inventory = self.inventory(header_dependencies, context + ".header")
        if image_inventory is not None and header_inventory is not None and image_inventory != header_inventory:
            self.problem(context, "image and report dependency inventories differ")

    def validate_configurations(self, header: dict, context: str) -> None:
        configurations = header.get("configuration")
        if not isinstance(configurations, list) or not configurations:
            self.problem(context, "missing required configuration binding")
            return
        seen = set()
        for item in configurations:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
                self.problem(context, "malformed configuration binding")
                continue
            if item["name"] in seen:
                self.problem(context, "duplicate configuration binding: %s" % item["name"])
            seen.add(item["name"])
            if not isinstance(item.get("sha256"), str) or not SHA256.fullmatch(item["sha256"]):
                self.problem(context, "configuration %s has an invalid SHA-256" % item["name"])
            if not isinstance(item.get("policy_version"), str) or not item["policy_version"]:
                self.problem(context, "configuration %s has no policy version" % item["name"])

    def validate_header(self, header: dict, context: str, *, require_configuration: bool) -> None:
        if not isinstance(header, dict) or header.get("schema") != "enkstein-guard.evidence/v1":
            self.problem(context, "missing or invalid evidence header")
            return
        if not isinstance(header.get("report"), str) or not header["report"]:
            self.problem(context, "missing report identity")
        if not isinstance(header.get("environment"), dict) or not header["environment"]:
            self.problem(context, "missing environment binding")
        self.validate_candidate(header, context)
        self.validate_revision(header, context)
        self.validate_dependencies(header, context)
        self.validate_image(header, context)
        if require_configuration:
            self.validate_configurations(header, context)

    def validate_report(self, path: Path) -> None:
        context = str(path)
        try:
            report = _load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self.problem(context, "invalid JSON: %s" % error)
            return
        if not isinstance(report, dict):
            self.problem(context, "report is not a JSON object")
            return
        if report.get("passed") is not True:
            self.problem(context, "release report did not pass")
        if report.get("error") not in (None, ""):
            self.problem(context, "release report contains an error")
        self.validate_header(report.get("evidence"), context, require_configuration=True)

    def validate_scan(self) -> None:
        context = str(self.args.scan_provenance)
        try:
            raw = _load_json(self.args.scan_report)
            provenance = _load_json(self.args.scan_provenance)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self.problem("scan", "invalid JSON: %s" % error)
            return
        if not isinstance(raw, dict) or not isinstance(provenance, dict):
            self.problem("scan", "scan files must be JSON objects")
            return
        raw_sha = _sha256(self.args.scan_report)
        if provenance.get("report_sha256") != raw_sha:
            self.problem(context, "raw scan report SHA-256 does not match provenance")
        if provenance.get("image_id") != self.args.image_id:
            self.problem(context, "scan image ID does not match the explicit snapshot")
        if provenance.get("network_during_scan") != "none" or provenance.get("ignored_unfixed") is not False:
            self.problem(context, "scan must be offline and include unfixed findings")
        if not isinstance(provenance.get("archive_sha256"), str) or not SHA256.fullmatch(provenance["archive_sha256"]):
            self.problem(context, "missing exact image archive SHA-256")
        if not isinstance(provenance.get("scanner_image"), str) or not re.search(r"@sha256:[0-9a-f]{64}$",
                                                                                 provenance["scanner_image"]):
            self.problem(context, "scanner image is not digest-pinned")
        if raw.get("ArtifactType") != "container_image" or not isinstance(raw.get("Results"), list):
            self.problem(str(self.args.scan_report), "malformed container image scan")
            return
        metadata = raw.get("Metadata")
        scanner_id = metadata.get("ImageID") if isinstance(metadata, dict) else None
        if not isinstance(scanner_id, str) or provenance.get("trivy_reported_image_id") != scanner_id:
            self.problem(context, "scanner-reported image identity is not bound to the raw report")
        counts = collections.Counter()
        malformed = False
        for result in raw["Results"]:
            if not isinstance(result, dict):
                malformed = True
                continue
            vulnerabilities = result.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                malformed = True
                continue
            for vulnerability in vulnerabilities:
                severity = vulnerability.get("Severity") if isinstance(vulnerability, dict) else None
                if not isinstance(severity, str) or not severity:
                    malformed = True
                else:
                    counts[severity.upper()] += 1
        if malformed:
            self.problem(str(self.args.scan_report), "malformed vulnerability entry")
        recomputed = dict(sorted((key, value) for key, value in counts.items() if value))
        if provenance.get("severity_counts") != recomputed:
            self.problem(context, "severity counts do not match the raw scan report")
        high = counts["HIGH"] + counts["CRITICAL"]
        gate = "blocked_high_findings" if high else "no_high_critical_findings"
        if provenance.get("gate") != gate:
            self.problem(context, "scan gate does not match recomputed findings")
        if high:
            self.problem(context, "raw scan contains %d high/critical findings" % high)
        self.validate_header(provenance.get("evidence"), context, require_configuration=False)

    def run(self) -> dict:
        if self.prepare():
            for report in self.args.report:
                self.validate_report(report)
            self.validate_scan()
        self.checks = {
            "explicit_inputs_complete": not any(problem.startswith("inputs:") for problem in self.problems),
            "wheel_bound": not any("wheel" in problem.lower() for problem in self.problems),
            "reports_bound": not any(str(path) in problem for path in self.args.report for problem in self.problems),
            "scan_bound": not any("scan" in problem.lower() for problem in self.problems),
            "dependencies_bound": not any("dependenc" in problem.lower() or "lock" in problem.lower()
                                          for problem in self.problems),
        }
        return {
            "schema": SCHEMA,
            "passed": not self.problems,
            "candidate": {"version": self.args.version, "wheel": str(self.args.wheel),
                          "wheel_sha256": self.wheel_sha256 or None,
                          "wheel_package_sha256": self.wheel_package_sha256 or None,
                          "image_id": self.args.image_id},
            "reports": [str(path) for path in self.args.report],
            "checks": self.checks,
            "problems": self.problems,
        }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", type=Path, required=True, help="root used to resolve lock paths recorded in reports")
    result.add_argument("--version", required=True)
    result.add_argument("--package", required=True, help="Python import package directory inside the wheel")
    result.add_argument("--wheel", type=Path, required=True)
    result.add_argument("--image-id", required=True)
    result.add_argument("--scan-report", type=Path, required=True)
    result.add_argument("--scan-provenance", type=Path, required=True)
    result.add_argument("--report", type=Path, action="append", required=True,
                        help="configured, passed release report; repeat explicitly")
    result.add_argument("--lock", type=Path, action="append", required=True, help="current dependency lock; repeat")
    result.add_argument("--allow-build-pip-absence", type=Path, action="append", default=[],
                        help="lock for an image that intentionally removes build-only pip")
    result.add_argument("--revision", action="append", required=True,
                        help="explicit NAME=SHA256; supply source, tests, tools, deployment and definitions")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    args.root = args.root.resolve()
    args.wheel = _resolve(args.root, str(args.wheel))
    args.scan_report = _resolve(args.root, str(args.scan_report))
    args.scan_provenance = _resolve(args.root, str(args.scan_provenance))
    args.report = [_resolve(args.root, str(path)) for path in args.report]
    args.lock = [_resolve(args.root, str(path)) for path in args.lock]
    args.allow_build_pip_absence = [_resolve(args.root, str(path)) for path in args.allow_build_pip_absence]
    verdict = SnapshotVerifier(args).run()
    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
