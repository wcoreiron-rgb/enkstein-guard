"""Identity header recorded in every acceptance report.

``header()`` returns the ``evidence`` object (schema enkstein-guard.evidence/v1):

- candidate: version, release wheel SHA-256, and a digest of the Guard package
  files actually imported (or installed in the image), compared with the
  wheel's package files;
- image: Docker image ID, tags, repository digests and an in-image probe of the
  installed package, Python distributions and Alpine packages (container runs);
- configuration: SHA-256 and policy version of every Guard configuration used;
- dependencies: installed Python distributions, inventory digest and whether
  they equal the hash lock;
- revision: content digests of source, tests, tools, deployment files and
  acceptance definitions (the workspace is not a version-control checkout);
- environment: interpreter, OS, kernel, CPU and memory of the runner, plus the
  Docker engine for container runs.

Run as ``python evidence.py probe`` inside an image to print the probe; it uses
only the standard library so it works in the minimal runtime image.
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.metadata as metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import zipfile

SCHEMA = "enkstein-guard.evidence/v1"
ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "enkstein_guard"
_SKIP_PARTS = {"__pycache__", ".pytest_cache"}


def source_version(root=ROOT):
    """Candidate version from the source tree (tools never hard-code it)."""
    path = root / "src" / PACKAGE / "__init__.py"
    match = re.search(r'__version__ = "([^"]+)"', path.read_text()) if path.exists() else None
    return match[1] if match else None


VERSION = source_version()
WHEEL = ROOT / "dist/deployment" / ("enkstein_guard-%s-py3-none-any.whl" % VERSION)
# 0.5.0rc1 evidence stays in verification/cli-v1; later candidates use their version.
EVIDENCE_DIR = ROOT / "verification" / ("cli-v1" if VERSION == "0.5.0rc1" else str(VERSION))
IMAGE_TAG = "enkstein-guard:%s" % VERSION


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _files(base, root=ROOT):
    base = root / base
    if base.is_file():
        return [base]
    if not base.is_dir():
        return []
    return sorted(p for p in base.rglob("*") if p.is_file() and not _SKIP_PARTS & set(p.parts)
                  and not p.name.endswith((".pyc", ".pyo")) and p.name != ".DS_Store")


def tree_digest(bases, root=ROOT):
    """SHA-256 over (relative path, file SHA-256) for every file, in order."""
    tree, count = hashlib.sha256(), 0
    for base in bases:
        for path in _files(base, root):
            tree.update(path.relative_to(root).as_posix().encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
            count += 1
    return {"sha256": tree.hexdigest(), "files": count}


def source_digest(root=ROOT):
    """Same algorithm as tools/build_provenance.py source_tree()."""
    files = sorted(p for p in (root / "src" / PACKAGE).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    tree = hashlib.sha256()
    for path in files:
        tree.update(path.relative_to(root).as_posix().encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    for extra in ("pyproject.toml", "README.md", "LICENSE"):
        tree.update(extra.encode() + b"\0" + hashlib.sha256((root / extra).read_bytes()).digest())
    return {"sha256": tree.hexdigest(), "files": len(files)}


def revision(root=ROOT):
    return {"vcs": "none: the workspace is not a version-control checkout; content digests identify the revision",
            "source": source_digest(root),
            "tests": tree_digest(("tests", "tests_adversarial", "tests_optional"), root),
            "tools": tree_digest(("tools",), root),
            "deployment": tree_digest(("deployment",), root),
            "definitions": tree_digest(("docs/operations/capacity-targets.json",
                                        "docs/operations/capacity-targets-production.json",
                                        "docs/operations/soak-targets.json",
                                        "docs/security/control-mapping-v2.json"), root)}


def _package_entries(pairs):
    digest, count = hashlib.sha256(), 0
    for name, content in sorted(pairs):
        digest.update(("%s\0%s\n" % (name, hashlib.sha256(content).hexdigest())).encode())
        count += 1
    return {"sha256": digest.hexdigest(), "files": count}


def wheel_package_digest(wheel):
    with zipfile.ZipFile(wheel) as archive:
        return _package_entries((name, archive.read(name)) for name in archive.namelist()
                                if name.startswith(PACKAGE + "/") and not name.endswith("/"))


def installed_package():
    spec = importlib.util.find_spec(PACKAGE)
    if spec is None or not spec.submodule_search_locations:
        return None
    location = Path(list(spec.submodule_search_locations)[0]).resolve()
    pairs = ((PACKAGE + "/" + path.relative_to(location).as_posix(), path.read_bytes())
             for path in _files(".", location))
    version = re.search(r'__version__ = "([^"]+)"', (location / "__init__.py").read_text())
    return {"location": str(location), "version": version[1] if version else None, **_package_entries(pairs)}


def distributions():
    seen = {}
    for item in metadata.distributions():
        name = (item.metadata["Name"] or "").strip()
        if name:
            seen.setdefault(name.lower().replace("_", "-"), set()).add(item.version)
    rows = [{"name": name, "versions": sorted(versions)} for name, versions in sorted(seen.items())]
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    return {"python": rows, "inventory_sha256": digest,
            "shadowed": sorted(row["name"] for row in rows if len(row["versions"]) > 1)}


def lock_comparison(inventory, lock, *, allowed_absent=()):
    """Compare installed versions with ``name==version --hash`` lines of a lock.

    A strict match: no other version, nothing installed beyond the lock, and
    nothing pinned missing except ``allowed_absent`` (the runtime image removes
    the build-only ``pip`` after installing from its lock)."""
    if lock is None or not Path(lock).exists():
        return None
    pinned = {name.lower().replace("_", "-"): version for name, version in
              re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", Path(lock).read_text(), re.M)}
    installed = {row["name"]: row["versions"] for row in inventory["python"]}
    # Installed with another version (or several copies) versus pinned but absent
    # (the runtime image removes pip after installing from the lock).
    mismatched = sorted(name for name, version in pinned.items() if name in installed and installed[name] != [version])
    absent = sorted(name for name in pinned if name not in installed)
    extra = sorted(set(installed) - set(pinned))
    unexpected_absent = sorted(set(absent) - set(allowed_absent))
    return {"lock": str(Path(lock).relative_to(ROOT)) if Path(lock).is_relative_to(ROOT) else str(lock),
            "lock_sha256": sha256_file(lock), "pinned": len(pinned), "mismatched": mismatched,
            "absent": absent, "allowed_absent": sorted(allowed_absent), "not_in_lock": extra,
            "matches_lock": not mismatched and not extra and not unexpected_absent}


def _memory_bytes():
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        pass
    try:
        return int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5).stdout)
    except Exception:
        return None


def environment():
    return {"python": platform.python_version(), "implementation": platform.python_implementation(),
            "executable": sys.executable, "platform": platform.platform(), "system": platform.system(),
            "kernel": platform.release(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
            "memory_bytes": _memory_bytes(), "in_container": Path("/.dockerenv").exists(),
            "user_id": os.getuid() if hasattr(os, "getuid") else None}


def alpine_packages():
    path = Path("/lib/apk/db/installed")
    if not path.exists():
        return None
    packages, name = [], None
    for line in path.read_text().splitlines():
        if line.startswith("P:"):
            name = line[2:]
        elif line.startswith("V:") and name:
            packages.append(name + "-" + line[2:])
            name = None
    return {"packages": sorted(packages),
            "inventory_sha256": hashlib.sha256("\n".join(sorted(packages)).encode()).hexdigest()}


def probe():
    """In-image identity: installed package, distributions, OS packages."""
    return {"installed_package": installed_package(), "dependencies": distributions(),
            "os_packages": alpine_packages(), "environment": environment()}


def candidate(version=None, *, installed=None):
    installed = installed if installed is not None else installed_package()
    version = version or (installed or {}).get("version") or VERSION
    wheel = ROOT / "dist/deployment" / ("enkstein_guard-%s-py3-none-any.whl" % version) if version else None
    result = {"version": version, "wheel": None, "wheel_sha256": None, "wheel_package_sha256": None,
              "installed_package_sha256": installed and installed["sha256"],
              "installed_location": installed and installed["location"], "installed_matches_wheel": None}
    if wheel is not None and wheel.exists():
        package = wheel_package_digest(wheel)
        result.update(wheel=str(wheel.relative_to(ROOT)), wheel_sha256=sha256_file(wheel),
                      wheel_package_sha256=package["sha256"],
                      installed_matches_wheel=bool(installed) and installed["sha256"] == package["sha256"])
    return result


def _policy_version(data):
    """Guard's policy version for a configuration, computed only by the
    candidate's own code (never by another installed release)."""
    try:
        installed = installed_package()
        if not installed or installed.get("version") != VERSION:
            return None
        from enkstein_guard.host import policy_version
        from enkstein_guard.productconfig import validate
        return policy_version(validate(data))
    except Exception:
        return None


def configuration(path, *, name=None, policy_version=None, preserve=None):
    """Hash of a configuration file plus the Guard policy version.

    ``preserve=(directory, file_name)`` also keeps an exact copy (acceptance
    configurations are synthetic and hold no secret values) so the recorded
    hash can be checked against the file later; the entry names the copy
    relative to the evidence directory ("configurations/<file_name>").
    """
    raw = Path(path).read_bytes()
    entry = {"name": name or Path(path).name, "sha256": hashlib.sha256(raw).hexdigest(),
             "policy_version": policy_version or _policy_version(json.loads(raw))}
    if preserve is not None:
        directory, file_name = Path(preserve[0]), preserve[1]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / file_name).write_bytes(raw)
        entry["preserved"] = "configurations/" + file_name
    return entry


def configuration_data(data, *, name):
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return {"name": name, "sha256": hashlib.sha256(raw).hexdigest(), "encoding": "canonical-json",
            "policy_version": _policy_version(data)}


def _docker(*args, timeout=120):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("docker %s failed" % args[0])
    return result.stdout


def docker_engine():
    info = json.loads(_docker("info", "--format", "{{json .}}"))
    return {key: info.get(key) for key in ("ServerVersion", "OperatingSystem", "KernelVersion", "Architecture", "NCPU",
                                           "MemTotal", "Driver", "CgroupVersion", "Name")}


def image(reference):
    """Identity of a local image plus the in-image probe."""
    inspected = json.loads(_docker("image", "inspect", reference))[0]
    output = _docker("run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
                     "--tmpfs", "/tmp:rw,size=8m", "-v", str(ROOT / "tools") + ":/eg-tools:ro",
                     "--entrypoint", "python", inspected["Id"], "/eg-tools/evidence.py", "probe")
    inside = json.loads(output.strip().splitlines()[-1])
    return {"reference": reference, "id": inspected["Id"], "tags": inspected.get("RepoTags") or [],
            "repo_digests": inspected.get("RepoDigests") or [], "created": inspected.get("Created"),
            "architecture": inspected.get("Architecture"), "os": inspected.get("Os"),
            "installed_package": inside["installed_package"], "dependencies": inside["dependencies"],
            "os_packages": inside["os_packages"], "runtime": inside["environment"]}


def header(report, *, configurations=(), image_info=None, lock=None, extra=None, probe_info=None):
    """``probe_info``: the probe of another interpreter that ran the tested code."""
    source = image_info or probe_info
    installed = source["installed_package"] if source else installed_package()
    inventory = source["dependencies"] if source else distributions()
    lock = lock or (ROOT / ("dist/vendor-linux-musl-arm64/requirements.txt" if image_info else
                            "deployment/requirements-linux-arm64.txt"))
    result = {"schema": SCHEMA, "report": report,
              "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "candidate": candidate(installed=installed), "image": image_info,
              "configuration": list(configurations),
              "dependencies": {**inventory, "lock": lock_comparison(
                  inventory, lock, allowed_absent=("pip",) if image_info else ())},
              "revision": revision(), "environment": environment()}
    if image_info is not None:
        try:
            result["environment"]["docker_engine"] = docker_engine()
        except Exception:
            result["environment"]["docker_engine"] = None
    if extra:
        result.update(extra)
    return result


def test_counts(records, skip_reasons):
    """Explicit counts: executed is not passed when tests are skipped."""
    counts = {"executed": len(records)}
    for state in ("passed", "skipped", "failed", "error", "expected_failure", "unexpected_success"):
        counts[state] = sum(value == state for value in records.values())
    counts["summary"] = "%d passed, %d skipped, %d failed, %d errors (%d executed)" % (
        counts["passed"], counts["skipped"], counts["failed"], counts["error"], counts["executed"])
    return {"counts": counts, "skipped_tests": dict(sorted(skip_reasons.items()))}


if __name__ == "__main__":
    if sys.argv[1:] == ["probe"]:
        print(json.dumps(probe(), sort_keys=True))
    elif sys.argv[1:2] == ["image"]:
        print(json.dumps({"image": image(sys.argv[2]), "docker_engine": docker_engine()}, sort_keys=True))
    else:
        raise SystemExit("usage: evidence.py probe | image <reference>")
