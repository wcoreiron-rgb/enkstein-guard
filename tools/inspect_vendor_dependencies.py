#!/usr/bin/env python3
"""Inventory installed optional vendor SDK dependency metadata without imports.

The inventory is deliberately based on ``importlib.metadata``.  It never imports
the SDK packages whose deployment feasibility it is evaluating and it performs
no package resolution, installation, download, or network access.
"""

from __future__ import annotations

import argparse
import ast
import importlib.metadata as metadata
import ipaddress
import json
import os
import platform
import re
import sys
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

SCHEMA_VERSION = 1
EXPECTED_ROOTS = {
    "agent-governance-toolkit-control-plane": "5.0.0",
    "agent-governance-toolkit": "4.1.0",
    "nemoguardrails": "0.24.1",
    "cisco-aidefense-sdk": "2.2.0",
}
SELECTED_ADAPTER_ROOTS = (
    "agent-governance-toolkit-control-plane",
    "nemoguardrails",
    "cisco-aidefense-sdk",
)
COMPARISON_ONLY_ROOTS = ("agent-governance-toolkit",)
EXPECTED_AGT_COMMIT = "86db4607dcb67e5dbe48b885bc535f77be5e244d"
TARGET_PYTHON = "3.12"
TARGET_PLATFORM = "Linux/Alpine (musl), ARM64"
CORE_REQUIREMENTS = ("cryptography>=50.0.2,<51",)
_NORMALIZE_RE = re.compile(r"[-_.]+")
_SAFE_SUBDIRECTORY_RE = re.compile(r"[A-Za-z0-9._/+\-]+")
_REQUIREMENT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"\s*(?:\[(?P<extras>[^]]*)\])?\s*(?P<specifier>.*)$"
)
_MARKER_TOKEN_RE = re.compile(
    r"\s*(<=|>=|==|!=|~=|===|<|>|\(|\)|\bnot\b|\bin\b|\band\b|\bor\b|"
    r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[A-Za-z_][A-Za-z0-9_.-]*)"
)
_EMBEDDED_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s;)\]]+")
_DIRECT_REQUIREMENT_URL_RE = re.compile(
    r"^(?P<prefix>.*?@\s*)(?P<url>[A-Za-z][A-Za-z0-9+.-]*://\S+)"
    r"(?P<suffix>\s+;\s*.*)?$"
)


@dataclass(frozen=True)
class ParsedRequirement:
    name: str
    extras: frozenset[str]
    specifier: str
    marker: str | None


class RequirementParseError(ValueError):
    pass


def default_environment() -> dict[str, str]:
    """Return the standard marker variables using only the Python stdlib."""

    implementation_version = platform.python_version()
    return {
        "implementation_name": sys.implementation.name,
        "implementation_version": implementation_version,
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_python_implementation": platform.python_implementation(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "sys_platform": sys.platform,
    }


def parse_requirement(raw: str) -> ParsedRequirement:
    """Parse the bounded Requires-Dist shape needed for metadata traversal."""

    if "@" in raw and "://" in raw:
        direct_parts = re.split(r"\s+;\s*", raw, maxsplit=1)
        requirement_text = direct_parts[0]
        separator = ";" if len(direct_parts) == 2 else ""
        marker = direct_parts[1] if len(direct_parts) == 2 else ""
    else:
        requirement_text, separator, marker = raw.partition(";")
    match = _REQUIREMENT_RE.fullmatch(requirement_text)
    if match is None:
        raise RequirementParseError("unsupported-requirement-shape")
    specifier = match.group("specifier").strip()
    if specifier.startswith("(") and specifier.endswith(")"):
        specifier = specifier[1:-1].strip()
    extras = frozenset(
        normalize_name(value.strip())
        for value in (match.group("extras") or "").split(",")
        if value.strip()
    )
    return ParsedRequirement(
        name=match.group("name"),
        extras=extras,
        specifier=specifier,
        marker=marker.strip() if separator and marker.strip() else None,
    )


def _marker_tokens(marker: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(marker):
        match = _MARKER_TOKEN_RE.match(marker, position)
        if match is None:
            raise ValueError("unsupported-marker-token")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


def _version_key(value: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)*)", value)
    if match is None:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


class _MarkerParser:
    def __init__(self, marker: str, environment: Mapping[str, str]) -> None:
        self.tokens = _marker_tokens(marker)
        self.position = 0
        self.environment = environment

    def parse(self) -> bool:
        value = self._or_expression()
        if self.position != len(self.tokens):
            raise ValueError("trailing-marker-tokens")
        return value

    def _or_expression(self) -> bool:
        value = self._and_expression()
        while self._peek() == "or":
            self.position += 1
            right = self._and_expression()
            value = value or right
        return value

    def _and_expression(self) -> bool:
        value = self._factor()
        while self._peek() == "and":
            self.position += 1
            right = self._factor()
            value = value and right
        return value

    def _factor(self) -> bool:
        if self._peek() == "(":
            self.position += 1
            value = self._or_expression()
            self._expect(")")
            return value
        left_token = self._take()
        operator = self._take()
        if operator == "not":
            self._expect("in")
            operator = "not in"
        right_token = self._take()
        left, left_is_version = self._value(left_token)
        right, right_is_version = self._value(right_token)
        if operator in {"in", "not in"}:
            result = left in right
            return not result if operator == "not in" else result
        if operator not in {"==", "!=", "<", "<=", ">", ">=", "~=", "==="}:
            raise ValueError("unsupported-marker-operator")
        if operator == "~=":
            raise ValueError("unsupported-compatible-release-marker")
        if left_is_version or right_is_version:
            if operator in {"==", "!="} and (left.endswith(".*") or right.endswith(".*")):
                if left.endswith(".*"):
                    result = right == left[:-2] or right.startswith(f"{left[:-2]}.")
                else:
                    result = left == right[:-2] or left.startswith(f"{right[:-2]}.")
                return not result if operator == "!=" else result
            left_key = _version_key(left)
            right_key = _version_key(right)
            if left_key is None or right_key is None:
                raise ValueError("unsupported-marker-version")
            left_value: object = left_key
            right_value: object = right_key
        else:
            left_value = left
            right_value = right
        if operator in {"==", "==="}:
            return left_value == right_value
        if operator == "!=":
            return left_value != right_value
        if operator == "<":
            return left_value < right_value
        if operator == "<=":
            return left_value <= right_value
        if operator == ">":
            return left_value > right_value
        if operator == ">=":
            return left_value >= right_value
        raise AssertionError("unreachable-marker-operator")

    def _value(self, token: str) -> tuple[str, bool]:
        if token[:1] in {"'", '"'}:
            value = ast.literal_eval(token)
            if not isinstance(value, str):
                raise ValueError("non-string-marker-literal")
            return value, False
        if token not in self.environment:
            raise ValueError(f"unknown-marker-variable:{token}")
        return self.environment[token], token.endswith("_version") or token in {
            "python_version",
            "python_full_version",
            "implementation_version",
        }

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("incomplete-marker")
        self.position += 1
        return token

    def _expect(self, expected: str) -> None:
        if self._take() != expected:
            raise ValueError(f"expected-{expected}")


def normalize_name(name: str) -> str:
    """Return the PEP 503 normalized distribution name."""

    return _NORMALIZE_RE.sub("-", name).lower()


def _hostname_is_safe(hostname: str | None) -> bool:
    if not hostname:
        return False
    lowered = hostname.rstrip(".").lower()
    if lowered == "localhost" or lowered.endswith((".local", ".localhost")):
        return False
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        # Package metadata intentionally publishes source/documentation FQDNs.
        return "." in lowered
    return address.is_global


def sanitize_origin(url: str) -> str:
    """Return a credential/query-free public origin or a redacted sentinel."""

    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return "<redacted-invalid-origin>"
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "git+http", "git+https"}:
        return f"{scheme or 'unknown'}://<redacted>"
    if not _hostname_is_safe(parsed.hostname):
        return f"{scheme}://<redacted>"
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        port = ""
    # User info, query parameters, and fragments are never retained.
    return urlunsplit((scheme, f"{hostname}{port}", parsed.path or "", "", ""))


def sanitize_requirement_evidence(value: str) -> str:
    """Redact any URL embedded in a Requires-Dist evidence string."""

    direct = _DIRECT_REQUIREMENT_URL_RE.fullmatch(value)
    if direct is not None:
        return (
            f"{direct.group('prefix')}{sanitize_origin(direct.group('url'))}"
            f"{direct.group('suffix') or ''}"
        )
    return _EMBEDDED_URL_RE.sub(
        lambda match: sanitize_origin(match.group(0)),
        value,
    )


def _safe_subdirectory(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if (
        value.startswith("/")
        or ".." in value.split("/")
        or not _SAFE_SUBDIRECTORY_RE.fullmatch(value)
    ):
        return "<redacted>"
    return value


def sanitize_direct_url(raw: str | None) -> dict[str, object] | None:
    """Parse direct_url.json while retaining only non-secret provenance facts."""

    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {"error": "invalid-direct-url-json"}
    if not isinstance(value, dict):
        return {"error": "invalid-direct-url-shape"}

    result: dict[str, object] = {}
    if isinstance(value.get("url"), str):
        result["url"] = sanitize_origin(value["url"])
    vcs_info = value.get("vcs_info")
    if isinstance(vcs_info, dict):
        result["vcs_info"] = {
            key: item
            for key in ("vcs", "requested_revision", "commit_id")
            if isinstance((item := vcs_info.get(key)), str)
        }
    archive_info = value.get("archive_info")
    if isinstance(archive_info, dict):
        safe_archive: dict[str, object] = {}
        if isinstance(archive_info.get("hash"), str):
            safe_archive["hash"] = archive_info["hash"]
        if isinstance(archive_info.get("hashes"), dict):
            safe_archive["hashes"] = {
                str(key): str(item)
                for key, item in archive_info["hashes"].items()
                if isinstance(key, str) and isinstance(item, str)
            }
        result["archive_info"] = safe_archive
    if "subdirectory" in value:
        result["subdirectory"] = _safe_subdirectory(value["subdirectory"])
    dir_info = value.get("dir_info")
    if isinstance(dir_info, dict):
        result["dir_info"] = {"editable": bool(dir_info.get("editable", False))}
    return result


def _metadata_values(dist: metadata.Distribution, field: str) -> list[str]:
    get_all = getattr(dist.metadata, "get_all", None)
    values = get_all(field) if callable(get_all) else None
    return [str(value) for value in (values or [])]


def _license_facts(dist: metadata.Distribution) -> dict[str, object]:
    license_value = dist.metadata.get("License")
    # Some legacy License fields contain the whole license text.  Do not copy it.
    if isinstance(license_value, str) and len(license_value) > 200:
        license_value = "<long-license-text-omitted>"
    return {
        "expression": dist.metadata.get("License-Expression"),
        "license": license_value,
        "classifiers": [
            value
            for value in _metadata_values(dist, "Classifier")
            if value.startswith("License ::")
        ],
        "files": _metadata_values(dist, "License-File"),
    }


def _project_origins(dist: metadata.Distribution) -> list[dict[str, str]]:
    origins: list[dict[str, str]] = []
    home_page = dist.metadata.get("Home-page")
    if isinstance(home_page, str) and home_page.strip():
        origins.append({"label": "Home-page", "url": sanitize_origin(home_page)})
    for value in _metadata_values(dist, "Project-URL"):
        label, separator, url = value.partition(",")
        if separator and url.strip():
            origins.append({"label": label.strip(), "url": sanitize_origin(url.strip())})
    return origins


def _wheel_tags(dist: metadata.Distribution) -> list[str]:
    wheel = dist.read_text("WHEEL") or ""
    return sorted(
        {line.partition(":")[2].strip() for line in wheel.splitlines() if line.startswith("Tag:")}
    )


def _native_tags(tags: Sequence[str]) -> list[str]:
    native: list[str] = []
    for tag in tags:
        parts = tag.rsplit("-", 2)
        if len(parts) == 3 and parts[2] != "any":
            native.append(tag)
    return native


@dataclass(frozen=True)
class DistributionIndex:
    unique: Mapping[str, metadata.Distribution]
    duplicates: Mapping[str, tuple[metadata.Distribution, ...]]


def index_distributions(distributions: Iterable[metadata.Distribution]) -> DistributionIndex:
    """Index installed metadata and surface ambiguous normalized duplicates."""

    grouped: dict[str, list[metadata.Distribution]] = {}
    for dist in distributions:
        name = dist.metadata.get("Name")
        if isinstance(name, str) and name.strip():
            grouped.setdefault(normalize_name(name), []).append(dist)
    unique = {name: values[0] for name, values in grouped.items() if len(values) == 1}
    duplicates = {
        name: tuple(values) for name, values in grouped.items() if len(values) > 1
    }
    return DistributionIndex(unique=unique, duplicates=duplicates)


def marker_applies(
    requirement: ParsedRequirement,
    environment: Mapping[str, str],
    active_extras: Iterable[str] = (),
) -> bool | None:
    """Evaluate a requirement marker for base install plus requested extras."""

    marker = requirement.marker
    if marker is None:
        return True
    extras = {"", *(str(extra) for extra in active_extras)}
    try:
        for extra in extras:
            marker_environment = dict(environment)
            marker_environment["extra"] = extra
            if _MarkerParser(marker, marker_environment).parse():
                return True
        return False
    except (SyntaxError, ValueError):
        return None


def _specifier_contains(specifier: str, version: str) -> tuple[bool | None, str | None]:
    if not specifier:
        return True, None
    if specifier.lstrip().startswith("@"):
        return None, "direct-url-requirement-not-version-evaluated"
    try:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
    except ModuleNotFoundError:
        return None, "pep440-evaluator-unavailable"
    try:
        return SpecifierSet(specifier).contains(version, prereleases=True), None
    except InvalidSpecifier:
        return None, "invalid-or-unsupported-specifier"


def _python_compatibility(specifier: str | None, target_python: str) -> bool | None:
    if not specifier:
        return None
    value, _reason = _specifier_contains(specifier, target_python)
    return value


def _dist_record(dist: metadata.Distribution, target_python: str) -> dict[str, object]:
    name = str(dist.metadata.get("Name") or "")
    tags = _wheel_tags(dist)
    requires_python = dist.metadata.get("Requires-Python")
    return {
        "name": name,
        "normalized_name": normalize_name(name),
        "version": dist.version,
        "requires_python": requires_python,
        "target_python_compatible": _python_compatibility(requires_python, target_python),
        "wheel_tags": tags,
        "native_platform_tags": _native_tags(tags),
        "license": _license_facts(dist),
        "origins": _project_origins(dist),
        "direct_url": sanitize_direct_url(dist.read_text("direct_url.json")),
    }


def dependency_closure(
    index: DistributionIndex,
    roots: Sequence[tuple[str, Iterable[str]]],
    environment: Mapping[str, str] | None = None,
    target_python: str = TARGET_PYTHON,
) -> dict[str, object]:
    """Build the active installed closure and retain all declared marker edges."""

    marker_environment = dict(environment or default_environment())
    queue: deque[tuple[str, frozenset[str], str | None]] = deque(
        (normalize_name(name), frozenset(extras), None) for name, extras in roots
    )
    processed_extras: dict[str, frozenset[str]] = {}
    packages: dict[str, dict[str, object]] = {}
    requirements: dict[tuple[str, str], dict[str, object]] = {}
    missing: dict[tuple[str, str], dict[str, object]] = {}
    ambiguous: dict[str, dict[str, object]] = {}
    unresolved_markers: dict[tuple[str, str], dict[str, object]] = {}

    while queue:
        name, requested_extras, requested_by = queue.popleft()
        if name in index.duplicates:
            ambiguous[name] = {
                "normalized_name": name,
                "requested_by": requested_by,
                "candidates": sorted(
                    {
                        f"{dist.metadata.get('Name')}=={dist.version}"
                        for dist in index.duplicates[name]
                    }
                ),
            }
            continue
        dist = index.unique.get(name)
        if dist is None:
            missing[(requested_by or "<root>", name)] = {
                "normalized_name": name,
                "requested_by": requested_by,
            }
            continue

        previous = processed_extras.get(name, frozenset())
        combined = previous | requested_extras
        if name in processed_extras and combined == previous:
            continue
        processed_extras[name] = combined
        packages[name] = _dist_record(dist, target_python)
        packages[name]["active_extras"] = sorted(combined)

        for raw in dist.requires or []:
            safe_raw = sanitize_requirement_evidence(raw)
            try:
                requirement = parse_requirement(raw)
            except RequirementParseError as exc:
                requirements[(name, raw)] = {
                    "from": name,
                    "raw": safe_raw,
                    "parse_error": type(exc).__name__,
                    "applies_to_marker_environment": None,
                }
                continue
            dependency_name = normalize_name(requirement.name)
            applies = marker_applies(requirement, marker_environment, combined)
            installed = index.unique.get(dependency_name)
            version_satisfied = None
            version_satisfaction_error = None
            if installed is not None:
                version_satisfied, version_satisfaction_error = _specifier_contains(
                    requirement.specifier, installed.version
                )
            edge = {
                "from": name,
                "to": dependency_name,
                "raw": safe_raw,
                "specifier": sanitize_requirement_evidence(requirement.specifier),
                "marker": requirement.marker,
                "requested_extras": sorted(requirement.extras),
                "applies_to_marker_environment": applies,
                "installed_version": installed.version if installed is not None else None,
                "installed_version_satisfies": version_satisfied,
                "installed_version_satisfaction_error": version_satisfaction_error,
            }
            requirements[(name, raw)] = edge
            if applies is None:
                unresolved_markers[(name, raw)] = {
                    "from": name,
                    "raw": safe_raw,
                    "marker": requirement.marker,
                    "reason": "unsupported-or-invalid-marker",
                }
            elif applies:
                if installed is None and dependency_name not in index.duplicates:
                    missing[(name, dependency_name)] = {
                        "normalized_name": dependency_name,
                        "requested_by": name,
                        "requirement": safe_raw,
                    }
                else:
                    queue.append((dependency_name, frozenset(requirement.extras), name))

    return {
        "marker_environment": marker_environment,
        "packages": {name: packages[name] for name in sorted(packages)},
        "requirements": [requirements[key] for key in sorted(requirements)],
        "missing_dependencies": [missing[key] for key in sorted(missing)],
        "ambiguous_distributions": [ambiguous[key] for key in sorted(ambiguous)],
        "unresolved_markers": [
            unresolved_markers[key] for key in sorted(unresolved_markers)
        ],
    }


def _root_facts(
    index: DistributionIndex,
) -> list[dict[str, object]]:
    facts: list[dict[str, object]] = []
    for root, expected_version in EXPECTED_ROOTS.items():
        root_closure = dependency_closure(index, [(root, ())])
        root_packages = root_closure["packages"]
        assert isinstance(root_packages, dict)
        native_dependencies = sorted(
            name
            for name, value in root_packages.items()
            if isinstance(value, dict) and value.get("native_platform_tags")
        )
        dist = index.unique.get(root)
        duplicate = root in index.duplicates
        record = root_packages.get(root)
        installed_version = dist.version if dist is not None else None
        source_pin_matches: bool | None = None
        if root == "agent-governance-toolkit-control-plane" and isinstance(record, dict):
            direct_url = record.get("direct_url")
            serialized = json.dumps(direct_url, sort_keys=True)
            source_pin_matches = EXPECTED_AGT_COMMIT in serialized
        facts.append(
            {
                "name": root,
                "inventory_role": (
                    "selected-adapter-distribution"
                    if root in SELECTED_ADAPTER_ROOTS
                    else "distinct-umbrella-comparison-only"
                ),
                "expected_version": expected_version,
                "installed_version": installed_version,
                "installed_once": dist is not None and not duplicate,
                "version_matches_expected": installed_version == expected_version,
                "requires_python": record.get("requires_python") if isinstance(record, dict) else None,
                "target_python_compatible": record.get("target_python_compatible") if isinstance(record, dict) else None,
                "source_pin_matches_expected": source_pin_matches,
                "active_closure_package_count": len(root_packages),
                "active_closure_packages": sorted(root_packages),
                "closure_native_platform_dependencies": native_dependencies,
                "closure_missing_dependencies": root_closure["missing_dependencies"],
                "closure_unresolved_markers": root_closure["unresolved_markers"],
            }
        )
    return facts


def build_inventory(
    distributions: Iterable[metadata.Distribution] | None = None,
    argv: Sequence[str] | None = None,
) -> dict[str, object]:
    installed = list(distributions if distributions is not None else metadata.distributions())
    index = index_distributions(installed)
    environment = default_environment()
    roots = [(name, ()) for name in EXPECTED_ROOTS]
    closure = dependency_closure(index, roots, environment=environment)
    selected_closure = dependency_closure(
        index,
        [(name, ()) for name in SELECTED_ADAPTER_ROOTS],
        environment=environment,
    )
    target_environment = dict(environment)
    target_environment.update(
        {
            "implementation_name": "cpython",
            "implementation_version": "3.12.0",
            "os_name": "posix",
            "platform_machine": "aarch64",
            "platform_python_implementation": "CPython",
            "platform_release": "<target-release-unspecified>",
            "platform_system": "Linux",
            "platform_version": "<target-version-unspecified>",
            "python_full_version": "3.12.0",
            "python_version": TARGET_PYTHON,
            "sys_platform": "linux",
        }
    )
    target_closure = dependency_closure(
        index,
        [(name, ()) for name in SELECTED_ADAPTER_ROOTS],
        environment=target_environment,
    )
    target_packages = target_closure["packages"]
    assert isinstance(target_packages, dict)

    native_packages = sorted(
        {
            name
            for name, value in target_packages.items()
            if isinstance(value, dict) and value.get("native_platform_tags")
        }
    )
    incompatible = sorted(
        {
            name
            for name, value in target_packages.items()
            if isinstance(value, dict) and value.get("target_python_compatible") is False
        }
    )
    unknown_python = sorted(
        {
            name
            for name, value in target_packages.items()
            if isinstance(value, dict) and value.get("target_python_compatible") is None
        }
    )
    core_names = {normalize_name(parse_requirement(item).name) for item in CORE_REQUIREMENTS}
    additional = sorted(name for name in target_packages if name not in core_names)

    implementation = platform.python_implementation()
    libc_name, libc_version = platform.libc_ver()
    evidence: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": {
            "metadata_api": "importlib.metadata",
            "requirement_parser": "stdlib-bounded",
            "marker_evaluator": "stdlib-bounded; unresolved expressions are explicit",
            "pep440_evaluator": "packaging when already installed; otherwise explicit unknown",
            "sdk_modules_imported": False,
            "network_access": False,
            "resolver_or_installer_run": False,
        },
        "invocation": {
            "argv": list(argv if argv is not None else sys.argv),
            "executable": sys.executable,
        },
        "inventory_runtime": {
            "python_implementation": implementation,
            "python_version": platform.python_version(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "libc": {"name": libc_name or None, "version": libc_version or None},
            "marker_environment": environment,
        },
        "deployment_target": {
            "python_version": TARGET_PYTHON,
            "platform": TARGET_PLATFORM,
            "core_requirements_only": list(CORE_REQUIREMENTS),
            "optional_vendor_distributions_present_in_core": False,
        },
        "roots": _root_facts(index),
        "closure": closure,
        "selected_adapter_target_marker_projection": target_closure,
        "deployment_facts": {
            "selected_adapter_roots": list(SELECTED_ADAPTER_ROOTS),
            "comparison_only_roots": list(COMPARISON_ONLY_ROOTS),
            "selected_adapter_target_marker_package_count": len(target_packages),
            "additional_distributions_required_beyond_core": additional,
            "target_python_incompatible_installed_versions": incompatible,
            "target_python_compatibility_undeclared": unknown_python,
            "installed_native_platform_distributions": native_packages,
            "local_native_artifacts_are_target_evidence": False,
            "target_linux_musl_arm64_artifact_availability_tested": False,
            "target_install_or_import_tested": False,
            "target_projection_unresolved_markers": target_closure["unresolved_markers"],
            "optional_contract_tests_prove_target_deployability": False,
        },
        "duplicate_installed_distributions": {
            name: sorted(
                f"{dist.metadata.get('Name')}=={dist.version}"
                for dist in distributions_for_name
            )
            for name, distributions_for_name in sorted(index.duplicates.items())
        },
    }
    return evidence


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="JSON evidence output path (created atomically via a temporary sibling)",
    )
    parser.add_argument(
        "--strict-roots",
        action="store_true",
        help="return nonzero after writing evidence if an expected root/version is absent",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    evidence = build_inventory(argv=[sys.argv[0], *(argv if argv is not None else sys.argv[1:])])
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(f"{output.suffix}.tmp")
    temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    roots = evidence["roots"]
    assert isinstance(roots, list)
    failures = [
        item
        for item in roots
        if not item["installed_once"] or not item["version_matches_expected"]
    ]
    if failures:
        print(f"inventory written with {len(failures)} root mismatch(es): {output}")
        return 1 if args.strict_roots else 0
    print(f"inventory written: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
