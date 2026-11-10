from __future__ import annotations

import sys
import unittest
from unittest import mock
from email.message import Message
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import inspect_vendor_dependencies as inventory  # noqa: E402


class SyntheticDistribution:
    def __init__(
        self,
        name: str,
        version: str,
        *,
        requires: list[str] | None = None,
        requires_python: str | None = ">=3.10",
        files: dict[str, str] | None = None,
    ) -> None:
        metadata = Message()
        metadata["Name"] = name
        metadata["Version"] = version
        if requires_python is not None:
            metadata["Requires-Python"] = requires_python
        metadata["License-Expression"] = "MIT"
        self.metadata = metadata
        self.version = version
        self.requires = requires or []
        self._files = {"WHEEL": "Wheel-Version: 1.0\nTag: py3-none-any\n", **(files or {})}

    def read_text(self, filename: str) -> str | None:
        return self._files.get(filename)


def marker_environment(**updates: str) -> dict[str, str]:
    value = inventory.default_environment()
    value.update(updates)
    return value


class DependencyClosureTests(unittest.TestCase):
    def test_walks_active_transitive_dependencies_and_preserves_markers(self) -> None:
        root = SyntheticDistribution(
            "Root.SDK",
            "1.0",
            requires=[
                "Middle>=2",
                'legacy-only; python_version < "3.0"',
            ],
        )
        middle = SyntheticDistribution("middle", "2.1", requires=["Leaf==3"])
        leaf = SyntheticDistribution("leaf", "3")
        index = inventory.index_distributions([root, middle, leaf])

        result = inventory.dependency_closure(
            index,
            [("root-sdk", ())],
            environment=marker_environment(python_version="3.11"),
        )

        self.assertEqual(list(result["packages"]), ["leaf", "middle", "root-sdk"])
        legacy = next(
            edge for edge in result["requirements"] if edge.get("to") == "legacy-only"
        )
        self.assertFalse(legacy["applies_to_marker_environment"])
        middle_edge = next(
            edge for edge in result["requirements"] if edge.get("to") == "middle"
        )
        self.assertIn(middle_edge["installed_version_satisfies"], (True, None))
        if middle_edge["installed_version_satisfies"] is None:
            self.assertEqual(
                middle_edge["installed_version_satisfaction_error"],
                "pep440-evaluator-unavailable",
            )
        self.assertEqual(result["missing_dependencies"], [])

    def test_extra_marker_only_activates_for_requested_extra(self) -> None:
        root = SyntheticDistribution(
            "root",
            "1",
            requires=['feature-dep; extra == "feature"'],
        )
        feature = SyntheticDistribution("feature_dep", "1")
        index = inventory.index_distributions([root, feature])

        base = inventory.dependency_closure(index, [("root", ())])
        enabled = inventory.dependency_closure(index, [("root", ("feature",))])

        self.assertNotIn("feature-dep", base["packages"])
        self.assertIn("feature-dep", enabled["packages"])
        edge = enabled["requirements"][0]
        self.assertEqual(edge["marker"], 'extra == "feature"')
        self.assertTrue(edge["applies_to_marker_environment"])

    def test_python_full_version_wildcard_marker_is_bounded_and_explicit(self) -> None:
        root = SyntheticDistribution(
            "root",
            "1",
            requires=[
                'target-dep; python_full_version == "3.12.*"',
                'other-dep; python_full_version == "3.11.*"',
            ],
        )
        target = SyntheticDistribution("target-dep", "1")
        other = SyntheticDistribution("other-dep", "1")

        result = inventory.dependency_closure(
            inventory.index_distributions([root, target, other]),
            [("root", ())],
            environment=marker_environment(
                python_version="3.12", python_full_version="3.12.0"
            ),
        )

        self.assertIn("target-dep", result["packages"])
        self.assertNotIn("other-dep", result["packages"])
        self.assertEqual(result["unresolved_markers"], [])

    def test_numeric_marker_comparison_normalizes_trailing_zero_components(self) -> None:
        environment = marker_environment(
            python_version="3.12", python_full_version="3.12"
        )
        equal = inventory.parse_requirement(
            'dep; python_full_version == "3.12.0"'
        )
        bounded = inventory.parse_requirement(
            'dep; python_full_version >= "3.12.0" and python_full_version < "3.12.1"'
        )

        self.assertTrue(inventory.marker_applies(equal, environment))
        self.assertTrue(inventory.marker_applies(bounded, environment))

    def test_compatible_release_marker_is_explicitly_unresolved(self) -> None:
        root = SyntheticDistribution(
            "root",
            "1",
            requires=['dep; python_version ~= "3.12.1"'],
        )
        dep = SyntheticDistribution("dep", "1")

        result = inventory.dependency_closure(
            inventory.index_distributions([root, dep]),
            [("root", ())],
            environment=marker_environment(python_version="3.12"),
        )

        self.assertNotIn("dep", result["packages"])
        self.assertIsNone(result["requirements"][0]["applies_to_marker_environment"])
        self.assertEqual(
            result["unresolved_markers"][0]["reason"],
            "unsupported-or-invalid-marker",
        )

    def test_records_active_missing_distribution(self) -> None:
        root = SyntheticDistribution("root", "1", requires=["not-installed>=4"])

        result = inventory.dependency_closure(
            inventory.index_distributions([root]), [("root", ())]
        )

        self.assertEqual(
            result["missing_dependencies"],
            [
                {
                    "normalized_name": "not-installed",
                    "requested_by": "root",
                    "requirement": "not-installed>=4",
                }
            ],
        )

    def test_empty_core_inventory_reports_optional_roots_missing_without_crash(self) -> None:
        result = inventory.build_inventory([], argv=["inspect_vendor_dependencies.py"])

        self.assertEqual(result["closure"]["packages"], {})
        self.assertEqual(len(result["roots"]), 4)
        self.assertTrue(all(not root["installed_once"] for root in result["roots"]))
        self.assertEqual(len(result["closure"]["missing_dependencies"]), 4)
        target_environment = result["selected_adapter_target_marker_projection"][
            "marker_environment"
        ]
        self.assertEqual(target_environment["implementation_name"], "cpython")
        self.assertEqual(target_environment["implementation_version"], "3.12.0")
        self.assertEqual(target_environment["platform_python_implementation"], "CPython")

    def test_direct_requirement_url_is_redacted_and_not_version_evidence(self) -> None:
        root = SyntheticDistribution(
            "root",
            "1",
            requires=[
                "dep @ https://user:token@github.com/vendor/dep.whl"
                "?signature=secret;second=value#sha256=abc"
            ],
        )
        dep = SyntheticDistribution("dep", "1")

        result = inventory.dependency_closure(
            inventory.index_distributions([root, dep]), [("root", ())]
        )
        edge = result["requirements"][0]

        self.assertEqual(edge["raw"], "dep @ https://github.com/vendor/dep.whl")
        self.assertEqual(edge["specifier"], "@ https://github.com/vendor/dep.whl")
        self.assertIsNone(edge["installed_version_satisfies"])
        self.assertEqual(
            edge["installed_version_satisfaction_error"],
            "direct-url-requirement-not-version-evaluated",
        )

    def test_normalized_duplicate_distributions_are_ambiguous(self) -> None:
        duplicate_one = SyntheticDistribution("Shared_Dep", "1")
        duplicate_two = SyntheticDistribution("shared-dep", "2")
        index = inventory.index_distributions([duplicate_one, duplicate_two])

        result = inventory.dependency_closure(index, [("shared.dep", ())])

        self.assertNotIn("shared-dep", index.unique)
        self.assertEqual(
            result["ambiguous_distributions"][0]["candidates"],
            ["Shared_Dep==1", "shared-dep==2"],
        )


class OriginSanitizationTests(unittest.TestCase):
    def test_removes_credentials_query_and_fragment(self) -> None:
        sanitized = inventory.sanitize_origin(
            "https://user:token@github.com/vendor/repo.git?access_token=secret#branch"
        )

        self.assertEqual(sanitized, "https://github.com/vendor/repo.git")
        self.assertNotIn("user", sanitized)
        self.assertNotIn("secret", sanitized)

    def test_redacts_local_direct_url_but_keeps_public_commit(self) -> None:
        local = inventory.sanitize_direct_url(
            '{"url":"file:///Users/person/private/repo","dir_info":{"editable":true}}'
        )
        public = inventory.sanitize_direct_url(
            "{"
            '"url":"https://name:secret@github.com/vendor/repo.git?token=x",'
            '"vcs_info":{"vcs":"git","commit_id":"abc123"}'
            "}"
        )

        self.assertEqual(local["url"], "file://<redacted>")
        self.assertEqual(local["dir_info"], {"editable": True})
        self.assertEqual(public["url"], "https://github.com/vendor/repo.git")
        self.assertEqual(public["vcs_info"]["commit_id"], "abc123")


class OptionalPep440Tests(unittest.TestCase):
    def test_missing_packaging_reports_unknown_instead_of_accepting(self) -> None:
        original_import = __import__

        def without_packaging(name, *args, **kwargs):
            if name == "packaging.specifiers":
                raise ModuleNotFoundError(name)
            return original_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=without_packaging):
            value, reason = inventory._specifier_contains(">=2", "2.1")

        self.assertIsNone(value)
        self.assertEqual(reason, "pep440-evaluator-unavailable")


if __name__ == "__main__":
    unittest.main()
