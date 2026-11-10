import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = ROOT / "tools" / "profile_security_history.py"
SPEC = importlib.util.spec_from_file_location("profile_security_history", TOOL_PATH)
profiler = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = profiler
SPEC.loader.exec_module(profiler)


class SecurityHistoryProfilePlanTests(unittest.TestCase):
    def test_default_is_plan_only_and_allocates_no_store_or_output(self):
        output = io.StringIO()
        with (mock.patch.object(
                profiler.tempfile, "TemporaryDirectory",
                side_effect=AssertionError("temporary store forbidden in plan mode")),
              mock.patch.object(
                  profiler.SecurityHistoryStore, "initialize",
                  side_effect=AssertionError("store initialization forbidden in plan mode")),
              redirect_stdout(output)):
            self.assertEqual(profiler.main([]), 0)

        plan = json.loads(output.getvalue())
        self.assertEqual(plan["schema"], profiler.PLAN_SCHEMA)
        self.assertEqual(plan["mode"], "plan")
        self.assertFalse(plan["acceptance_eligible"])
        self.assertEqual(plan["parameters"]["history_records"], 2_048)
        self.assertEqual(plan["request_counts"], {
            "recent": 8, "record": 8, "total": 16,
        })
        self.assertFalse(plan["side_effects_performed"]["temporary_store_created"])
        self.assertFalse(plan["side_effects_performed"]["output_created"])

    def test_parameter_bounds_are_strict(self):
        invalid = (
            {"actors": 0}, {"actors": 17}, {"actors": True},
            {"per_actor_history": 15}, {"per_actor_history": 257},
            {"per_actor_history": True},
            {"iterations": 0}, {"iterations": 101}, {"iterations": True},
            {"bulk_seed": 1},
        )
        for changes in invalid:
            values = {
                "actors": 2, "per_actor_history": 16,
                "iterations": 1, "bulk_seed": False, **changes,
            }
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                profiler.ProfileParameters(**values)

    def test_plan_records_bulk_seed_scope_and_exact_counts(self):
        parameters = profiler.ProfileParameters(
            actors=16, per_actor_history=256, iterations=100, bulk_seed=True,
        )
        plan = profiler.build_plan(parameters, Path("synthetic-output"))
        self.assertEqual(plan["parameters"]["history_records"], 4_096)
        self.assertEqual(plan["request_counts"], {
            "recent": 1_600, "record": 1_600, "total": 3_200,
        })
        self.assertEqual(
            plan["fixture"]["construction"], "authenticated_sqlite_bulk_seed")
        self.assertIn("--bulk-seed", plan["arguments"])
        self.assertFalse(plan["scope_limits"]["network"])
        self.assertFalse(plan["scope_limits"]["deployment"])

    def test_explicit_run_builds_and_profiles_tiny_verified_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "profile-output"
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(profiler.main([
                    "--run", "--actors", "2", "--per-actor-history", "16",
                    "--iterations", "1", "--output-dir", str(output_dir),
                ]), 0)
            report = json.loads(output.getvalue())
            stored = json.loads((output_dir / profiler.REPORT_NAME).read_text())

            self.assertEqual(report, stored)
            self.assertEqual(report["fixture_verification"]["records"], 32)
            self.assertEqual(report["final_verification"]["records"], 32)
            self.assertEqual(report["profiled_request_counts"], {
                "recent": 2, "record": 2, "total": 4,
            })
            self.assertTrue((output_dir / profiler.PROFILE_NAME).is_file())
            self.assertTrue(report["top_functions"])
            self.assertIn("security_context_sha256", report["source"])
            self.assertIn(report["source"]["location_kind"], {
                "source_tree", "installed_distribution",
            })

    def test_report_omits_synthetic_context_and_payload_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "profile-output"
            profiler.execute(
                profiler.ProfileParameters(actors=1, per_actor_history=16),
                output_dir,
            )
            report_text = (output_dir / profiler.REPORT_NAME).read_text()
            for forbidden in (
                    "synthetic-tenant", "synthetic-principal", "synthetic-agent",
                    "synthetic-operation", '"payload"', '"key"', "token"):
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden, report_text)

    def test_bulk_seed_run_is_still_fully_verified_before_profiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = profiler.execute(
                profiler.ProfileParameters(
                    actors=1, per_actor_history=16, iterations=1, bulk_seed=True,
                ),
                Path(temporary) / "bulk-profile-output",
            )
        self.assertEqual(report["plan"]["fixture"]["construction"],
                         "authenticated_sqlite_bulk_seed")
        self.assertEqual(report["fixture_verification"], {
            "status": "verified", "records": 16,
        })
        self.assertEqual(report["final_verification"], {
            "status": "verified", "records": 16,
        })

    def test_existing_output_is_rejected_before_store_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "existing"
            output_dir.mkdir()
            with (mock.patch.object(
                    profiler.tempfile, "TemporaryDirectory",
                    side_effect=AssertionError("must reject before allocation")),
                  self.assertRaises(FileExistsError)):
                profiler.execute(profiler.ProfileParameters(
                    actors=1, per_actor_history=16), output_dir)


if __name__ == "__main__":
    unittest.main()
