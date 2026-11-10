from importlib.resources import files
import json
import unittest


class CoverageTests(unittest.TestCase):
    def test_all_twenty_categories_have_scoped_evidence_without_full_acceptance(self):
        data = json.loads(files("enkstein_guard").joinpath("coverage.json").read_text())
        rows = data["requirements"]
        expected = {f"{prefix}{i:02d}:2026" for prefix in ("LLM", "ASI") for i in range(1, 11)}
        self.assertEqual({row["id"] for row in rows}, expected)
        self.assertEqual(len(rows), 20)
        for row in rows:
            self.assertIn(row["status"], {"scoped_evidence_only", "gap_confirmed"})
            self.assertFalse(row["full_category_acceptance"])
            self.assertTrue(row["executed_tests"])
            self.assertTrue(row["acceptance_test_id"])
        self.assertTrue(data["mitre_atlas"]["techniques"])
        self.assertEqual(data["evidence"]["gate"], "blocked_known_gaps")
