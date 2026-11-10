import asyncio
import hashlib
import json
import unittest

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.retrieval import check_grounding, grounding_control
from enkstein_guard.runtime import Operation


class StringSubclass(str):
    pass


class DictSubclass(dict):
    pass


class ListSubclass(list):
    pass


class HostileMode:
    def __eq__(self, other):
        raise AssertionError("invalid modes must not be compared")


class HostileKey:
    def __hash__(self):
        return hash("runbook")

    def __eq__(self, other):
        raise RuntimeError("malformed context key")


class ExtractiveGroundingTests(unittest.TestCase):
    def setUp(self):
        self.allowed = {
            "runbook": "Restart the ticket service during an outage. Keep the incident open.",
            "status": "The service is recovering.",
        }

    @staticmethod
    def response(*citations):
        return {"answer": "".join(item["quote"] for item in citations), "citations": list(citations)}

    def test_exact_authorized_spans_are_retained(self):
        value = self.response(
            {"doc_id": "runbook", "quote": "Restart the ticket service during an outage."},
            {"doc_id": "status", "quote": "The service is recovering."},
        )
        self.assertEqual(
            check_grounding(value, self.allowed, mode="extractive"),
            (True, "extractive_spans_verified"),
        )

    def test_real_citation_cannot_justify_invented_answer_prose(self):
        value = {
            "answer": "The incident is resolved.",
            "citations": [{"doc_id": "runbook", "quote": "Keep the incident open."}],
        }
        self.assertEqual(
            check_grounding(value, self.allowed, mode="extractive"),
            (False, "answer_not_source_extractive"),
        )

    def test_extra_fields_and_opaque_wrappers_are_rejected(self):
        quote = "Keep the incident open."
        valid = self.response({"doc_id": "runbook", "quote": quote})
        cases = [
            {**valid, "analysis": "Invented hidden prose"},
            {"provider_response": valid},
            {"answer": quote, "citations": [{"doc_id": "runbook", "quote": quote, "note": "hidden"}]},
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    check_grounding(value, self.allowed, mode="extractive"),
                    (False, "extractive_schema_invalid"),
                )

    def test_mixed_authorized_and_unauthorized_sources_are_rejected(self):
        value = self.response(
            {"doc_id": "runbook", "quote": "Keep the incident open."},
            {"doc_id": "other-tenant", "quote": "Do not release this."},
        )
        self.assertEqual(
            check_grounding(value, self.allowed, mode="extractive"),
            (False, "citation_not_in_retrieved_context"),
        )

    def test_malformed_empty_fabricated_and_oversized_values_are_rejected(self):
        malformed = [
            None,
            True,
            float("nan"),
            {"answer": "", "citations": []},
            {"answer": "x", "citations": [{"doc_id": "runbook", "quote": ""}]},
            {"answer": "x", "citations": [{"document_id": "runbook", "quote": "x"}]},
            {"answer": "x" * 17, "citations": [{"doc_id": "runbook", "quote": "x"}] * 17},
            {"answer": "\ud800", "citations": [{"doc_id": "runbook", "quote": "\ud800"}]},
            DictSubclass(answer="x", citations=[{"doc_id": "runbook", "quote": "x"}]),
            {"answer": StringSubclass("x"), "citations": [{"doc_id": "runbook", "quote": "x"}]},
            {"answer": "x", "citations": ListSubclass([{"doc_id": "runbook", "quote": "x"}])},
            {"answer": "x", "citations": [DictSubclass(doc_id="runbook", quote="x")]},
            {"answer": "x", "citations": [{"doc_id": StringSubclass("runbook"), "quote": "x"}]},
            {"answer": "x", "citations": [{"doc_id": "runbook", "quote": StringSubclass("x")}]},
        ]
        for value in malformed:
            with self.subTest(value=value):
                self.assertFalse(check_grounding(value, self.allowed, mode="extractive")[0])

        fabricated = self.response({"doc_id": "runbook", "quote": "The incident is resolved."})
        self.assertEqual(
            check_grounding(fabricated, self.allowed, mode="extractive"),
            (False, "quote_not_found_in_cited_document"),
        )
        oversized = "x" * 32_769
        self.assertEqual(
            check_grounding(
                {"answer": oversized, "citations": [{"doc_id": "runbook", "quote": oversized}]},
                {"runbook": oversized},
                mode="extractive",
            ),
            (False, "extractive_output_too_large"),
        )
        aggregate_only = "y" * 32_769
        self.assertEqual(
            check_grounding(
                {"answer": "y", "citations": [{"doc_id": "large", "quote": aggregate_only}]},
                {"large": aggregate_only},
                mode="extractive",
            ),
            (False, "extractive_output_too_large"),
        )

    def test_optional_and_unknown_modes_fail_closed(self):
        self.assertFalse(check_grounding({"answer": "invented"}, self.allowed, required=False,
                                         mode="extractive")[0])
        self.assertEqual(
            check_grounding({}, self.allowed, required=False, mode="semantic"),
            (False, "unsupported_grounding_mode"),
        )
        for mode in (None, True, float("nan"), [], {}, HostileMode(), StringSubclass("extractive")):
            with self.subTest(mode=mode):
                self.assertEqual(
                    check_grounding({}, self.allowed, mode=mode),
                    (False, "unsupported_grounding_mode"),
                )

    def test_exact_comparison_rejects_whitespace_or_line_break_changes(self):
        value = {
            "answer": "Keep the incident open.\n",
            "citations": [{"doc_id": "runbook", "quote": "Keep the incident open."}],
        }
        self.assertEqual(
            check_grounding(value, self.allowed, mode="extractive"),
            (False, "answer_not_source_extractive"),
        )
        normalized_quote = self.response({"doc_id": "formatted", "quote": "first line second line"})
        self.assertEqual(
            check_grounding(normalized_quote, {"formatted": "first line\nsecond line"}, mode="extractive"),
            (False, "quote_not_found_in_cited_document"),
        )
        unicode_quote = self.response({"doc_id": "unicode", "quote": "cafe\u0301"})
        self.assertEqual(
            check_grounding(unicode_quote, {"unicode": "caf\u00e9"}, mode="extractive"),
            (False, "quote_not_found_in_cited_document"),
        )
        trailing = self.response({"doc_id": "runbook", "quote": "Keep the incident open. "})
        self.assertEqual(
            check_grounding(trailing, self.allowed, mode="extractive"),
            (False, "quote_not_found_in_cited_document"),
        )

    def test_pathological_context_fails_closed_with_fixed_reason(self):
        exact = self.response({"doc_id": "runbook", "quote": "x"})
        contexts = [
            None,
            DictSubclass(runbook="x"),
            {"runbook": ["x"]},
            {"runbook": StringSubclass("x")},
            {"runbook": "x" * 1_048_577},
            {str(index): "x" for index in range(257)},
            {"invalid id": "x"},
            {HostileKey(): "x"},
        ]
        for context in contexts:
            with self.subTest(context_type=type(context).__name__):
                self.assertEqual(
                    check_grounding(exact, context, mode="extractive"),
                    (False, "extractive_context_invalid"),
                )

    def test_legacy_citation_mode_is_unchanged(self):
        unsupported = {"answer": "The incident is resolved. [[cite:runbook]]"}
        self.assertEqual(check_grounding(unsupported, self.allowed), (True, "citations_verified"))
        self.assertEqual(check_grounding({"answer": "No citation"}, self.allowed, required=False),
                         (True, "no_citations"))

    def test_grounding_control_passes_extractive_mode_through(self):
        control = grounding_control(lambda operation: self.allowed, mode="extractive")
        context = SecurityContext("t", "p", "a", "w", "o", "model.output", "v1")

        def run(value):
            encoded = json.dumps(value)
            operation = Operation(context, "model", "m", "d", encoded, hashlib.sha256(encoded.encode()).hexdigest())
            return asyncio.run(control(operation)).action

        exact = self.response({"doc_id": "runbook", "quote": "Keep the incident open."})
        invented = {"answer": "Resolved", "citations": exact["citations"]}
        self.assertEqual(run(exact), Action.ALLOW)
        self.assertEqual(run(invented), Action.DENY)


if __name__ == "__main__":
    unittest.main()
