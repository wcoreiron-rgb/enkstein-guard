"""Reject oversized untrusted trees before serializing a second large copy."""
import unittest
from unittest.mock import patch

from enkstein_guard import model_responses as adapter


class ModelResponseBoundsTests(unittest.TestCase):
    def assert_rejected_before_serializing(self, value):
        with patch.object(adapter.json, "dumps") as serialize:
            with self.assertRaises(adapter.ModelResponseError):
                adapter.extract_chat_answer(value)
            serialize.assert_not_called()

    def test_oversized_single_string_is_rejected_before_copy(self):
        self.assert_rejected_before_serializing({"usage": {"text": "x" * (adapter.MAX_ENVELOPE_BYTES + 1)}})

    def test_aggregate_strings_are_bounded_before_copy(self):
        self.assert_rejected_before_serializing({"usage": {"text": ["x" * 65536, "y" * 65536]}})

    def test_oversized_key_is_bounded_before_copy(self):
        self.assert_rejected_before_serializing({"usage": {"x" * (adapter.MAX_ENVELOPE_BYTES + 1): 0}})
