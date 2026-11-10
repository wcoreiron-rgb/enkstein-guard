"""Strict chat-completions response extraction."""

import copy
import json
import unittest

from enkstein_guard.model_responses import ModelResponseError, extract_chat_answer


ANSWER = {"answer": "Exact source span.",
          "citations": [{"doc_id": "kb-1", "quote": "Exact source span."}]}


def envelope(content=None):
    return {
        "id": "chatcmpl-synthetic",
        "object": "chat.completion",
        "created": 1_799_999_999,
        "model": "synthetic-model",
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
        "service_tier": "default",
        "system_fingerprint": None,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content or json.dumps(ANSWER), "refusal": None},
            "finish_reason": "stop",
            "logprobs": None,
        }],
    }


class ModelResponseTests(unittest.TestCase):
    def assertInvalid(self, value):
        with self.assertRaises(ModelResponseError) as caught:
            extract_chat_answer(value)
        self.assertEqual(str(caught.exception), "model_response_invalid")
        self.assertEqual(caught.exception.args, ("model_response_invalid",))

    def test_normal_structured_answer_is_returned_without_outer_metadata(self):
        value = envelope()
        parsed = extract_chat_answer(value)
        self.assertEqual(parsed, ANSWER)
        self.assertIsNot(parsed, ANSWER)
        serialized = json.dumps(parsed)
        for metadata in (value["id"], value["model"], "prompt_tokens", "system_fingerprint"):
            self.assertNotIn(metadata, serialized)

    def test_unknown_outer_choice_and_message_fields_are_rejected(self):
        cases = []
        value = envelope()
        value["opaque"] = {"answer": ANSWER}
        cases.append(value)
        value = envelope()
        value["choices"][0]["opaque"] = "ignored"
        cases.append(value)
        value = envelope()
        value["choices"][0]["message"]["name"] = "unexpected"
        cases.append(value)
        for value in cases:
            with self.subTest(fields=list(value)):
                self.assertInvalid(value)

    def test_refusal_tool_calls_and_function_calls_are_rejected(self):
        refusal = envelope()
        refusal["choices"][0]["message"]["refusal"] = "I cannot answer"
        tool = envelope()
        tool["choices"][0]["message"]["tool_calls"] = []
        function = envelope()
        function["choices"][0]["message"]["function_call"] = {"name": "unsafe"}
        for value in (refusal, tool, function):
            self.assertInvalid(value)

    def test_multiple_or_missing_choices_are_rejected(self):
        multiple = envelope()
        multiple["choices"].append(copy.deepcopy(multiple["choices"][0]))
        missing = envelope()
        missing["choices"] = []
        not_a_list = envelope()
        not_a_list["choices"] = {"0": not_a_list["choices"][0]}
        for value in (multiple, missing, not_a_list):
            self.assertInvalid(value)

    def test_duplicate_content_keys_are_rejected_at_every_depth(self):
        self.assertInvalid(envelope('{"answer":"one","answer":"two","citations":[]}'))
        self.assertInvalid(envelope(
            '{"answer":"q","citations":[{"doc_id":"kb-1","doc_id":"kb-2","quote":"q"}]}'))

    def test_nonfinite_content_and_metadata_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            self.assertInvalid(envelope(
                '{"answer":"q","citations":[{"doc_id":"kb-1","quote":%s}]}' % constant))
        metadata = envelope()
        metadata["usage"]["completion_tokens"] = float("nan")
        self.assertInvalid(metadata)

    def test_oversize_content_and_envelope_are_rejected(self):
        answer = {"answer": "x" * 65_536, "citations": [{"doc_id": "kb-1", "quote": "x"}]}
        self.assertInvalid(envelope(json.dumps(answer)))
        metadata = envelope()
        metadata["usage"]["details"] = "x" * 131_072
        self.assertInvalid(metadata)

    def test_incomplete_or_ambiguous_choice_is_rejected(self):
        cases = []
        for finish_reason in ("length", "tool_calls", "content_filter", None):
            value = envelope()
            value["choices"][0]["finish_reason"] = finish_reason
            cases.append(value)
        value = envelope()
        value["choices"][0]["index"] = 1
        cases.append(value)
        value = envelope()
        value["choices"][0]["index"] = False
        cases.append(value)
        value = envelope()
        value["choices"][0]["message"]["role"] = "tool"
        cases.append(value)
        value = envelope()
        value["choices"][0]["logprobs"] = {"content": []}
        cases.append(value)
        for value in cases:
            self.assertInvalid(value)

    def test_deep_or_non_json_values_are_rejected(self):
        nested = "leaf"
        for _ in range(22):
            nested = {"next": nested}
        deep = dict(ANSWER, extra=nested)
        self.assertInvalid(envelope(json.dumps(deep)))
        custom = envelope()
        custom["usage"] = (1, 2)
        self.assertInvalid(custom)

    def test_prose_fences_and_wrong_extractive_schema_are_rejected(self):
        values = [
            envelope("Here is the answer: " + json.dumps(ANSWER)),
            envelope("```json\n" + json.dumps(ANSWER) + "\n```"),
            envelope(json.dumps({"answer": "q", "citations": [], "debug": True})),
            envelope(json.dumps({"answer": "q", "citations": [{"doc_id": "kb-1", "quote": ""}]})),
            envelope(json.dumps({"answer": 1, "citations": [{"doc_id": "kb-1", "quote": "q"}]})),
        ]
        for value in values:
            self.assertInvalid(value)


if __name__ == "__main__":
    unittest.main()

