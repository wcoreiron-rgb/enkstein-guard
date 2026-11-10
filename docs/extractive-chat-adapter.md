# Extractive chat-completions adapter

Extractive grounding routes backed by `chat_completions` use a narrow adapter
for the provider's response envelope. The adapter returns only the assistant's
parsed extractive object. It never releases provider IDs, model names, usage,
fingerprints, service-tier values, or other outer metadata.

## Request contract

Request a non-streaming JSON-object response and instruct the model to emit the
exact extractive schema with no prose or Markdown fence:

```json
{
  "messages": [
    {
      "role": "developer",
      "content": "Return exactly one JSON object with keys answer and citations. Each citation must contain only doc_id and an exact source quote. answer must be the quotes concatenated in order."
    },
    {
      "role": "user",
      "content": "Answer only from the authorized context."
    }
  ],
  "response_format": {"type": "json_object"},
  "stream": false
}
```

`response_format` guides the provider but is not a security boundary. Guard
still validates every byte of the response.

The assistant content must parse to:

```json
{
  "answer": "Exact source quote.",
  "citations": [
    {"doc_id": "kb-1", "quote": "Exact source quote."}
  ]
}
```

The later extractive grounding check verifies document authorization, exact
quote membership, citation limits, and that `answer` equals the cited quotes
concatenated in order.

## Supported response envelope

Guard recognizes exactly one non-streaming chat-completions shape:

- `choices` is a list with one entry.
- The choice has `index: 0`, `finish_reason: "stop"`, and optional
  `logprobs: null`.
- The message has `role: "assistant"`, string `content`, and optional
  `refusal` that is `null` or empty.
- Tool calls, function calls, refusals, additional choices, incomplete output,
  and unknown choice/message fields are refused.
- Optional outer fields are limited to `id`, `object`, `created`, `model`,
  `usage`, `service_tier`, and `system_fingerprint`. If present, `object` must
  be `chat.completion`. Outer metadata is discarded.

Assistant content is limited to 64 KiB of UTF-8 JSON. The full envelope is
limited to 128 KiB. Parsing rejects duplicate keys, `NaN`/infinity, excessive
nesting or node counts, non-JSON objects, trailing prose, Markdown fences, and
schema additions. Citation entries must contain exactly nonempty `doc_id` and
`quote` strings.

Every invalid or unsupported response raises the fixed
`ModelResponseError("model_response_invalid")`. Provider-controlled content is
never copied into that error or diagnostics.

Provider formats outside this tested contract are intentionally unsupported.
Add a separately reviewed adapter rather than heuristically searching or
unwrapping arbitrary nested response fields.

