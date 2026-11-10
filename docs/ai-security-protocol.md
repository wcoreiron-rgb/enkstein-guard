# AI security assessment protocol

The AI security analyzer produces a bounded recommendation for an already
identified action. It does not execute the action, rewrite its payload, grant a
route, assert an identity, change policy, or supply tools. Existing deterministic
controls, authorization, approval binding, and execution boundaries retain
authority.

This staged protocol has three public interfaces:

```python
SecurityAssessment(
    schema_version=1,
    action_digest="<64 lowercase hex characters>",
    decision="allow | deny | require_approval",
    risk="low | medium | high | critical",
    confidence=0.0,
    signals=("prompt_injection",),
)

parse_assessment(value, *, action_digest=expected_digest)

await ChatSecurityAnalyzer(provider, timeout=1.5).analyze(
    inspector_operation, tokenized_context, expected_digest
)
```

`SecurityAssessment` is frozen. JSON signal lists are normalized to immutable
tuples after validation.

## Assessment schema

The model content must be exactly one JSON object with these six keys:

```json
{
  "schema_version": 1,
  "action_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "decision": "require_approval",
  "risk": "high",
  "confidence": 0.92,
  "signals": ["prompt_injection", "tool_misuse"]
}
```

Allowed signals are:

- `prompt_injection`
- `data_exfiltration`
- `credential_theft`
- `privilege_escalation`
- `destructive_action`
- `untrusted_instruction`
- `tool_misuse`
- `policy_evasion`
- `suspicious_sequence`

Signals are unique and limited to 16. An empty list is accepted only for low
risk. Confidence is an exact integer or finite float from 0 through 1; booleans
are not numbers in this protocol. The action digest must exactly match the
trusted expected digest, preventing an assessment from being replayed for a
different action.

Additional keys are refused, including prose, identities, permissions, tools,
rewritten payloads, or execution instructions. Parsing also rejects duplicate
JSON keys, non-finite numbers, non-JSON values, excessive depth/node counts,
oversized input, invalid primitive types, and unknown enum values.

## Provider boundary

The host supplies a trusted internal inspector `Operation` created for the
registered model connector. The analyzer ignores its dummy payload and builds a
new bounded request, while preserving only the operation's internal security
context, route, model resource, destination, and digest. Target action text in
the inspection context cannot choose the model endpoint, connector route, or
broker credential scope.

The request is fixed to:

- two messages: a constant system classifier contract and a user JSON object
  containing only `action_digest` and the already privacy-tokenized context;
- the provider's configured model;
- `stream: false`, temperature zero, and a 512-token output bound;
- `response_format: {"type": "json_object"}`;
- no tools or tool choice.

Only one complete index-zero assistant choice with `finish_reason: "stop"` is
accepted. Refusals, tool/function calls, multiple choices, truncation,
non-null log probabilities, unknown envelope fields, invalid JSON, provider
errors, and timeouts fail closed.

All failures use the fixed `AssessmentError("assessment_invalid")`. Provider,
model, context, and response text are never copied into exceptions or returned
as assessment data. The model's recommendation becomes input to the trusted
risk/control engine; it is never an execution instruction by itself.

