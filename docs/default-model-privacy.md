# Default model privacy

Routes backed by a supported `chat_completions` connector default to
`privacy: tokenize` when `privacy` is omitted. The default applies in both the
development and production profiles. It does not change the default or an
explicit `restore` mode for fixture, threat-intelligence, or local-retrieval
routes.

For a default-protected model route, Guard tokenizes detected sensitive request
values before local prompt and sensitivity controls run and before provider
dispatch. Model request bodies may therefore contain agent-scoped vault
references, but not the detected originals. Numeric JSON card values are
converted to string references for model routes; non-model tokenize routes keep
their existing fail-closed behavior so Guard does not silently change a
business API's numeric field type.

Provider credentials are not part of this transformation. The trusted secret
broker resolves the connector credential only after route authorization and
body preparation, and the provider transport adds its configured
`Authorization` or `X-API-Key` header. Agent/model content cannot supply or
replace that credential.

Provider output from a tokenized model route passes through the same privacy
pipeline before release. Detected output values are replaced by scoped vault
references, including numeric card values. This protection is heuristic and
text/JSON only; unsupported multimodal payloads fail closed.

## Explicit exceptions

Plaintext (`privacy: none`) and restoration (`privacy: restore`) are explicit
model privacy exceptions. Each requires a nonempty, trimmed
`privacy_exception_reason` of at most 256 characters in the trusted product
configuration:

```json
{
  "name": "model.legacy",
  "connector": "legacy-model",
  "privacy": "none",
  "privacy_exception_reason": "Approved compatibility exception SEC-42"
}
```

The reason field is rejected on tokenized model routes and on non-model routes.
It cannot be provided in a request body or provider response. Configuration
summary/status diagnostics expose only the affected route, privacy mode,
exception count, and `reason_present: true`; they never emit the freeform
reason or connector credential.

`privacy: restore` intentionally permits valid references scoped to the same
tenant/principal/agent and destination to be restored before model dispatch.
The existing clearance floor still applies. Use this mode only when the
provider must receive the original value and the exception has been reviewed.

## Operator checks

- Prefer omission or explicit `privacy: tokenize` for every model route.
- Treat any reported model privacy exception as a review item.
- Keep exception reasons non-sensitive even though diagnostics redact them.
- Test provider schemas with vault-reference strings before deployment.
- Continue using connector-bound secret brokerage; never place provider
  credentials in request content or product configuration.

