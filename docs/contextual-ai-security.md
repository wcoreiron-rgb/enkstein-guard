# Contextual AI security control

This staged API adds one non-authoritative security vote to the existing
deterministic control aggregation. It does not execute tools, rewrite payloads,
grant routes, satisfy approvals, or override another control's denial.

## Integration API

Create the encrypted local history explicitly:

```python
from enkstein_guard.security_context import SecurityHistoryStore

history = SecurityHistoryStore.initialize(
    "/private/state/ai-security.sqlite3",
    "/private/keys/ai-security.key",
    capacity=10_000,
    ttl_seconds=3600,
    per_actor_capacity=64,
)
```

Reopen with the same capacity, TTL, and per-actor ring size:

```python
history = SecurityHistoryStore(
    database,
    key_file,
    capacity=10_000,
    ttl_seconds=3600,
    per_actor_capacity=64,
)
history.verify()  # {"status": "verified", "records": <current count>}
```

`recent(operation, limit=16)` derives its actor key only from the trusted
`Operation.context` tenant, principal, and agent. `record(operation,
assessment, action)` accepts an exact validated `SecurityAssessment` and an
`ALLOW`, `DENY`, or `REQUIRE_APPROVAL` action. Neither method accepts caller
identity assertions.

The store is a rolling context window, not an audit ledger. Expired records are
removed, and a busy actor rolls only its own oldest entries after 64 records by
default. It cannot evict another actor's live entries. A new actor is denied if
the global store is full. Deployments should size `capacity` to at least the
number of protected actors times `per_actor_capacity`; durable full-fidelity
security events remain the responsibility of the audit subsystem. Sequence
detection is limited to the retained last-N/TTL window.

Construct the control with the engine-specific registry name used by the host:

```python
from enkstein_guard.ai_security import AISecurityControl

control = AISecurityControl(
    analyzer=analyzer,
    inspector_operation_for=inspector_operation_for,
    tokenizer=tokenizer,
    history=history,
    context_for=context_for,
    confidence_threshold=0.7,
    failure_action="deny",  # or "require_approval"
    name="ai_security.primary",
)
```

`inspector_operation_for(target)` is a synchronous trusted-host callback. It
must return an `Operation` for the fixed internal inspector route, tenant,
model resource, and model destination, with an empty JSON object payload. It
must use operation `security.assess` and principal/agent `guard-security`, and
must not reuse the target agent route. The inspector may share a provider
destination with a protected model. The control validates that binding before
calling the analyzer. The trusted internal `Operation.context` remains local
broker metadata so tenant-scoped credentials resolve correctly; it is not
serialized into the model request body. The separately supplied sanitized
context replaces target tenant and actor identifiers with opaque refs.
Internal inspector routes must never be granted to agents or configured to
inspect themselves.

`context_for(target)`, when supplied, is synchronous and may return only:

```python
{"level": "public|internal|confidential|restricted|unknown",
 "labels": ["sensitive|untrusted|internal|confidential|restricted", ...]}
```

The analyzer must expose async `analyze(internal_operation,
sanitized_context, action_digest)` and return an exact `SecurityAssessment`.
The control reparses the dataclass and verifies its digest before using it.

## Privacy and binding

The action digest binds the trusted tenant, principal, agent, workflow,
operation ID, policy, route, resource, destination, and original operation
digest. The payload cannot replace these fields, and a prior assessment cannot
be replayed for a later operation ID even when the payload is identical.

Before external analysis, the control tokenizes one combined context containing
the target payload, trusted target route/resource/destination/policy metadata,
fixed sensitivity metadata, and actor-local recent decisions. Existing vault
references in this inspection copy are never restored or reauthorized. Every
well-formed native `[[EGV:...]]` reference is first replaced with an irreversible
`protected-reference:<sha256>` marker, preserving its surrounding text; this is
only a non-privileged correlation hint, not proof that the reference was valid
or authorized. The ordinary tokenizer then processes the whole copy with native
references disabled. A malformed leftover `[[EGV:` prefix therefore fails
closed. Numeric card values use tokenization mode. The final serialized context
is capped at the assessment protocol's 32 KiB limit. The execution payload and
the global prepare/restore path are never modified by this inspection redaction.

Raw tenant, principal, agent, and workflow identifiers are not serialized into
history context sent to the model. Opaque SHA-256 refs provide local correlation
handles. They are pseudonymous handles, not guaranteed anonymization against a
party that already knows or can guess the underlying identifiers. The encrypted
history database stores trusted identifiers only inside authenticated ciphertext
and never stores request payloads, prose, credentials, or model explanations.

## Decision restrictions and failure behavior

- Model `deny` and all critical-risk assessments return `DENY`.
- High risk returns at least `REQUIRE_APPROVAL`; a stricter denial remains a denial.
- A low-confidence allow escalates to the configured failure action.
- Three retained prior denials for the same actor add `suspicious_sequence` and
  escalate a current allow to at least `REQUIRE_APPROVAL`.
- The final action is recorded before an allow or approval result is returned.
  History write failure returns a failed `DENY` result.
- Vault, tokenizer, history, trusted-context, inspector-binding, corruption, and
  local serialization failures always return a failed `DENY`, regardless of
  `failure_action`.
- Analyzer timeout, outage, malformed output, fake objects, and digest mismatch
  use the explicit `deny` or `require_approval` fallback.
- A deterministic local inspection-boundary rejection is not model uncertainty:
  it always returns a failed `DENY` and can never become approval fallback.

The control result still flows through `combine_results`. A deterministic deny
therefore remains authoritative. These staged unit tests do not constitute a
product acceptance or production-readiness claim.
