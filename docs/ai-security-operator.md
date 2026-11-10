# AI security engine operator guide

The optional AI security engine is a pre-dispatch control for selected routes.
It can recommend `allow`, `deny`, or `require_approval` within the existing Guard
decision contract. It cannot add route grants, change tenants or clearance,
rewrite an action payload, select credentials, or bypass deterministic controls.
A deterministic denial always wins.

This staged feature has synthetic-provider test coverage only. Configured does
not mean the provider is reachable or that a model has been independently
validated for a deployment.

## Configuration

Define one internal chat-completions route, one engine, and reference the engine
from each route that requires assessment:

```json
{
  "security_history": {
    "capacity": 10000,
    "ttl_seconds": 3600,
    "per_actor_capacity": 64
  },
  "security_engines": [
    {
      "name": "primary",
      "tenant": "tenant-a",
      "model_route": "security.inspect",
      "timeout_seconds": 1.5,
      "confidence_threshold": 0.7,
      "failure_action": "deny"
    }
  ],
  "routes": [
    {
      "name": "security.inspect",
      "tenant": "tenant-a",
      "operation": "security.assess",
      "connector": "security-model",
      "clearance": "confidential",
      "produces": "confidential",
      "privacy": "tokenize",
      "approval": "none"
    },
    {
      "name": "ticket.comment",
      "tenant": "tenant-a",
      "operation": "ticket.update",
      "connector": "tickets",
      "clearance": "confidential",
      "security_engine": "primary"
    }
  ]
}
```

The inspector route must use an existing `chat_completions` connector, have the
same tenant as the engine, use operation `security.assess`, retain
`privacy: tokenize`, and set `approval: none`. It cannot have grounding, task
boundaries, or its own `security_engine`. Never grant this route to an agent.
Its configured `local_prompt` and `sensitivity` controls run against the
already-sanitized internal model request before any inspector-provider
dispatch. A denial, invalid result, error, or timeout at this deterministic
boundary always denies the target action and cannot become approval fallback.
Guard invokes it internally with the fixed principal and agent
`guard-security`; provider endpoint, model, credential binding, egress policy,
and production backend inventory still come from the normal trusted connector
configuration.

The engine timeout must not exceed `service.control_timeout_seconds`.
`confidence_threshold` is between 0 and 1. `failure_action` defaults to `deny`.
If it is `require_approval`, every inspected route must use `approval: required`
or `approval: on_demand`, and the tenant must have a configured approver. An
agent cannot manufacture that approval: the existing action-bound approval
ticket and dispatch hooks remain authoritative.

`security_history` is encrypted single-host decision context, not a replacement
for the audit log. It retains a rolling bounded history per actor. Capacity must
reserve `per_actor_capacity` records for every configured agent that can call an
AI-inspected route. Changing these store parameters requires a service restart
because they are bound into the encrypted store identity.

## Runtime behavior

Guard tokenizes a bounded inspection copy before constructing the model request.
The target connector still receives the original authorized payload; model
output cannot rewrite it. The internal operation is pinned to the configured
model route and brokered credential. Recent history is scoped to the same
tenant, principal, and agent. Trusted context may add fixed sensitivity or taint
labels, never raw declared-context secrets.

For a protected chat route whose normal payload preparation already contains
native `[[EGV:...]]` references, Guard replaces those exact references with
one-way opaque `protected-reference:` markers only in the AI inspection copy,
then applies the inspector tokenizer. It never restores the target values,
widens reference permissions, or changes the prepared business payload. The
business connector receives its normal prepared references; the inspector
receives neither those references nor the underlying secret or payment-card
values.

The assessment response has a fixed, action-digest-bound schema. Model timeout,
provider failure, malformed or mismatched model output, and a model `allow`
below `confidence_threshold` resolve to the configured `failure_action`; there
is never a fallback allow. Local context validation, tokenization or vault
failure, security-history unavailability or corruption, and failure to record
a validated assessment always deny, even when `failure_action` is
`require_approval`.

`recent_decisions` contains prior validated AI-control votes for the same
tenant/principal/agent. It is bounded sequence context, not the complete audit
trail and not a claim about final business outcomes: a deterministic control can
still deny an action after an AI `allow`. The durable audit remains the record
of combined decisions and dispatch outcomes.

A model `allow` is only one required-control result. Authentication, tenant
isolation, route authorization, task boundaries, sensitivity, approvals,
payload preparation, dispatch bindings, and response-release checks still run.

## State, backup, and restore

`enkstein-guard init` creates:

- `state/security-history/security.sqlite3`
- `keys/security-history.key`

Adoption verifies a complete database/key pair. The coordinated backup manifest
includes both files and the configured history limits. Verification opens and
checks the encrypted store. Restore requires the manifest limits to match the
target configuration and verifies the restored store before reporting success.

## Diagnostics

`config validate`, `config show`, `policy explain`, `doctor`, and service status
report engine names, tenant and model-route bindings, model name, provider
destination, thresholds, failure action, inspected routes, and whether the
stage is absent, unavailable, configured, or active. These diagnostics never
include provider secret values or free-form model explanations. `configured`
means the schema and bindings are valid; only a running host reports `active`.
`doctor` compares the freshly loaded configured policy version with the running
service version. If they differ after a restart-required change, the engine
remains `configured`, reports `configuration_not_active` and a pending-restart
detail, and shows only the safe configured and active version identifiers.

When no engine is configured, `doctor` reports the feature as absent and does
not require optional AI runtime imports. No live provider call is made by
configuration validation or diagnostics.

## Reviewing recent AI votes

While the private admin service is running, an operator can inspect up to 16
recent votes for one configured agent without invoking the model:

```text
enkstein-guard --config guard.json security history --agent agent-a --limit 16
```

The host resolves the agent's tenant and principal from trusted configuration;
the command does not accept caller-supplied identity assertions. Output contains
only timestamp, target route, action digest, model decision, risk, confidence,
fixed signals, and the enforced AI-control action. It contains no target
payload, model prose, provider credential, or raw identity. Unknown agents and
limits outside 1–16 return fixed errors.

These records are prior AI-control votes, not final business outcomes. Use the
durable audit and outcome ledger to determine whether another control denied the
request, whether approval was satisfied, and whether dispatch completed.
