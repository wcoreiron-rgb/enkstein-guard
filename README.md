# Enkstein Guard

CLI-operated security boundary for AI agents on a single Linux/Docker host:
tenant-isolated identities, credential brokering, sensitive-data
classification and propagation, per-document retrieval authorization,
exact-action approvals, task boundaries, durable audit and duplicate
suppression, and a network-less Guard whose only egress is an independent
allowlisting proxy.

Status: **0.5.0rc3.dev12 unreleased development source.** The preserved
0.5.0rc2 wheel and image have a separate [readiness register](docs/cli-production-readiness.md).
Their measurements do not validate this newer source. Production acceptance
is not declared. The [original requirements register](docs/original-requirements-roadmap.md)
tracks the broader product work still open.

New development controls: [durable exact-action approvals](docs/durable-approvals.md),
[offline audit key rotation](docs/audit-key-rotation.md), and
[trusted production backend inventory](docs/backend-inventory.md).
Existing states require explicit adoption to provision the approval store;
production network configurations require the new inventory before starting.

The current development iteration adds [default model privacy](docs/default-model-privacy.md),
[source-extractive responses](docs/extractive-grounding.md), and an explicit
[durable workflow store](docs/durable-workflows.md) for SDK orchestration hosts.
The CLI service does not automatically persist embedded SDK workflows.
The optional [AI security engine](docs/ai-security-operator.md) adds a
model-assisted assessment before selected actions, with encrypted actor-scoped
rolling context. Its strict responses can deny or require an exact-action
approval. Deterministic denials, tenant permissions and execution payloads
remain authoritative. Configure a fixed chat provider and internal inspection
route explicitly; installation alone does not activate an AI engine.
Offline CLI rotation now also covers [connector secrets](docs/connector-secret-key-rotation.md),
[approval storage](docs/approval-key-rotation.md), and encrypted
[AI history](docs/security-history-key-rotation.md), including recoverable resume.
SDK [workflow snapshot rotation](docs/workflow-key-rotation.md) requires a closed
coordinator and retains the existing exclusive owner boundary.
[Vendor adapter capabilities](docs/reused-engine-capabilities.md) documents the
exact supported SDK surfaces and their separate activation requirements.
The optional [local AGT policy](docs/agt-cli-policy.md) now has CLI configuration:
exact trusted actor/route bindings and bounded typed conditions narrow existing
grants. Missing or incompatible configured SDKs reject startup. Its pinned wheel
has separate Mac and Alpine bootstrap tests; fresh installed-candidate and
physical deployment acceptance remain required.
An explicit [AI-path characterization harness](docs/operations/ai-security-characterization.md)
measures configured full histories with a synthetic provider; a plan is not a measurement.
The next development slice adds offline [identity signing-key rotation](docs/identity-key-rotation.md)
and a separate [synthetic AI endurance harness](docs/operations/ai-security-endurance.md).
Its full three-hour profile requires a fresh explicit run; plan/unit tests and
short smoke checks do not establish endurance. [Vendor dependency facts](docs/vendor-deployment-feasibility.md)
do not establish target image compatibility or activate vendor CLI factories.

The history cache reuses validated immutable records only when the complete
current database row and key epoch match. The current scan optimization
checks global row counts and field sizes inside SQLite before reading every
row. Whole-store integrity, actor limits and fresh expiry checks remain required.
Prior dev9 passed its finite eight-actor latency guardrails but failed at sixteen
actors; this version requires fresh installed and deployment evidence. Component
profiling alone does not establish end-to-end capacity.

See [current validation and open gates](docs/release/development-0.5.0rc3.dev12.md).

## Start here

- [CLI operator guide](docs/cli-operator-guide.md): install, initialize,
  register agents and connectors, policies, start/inspect/stop, approvals,
  audit, diagnostics, backup and upgrade.
- [Configuration reference](docs/configuration-reference.md) (schema version 2).
- [Production deployment](docs/production-deployment.md):
  `deployment/compose.production.yaml`, the only supported production topology.
- [Data protection](docs/data-protection.md): what is classified, propagated,
  withheld, and what cannot be recognized.
- [Operations runbook](docs/operations/runbook.md) and
  [capacity planning](docs/operations/capacity-planning.md).

For the local development wheel (not a production-accepted release):

```sh
python -m pip install dist/deployment/enkstein_guard-0.5.0rc3.dev12-py3-none-any.whl
enkstein-guard doctor
enkstein-guard --config guard.json config validate
enkstein-guard --config guard.json init
enkstein-guard --config guard.json service start
```

Installing the package does not mediate traffic or execution. Enforcement
exists only for agents that can reach their tools solely through a running
Guard in the `production-linux-peer-bound` profile; `doctor` reports whether
that is the case.

## Scope

Supported: one Guard host, Linux ARM64 containers, Python 3.11+ (validated 3.12
in containers and the Linux sandbox; 3.14 macOS for library tests).
Model requests are text-only: media and URL parts, hosted provider tools, web
search and provider-side storage fields are refused before dispatch. Production
configurations declare a request rate, and validation refuses an outcome
ledger too small for that rate and the retention schedule; retention runs
inside the service.
Unsupported: high availability or multi-host state, streaming, multimodal
content, Windows, other CPU architectures, cloud-specific isolation, network
agent-to-agent messaging. No complete OWASP or MITRE ATLAS protection is
claimed; `enkstein-guard coverage` prints the versioned control-to-scenario
mapping including confirmed gaps.

## Library use

The SDK (`GuardRuntime`, `PrivateAI`, `ProtectedOrchestrator`, `LocalVault`,
`GuardService`) remains available; see `docs/foundation.md`,
`docs/private-ai-runtime.md` and `docs/protected-orchestration.md`. The scanner
is copied from Enkstein under its MIT license; see
[provenance](docs/source-provenance.json).

## Tests

```sh
cd tests && python ../tools/verify_scenarios.py --suite . --output ../core.json   # passed/skipped/failed counted separately
python tools/verify_attack_scenarios.py --output attack.json   # exit 2 while known gaps remain
```
