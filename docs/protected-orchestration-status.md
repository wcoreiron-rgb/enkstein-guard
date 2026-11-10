# Protected orchestration delivery status

Artifact: `enkstein_guard-0.3.0.dev0-py3-none-any.whl`.
Scope: local single-coordinator application profile, macOS worker containment,
and optional actual LangGraph workflow. Original source repositories unchanged.

| Capability | Evidence | Remaining boundary |
|---|---|---|
| Scoped delegation | Child identities, grant subsets, tenant/workflow propagation, count/depth denial | Bootstrap remains trusted; no remote identity federation |
| Shared budgets | Calls/units/parallelism/deadline reservation and concurrent overspend tests | Units are configured reservations; no distributed ledger or measured currency accounting |
| Data flow | Direct PII and multi-agent summarized exfiltration blocked, including new taint during inspection | Conservative workflow-wide labels, not exact semantic lineage |
| Memory/handoffs | Encrypted artifacts, untrusted writes, retained prior artifacts, workflow ACL and replay tests | Indexes/replay state in memory; no cross-session durable memory service |
| Human approval | Separate approver credential, redacted review, immutable action binding, expiry/single-use, deny precedence | Host must connect its trusted approval UI |
| Component admission | Pinned bytes checked at registration/dispatch; replacement tests | Integrity against trusted pins, not malware certification or complete supply-chain scanning |
| Worker isolation | Actual macOS file/network denial, scrubbed environment, verified snapshot, output/deadline limits | No Linux/Windows/cloud sandbox profile; host runtime directories must not hold secrets |
| Containment | Parent/child revocation, cooperative task cancellation, actual worker kill/reaping | Arbitrary in-process callbacks remain cooperative; no rollback of prior effects |
| Existing workflow integration | AgentSession node adapter and actual LangGraph 1.2.16 reference | No automatic interception of every framework or coding-agent host |

## Executed checks

- 117 core tests passed against the installed wheel on macOS/Python 3.14.
- 4 optional integration tests passed on Python 3.11: actual LangGraph, pinned
  AGT, NeMo, and Cisco SDK with its remote inspection boundary mocked.
- Offline wheel installation and dependency checks passed in both environments.
- Foundation, private runtime and orchestration examples passed from `/tmp`.
- Actual LangGraph result: blocked=true, external_calls=0, two agents, shared
  calls=3 and units=3; confidential/sensitive classifications retained.

Full results: `verification/orchestration-core-tests.log` and
`verification/orchestration-frameworks-tests.log`. Exact wheel digest and test
profile: `verification/orchestration-artifact.json`.

This implements the supported local orchestration milestone. Production
sign-off still requires multi-host state/identity controls, supported cloud
isolation, broader admission scanning, real provider/service checks and the
versioned adversarial release evidence. No complete OWASP or ATLAS claim is made.

See [setup and trust model](protected-orchestration.md).
