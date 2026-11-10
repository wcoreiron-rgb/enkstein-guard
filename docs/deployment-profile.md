# Enforced local Linux container profile (legacy factory bootstrap)

> `deployment/compose.yaml` with a Python factory remains for SDK hosts. The CLI
> product uses `deployment/compose.production.yaml`; see
> [production-deployment.md](production-deployment.md). In this legacy profile
> the Guard container still has network access; the CLI profile removes it.

This profile is a concrete supported deployment target under validation, not a
claim of universal cloud protection. The container host and Guard bootstrap are
trusted. Agents are untrusted container processes without host/Docker access.

## Boundary

`deployment/compose.yaml` separates a trusted Guard process from a worker with
`network_mode: none`, a read-only root filesystem, no Linux capabilities,
no-new-privileges, nonroot UID, CPU/memory/PID limits, and a read-only socket
mount. The agent receives only its own scoped bearer credential. Provider keys,
vault keys, audit keys and the identity registry are mounted only in Guard.
The service still checks tenant identity: possession of a socket is not authority.

This prevents direct network bypass inside this worker profile. It does not
isolate a compromised container host, prevent every kernel escape, constrain an
agent launched outside this profile, or establish physical tenant isolation.
Use separate Guard/state/socket deployments per tenant where stronger separation
is required. Never mount the Docker socket, host home directory or Guard state
inside workers. Do not give workers privileged, host-network, host-PID or broad
volume access. The guard container itself has network access for configured
connectors; operator code and destination configuration remain trusted.

## Packaging and startup

Run `python tools/build_linux_release.py` in the development environment to
build the wheel and vendor hash-locked Linux ARM64 dependencies. Then build
with `docker build --network none -f deployment/Dockerfile -t enkstein-guard:local .`.
Dependency installation uses only the vendored wheelhouse with hash verification.
The validated architecture is Linux ARM64; an AMD64 wheelhouse/image still needs
its own lock and executed acceptance. The base image is pinned to the tested digest. Select a
new digest only with a new image vulnerability assessment and acceptance run.
Compose requires four operator-supplied values: GUARD_BOOTSTRAP_DIR,
GUARD_SECRETS_DIR, GUARD_AGENT_IMAGE and GUARD_AGENT_TOKEN_FILE. The trusted
bootstrap exports `build_runtime()`, returning GuardRuntime or a configured
GuardService. When returning GuardService its path must equal the daemon path.
Secrets and bootstrap are read-only mounts; guard state uses a dedicated volume.
The initialization container adjusts only the two dedicated volume directories.
Do not use synthetic acceptance bootstrap as a real business connector.

`enkstein-guard-host --factory bootstrap:build_runtime --socket /run/guard/guard.sock`
runs the trusted host. It locks the socket directory, rejects a second daemon,
recovers a stale socket only after a refused connection, and handles termination.
Compose restarts the host after failures. This is single-host supervision,
not highly available clustering or distributed workflow recovery.

## Durable action outcomes

Create OutcomeLedger once with its own database and key. Open it in the single
trusted owner and supply `GuardService(..., outcomes=ledger)`. Every request must
then provide a unique ASCII request_id of 16–128 characters. The ledger commits
an executing record before dispatch. IDs bind to tenant, principal, agent,
route and payload digest. Duplicate completed calls return completed_no_replay,
without executing again or re-releasing original output. Payload substitution
returns a conflict. Active calls return in_progress. After restart an interrupted
call becomes outcome_unknown_no_replay. A real side effect may have occurred;
reconcile with the destination before intentionally submitting a new action.
This is duplicate suppression, not an exactly-once external transaction.

The ledger stores encrypted bindings/states, not credentials or response bodies.
Only one owner may open it; the daemon holds the host lock before bootstrap.
Do not share it among multiple host instances. It has a bounded capacity and no
automatic eviction. At capacity it refuses new tracked actions. Retention,
archival and deliberate ID reuse require an operator policy before long-lived
production deployment. Restoring an old snapshot can lose deduplication history;
reconcile outstanding work before resuming. The ledger is not independently
rollback-proof. Back up all state consistently while writers are stopped.

## Connector support

BrokeredChatProvider supports fixed HTTPS chat-completions destinations using
bearer or x-api-key authentication; the latter supports the documented Hatz
header shape. Use it through PrivateAI for input/output protection. No automatic
fallback can bypass required inspection. Compatibility tests use captured fake
responses; no live Hatz or Cisco request has been executed.

VirusTotalIPProvider supports only globally routable IP reputation lookups at a
fixed VirusTotal endpoint. It validates identity/destination through the broker,
rejects caller-selected URLs and extra payload fields, and returns bounded
numeric stats rather than arbitrary provider instructions. No file upload or
production API key is used by acceptance tests. Service-specific API quotas and
workflow budgets still need operator configuration. No ServiceNow write adapter
has been enabled; protected writes require bound approvals and field/resource
constraints before live use.

## Executed acceptance

`python deployment/test_isolation.py` creates disposable synthetic credentials,
state and containers. It checks approved work, tokenization, tenant denial,
forged credentials, unknown tools, network denial, absent keys, nonroot execution,
read-only filesystem/socket mount and duplicate suppression. It force-kills the
host and repeats the checks after restart, then verifies the audit checkpoint.
Only its uniquely named Compose project/volumes are removed. It never accesses
production APIs. Results are in verification/container-isolation.json.

## Remaining release gates

Live service validation, distributed tenant storage/communication, durable
orchestration recovery/queues, retention automation, high availability, OS image
vulnerability analysis, independent review and complete OWASP/ATLAS adversarial
acceptance remain required for the full engineering handoff. Artifact signing
utilities are available, but a locally generated signing key is not an externally
trusted publisher identity. Distribute the trust anchor independently.
