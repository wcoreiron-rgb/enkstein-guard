# Separate security review — 0.4.0rc4

Review type: separate read-only AI-assisted source/configuration review, delegated
to a different execution pass. This is **not** an external penetration test,
third-party audit, certification, or attestation. Synthetic local data only;
no live APIs, customer data, or original-project changes.

Scope: runtime, service, daemon, outcomes, vault, PrivateAI, orchestration,
providers, threat intelligence, audit, workers and Compose configuration.
The reviewer executed 128 focused tests during review. The final installed
candidate separately passed 161 core tests and four optional integration tests.

## Findings fixed and regression-tested

| Finding | Fix | Regression evidence |
|---|---|---|
| One tenant could exhaust the global outcome ledger | Capacity reserved from trusted registered tenant inventory | test_service: one_tenant_cannot_exhaust_another_tenants_reserved_ledger_capacity |
| Cancelled HTTP requests left blocking work queued | Bounded dedicated executor; a slot is held until the actual thread finishes | test_blocking: cancelled_http_work_holds_capacity_until_thread_finishes |
| Policy-denied private requests accumulated durable vault entries | Failed-scope revocation; unpublished receipt cleanup | test_private_ai: denied_private_requests_do_not_accumulate_vault_entries |
| Initial quota patch introduced quadratic per-value scanning | Validate/stage first; one atomic batch; max128 distinct values and 10000 live entries | test_privacy_batch: one batch, limit-before-write and late-validation atomicity |
| Cleanup failure could misreport an unknown external outcome as denial | Track scope only after atomic preparation; retain outcome-unknown error semantics | test_private_ai: cleanup_failure_after_model_call_preserves_unknown_outcome |

The reviewer measured 100 values in 0.002s and 128 in 0.003s on a clean local
vault; 129 were rejected with zero rows. These are scoped samples, not a load SLA.

## Open findings

**High: shared-socket pre-authentication starvation.** service.py reserves a
connection slot before authentication. The two-second read deadline reclaims a
silent connection, but a process with socket access can continuously refill all
slots. A valid credential is not required. Mutually untrusted tenants must not
share one UID/socket and assume admission fairness. Separate tenant processes,
sockets and OS identities, or authenticated admission before the shared worker
pool, are needed. Reproduced as a confirmed gap in the attack suite.

**Medium: bounded full-vault accounting is synchronous.** put_many verifies up to
10000 live records per batch. This removes per-payload quadratic work, but repeated
full-vault requests can still contend for the event loop. Transactional authenticated
accounting/async work isolation and concurrent-load evidence remain needed.

**Medium: explicit vault tenant reservations are optional.** Generic library
defaults bound each tenant and the global database but do not reserve capacity for
every tenant. Shared multi-tenant hosts must supply tenant_limits whose sum fits
the data pool, or use separate vaults. The container acceptance bootstrap supplies
explicit reservations. This is not a globally safe default for every integration.

**Medium: outcome retention remains manual.** Per-tenant quotas prevent taking a
neighbor's reserved share, but a tenant can eventually fill its own permanent
request history. Archival must preserve duplicate-suppression semantics. No blind
cleanup/eviction was added because it could re-execute old destructive requests.

## Image evidence

The reviewer independently rescanned an intermediate image and confirmed removal
of the previously fixable high OS finding and all Python findings. Root then
scanned the final built image offline with no Docker socket exposed to the scanner.
The final image ID and report hashes are in verification/os-image-scan.provenance.json.
No ignore-unfixed flag was used. Final totals: zero Critical, 44 High OS finding
instances across eight CVEs, zero Python findings. The 44 High instances have no
fixed version in the current database. They remain release blockers, not waivers.

## Assumptions and residuals

Trusted bootstrap/transports can bypass application intent; they are outside the
untrusted-agent boundary. Guard itself has outbound network access; Compose does
not enforce its egress destinations. Audit rollback detection requires an external
checkpoint. The macOS sandbox is not cloud isolation. Mutable deployment tags are
not signed-image admission. Local release signatures do not establish publisher
trust. Source-installed AGT and local Guard are not covered by PyPI advisory lookup.
