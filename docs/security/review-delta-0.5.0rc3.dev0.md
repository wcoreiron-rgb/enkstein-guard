# Independent review delta — 0.5.0rc3.dev0

This is a review request, not an independent review result. The implementation
and tests were produced and reviewed with AI assistance. Artifact identities and
test limitations are in [development validation](../release/development-0.5.0rc3.dev0.md).

## Durable approvals

Review `approval_store.py`, `approvals.py`, host initialization and the backup
flow. The database authenticates/encrypts the ticket, exact-action binding,
decision, deciding identity and credential digest. SQLite transactions serialize
creation, decisions and single-use consumption. Current approver scope and
credential are checked again at consumption. Runtime creation is prohibited;
legacy state requires explicit adoption. Existing library callers can still
choose the in-memory book by omitting `store`.

Try concurrent consumers in different processes; request/decision races;
credential/scope revocation between approval and dispatch; policy reload and
restart; clock movement; disk-full and key replacement; malicious SQLite paths;
and backup manipulation. Tests are `test_durable_approvals.py` and
`test_durable_approvals_host.py`, alongside the existing approval/host suites.

Known limitation: a valid historical full-state restore can resurrect a consumed
approval. There is no independent monotonic checkpoint. Restored approvals must
be invalidated/reapproved when that threat matters. SQLite is for one host, not
multi-host consensus. Approval keys currently have no rotation migration.

## Audit key rotation

Review `audit.py::DurableAudit.rotate_key` and CLI `cmd_keys`. Rotation verifies
the chain and archives under an exclusive database transaction, atomically
publishes a keyring retaining prior decrypt keys, then records the administrative
event under the new primary. CLI maintenance uses the service state lock.

Try failures before/after rename and directory fsync, simultaneous writers and
rotators, an idle stale writer resuming later, corrupted archives/checkpoints,
and downgrade to a binary that only understands a raw key. Test files are
`test_audit_rotation.py` and `test_audit_rotation_cli.py`.

Known limitations: stop all SDK writers explicitly; the CLI lock cannot identify
arbitrary direct library processes. Writers recheck the key under their database
write lock. Old keys remain decrypt-capable, capped at 32 total. Key retirement
and re-encryption of immutable historical chains require a separate migration.

## Backend inventory admission

Review `backend_inventory.py`, `productconfig.py`, generated production configs
and the changed alias adversarial probe. Agent/model/tool data must never supply
inventory entries. Every production network connector must resolve to a trusted
origin with matching domain and permitted route tenants. Existing destination
clearance grouping remains in force; aliases in one inventory entry cannot
split the shared classification floor. Inventory changes require restart.

Try duplicate/case-varied origins, ambiguous/missing domains, cross-tenant
routes, malformed identifiers, alternate accounts on one origin and policy
reloads. Tests are `test_backend_inventory.py`, `test_product_config.py`, and
the product adversarial scenarios.

Known limitation: the operator can provide a wrong account/alias relationship.
No DNS inference or external credential-account attestation is performed. One
origin has one inventory identity, restricting independent SaaS account groups.
Missing origins fail closed; falsely declared separations remain a trust risk.

## Review exit criteria

Record findings with a concrete reproducer, affected boundary, severity and
required remediation. Re-run relevant benign and hostile cases after each fix.
Do not convert the seven expected-failure attack probes into passes or count a
skipped platform test as protection. The historical rc2 report and this review
delta do not provide independent acceptance of the new build.
