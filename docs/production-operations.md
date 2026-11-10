# Production operations and release gates (SDK hosts)

For the CLI product (0.5.0rc2) use the [operator guide](cli-operator-guide.md),
[runbook](operations/runbook.md) and [readiness register](cli-production-readiness.md);
they supersede the CLI-relevant parts of this page. This page remains the
reference for hosts that embed the SDK directly.

Enkstein Guard is an application-scoped release candidate. Installing the package
alone does not intercept every process, agent, model API or network connection.
A trusted host must route actions through GuardRuntime/ProtectedOrchestrator,
configure required inspectors, and restrict alternative credentials and egress.

## Durable audit

Initialize `DurableAudit.initialize(database, key_file)` once in trusted bootstrap,
then pass `DurableAudit(database, key_file)` as the runtime/orchestrator `audit`
callback. Use private operator-owned directories, separate from worker-readable
Python runtime paths. No implicit key regeneration occurs. Preserve the key
separately in an access-controlled backup. Records are encrypted using Fernet;
SQLite serializes concurrent local writers and commits before the callback returns.
Runtime-provided events omit payloads. Custom host events must also omit secrets.

`audit.verify()` returns a sequence and encrypted-record digest. Store the latest
checkpoint in a separately controlled system to detect rollback or suffix deletion.
`audit.verify(checkpoint)` checks an exact quiescent snapshot. Keys or checkpoints
on the same compromised host do not provide independent tamper protection.
Since 0.5.0rc1 the sink verifies the stored head and any rows added by other
writers on each append, checks the row count every 64 appends and re-verifies
the full chain at open, every `full_verify_every` appends and on demand.
`DurableAudit.archive()` moves a verified prefix into an encrypted segment and
keeps chain continuity (`verify(archives=...)`); `export()` writes allowlisted
metadata only. Archival is operator-triggered (CLI `audit archive`); there is no
scheduler or remote collector. Audit errors block new actions; post-execution
audit failure means the action may already have happened.

## Backup and recovery drill

1. Stop accepting new actions; drain or cancel workers and record uncertain outcomes.
2. Stop all writers. Record `audit.verify()` outside the host. Back up vault and
   audit databases and their respective keys to access-controlled storage. Do not
   copy an actively written SQLite database as an ordinary file.
3. Restore copies into fresh private directories on a trusted recovery host. Never
   overwrite the only working copy. Open LocalVault and DurableAudit and verify
   the external checkpoint. Exercise a disposable vault entry, restart, and verify
   it can only be restored by the original scope and approved destination.
4. Start a fresh coordinator. In-memory workflow leases, approvals, budgets,
   artifacts and private reply receipts do not survive a restart. Reauthorize
   workflows explicitly; never blindly retry an action with an unknown outcome.

## Upgrade and rollback

Keep the previous wheel, verified digest, dependency set and a quiescent data
backup. Install a candidate in a separate environment. Run all core tests, optional
adapter tests and offline reference workflows before switching the trusted host.
0.5.0rc1 migrates stores in place when opened: the vault gains an accounting
index (rebuilt at every open), the audit ledger gains an encrypted metadata
table when archived, and the outcome ledger switches to identity v2 when
time-bound request IDs are enabled. After that, 0.4.0rc5 refuses the outcome
ledger and an archived audit ledger (fail closed); roll back by restoring the
pre-upgrade backup (`tools/upgrade_rollback_drill.py` exercises this).
0.5.0rc2 migrates the outcome ledger to schema 3 (indexed issuance time and
tenant, archive table); 0.5.0rc1 and older then refuse it, so rollback again
means restoring the pre-upgrade backup.
No release has been published to PyPI by this work.

## Open gates for broader production claims

- Independent egress enforcement: done for the CLI production profile
  (`deployment/compose.production.yaml`); SDK hosts must provide their own.
- Linux/Windows/cloud worker isolation and deployment-specific escape tests.
- Multi-host durable workflow state, distributed budgets and approval recovery.
- Live Cisco and model-provider tests with operator-managed credentials.
- Signed release provenance and an independent human security review
  (unsigned provenance and a review package exist for 0.5.0rc2).
- Versioned adversarial evidence for every claimed OWASP category and applicable
  MITRE ATLAS technique. Current component tests do not establish full coverage.

Do not market universal protection or full OWASP/ATLAS coverage while these gates
remain open. Supported local behavior and unsupported deployment profiles must be
visible to the operator.
