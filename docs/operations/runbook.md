# Operations runbook

All commands take `--config guard.json`. Every command prints one JSON object;
see the [operator guide](../cli-operator-guide.md) for exit codes.

## Service fails to start

| `error` | Meaning | Action |
|---|---|---|
| `service_running_or_state_locked` | another instance owns the state | stop it; never run two owners |
| `production_preflight_failed:<checks>` | wrong platform/UID/root or network interfaces present | fix the deployment (UIDs, `network_mode: none`) |
| `egress_proxy_unavailable` | proxy not healthy | start `egress`; check its allowlist and socket directory |
| `service_already_running` | a live process answers on the socket path | find the other process |
| `unsafe_existing_service_path` | a non-socket or foreign file occupies the socket path | remove it manually after inspection |
| `service_start_failed` | stores unreadable, key missing, permissions unsafe, or the state volume full (opening the ledger and vault writes) | check free space on the state volume first, then run `audit verify`, check `0700` directories and key files |

Stale sockets from a crash are removed automatically only after a refused
connection proves them dead.

## A request returned an uncertain outcome

Statuses `execution_or_audit_failed_outcome_unknown`, `timeout_outcome_unknown`
or `outcome_unknown_no_replay` mean the destination may have executed.

1. `diagnose --id <diagnostic_id>` — confirm the final outcome and route.
2. Check the destination system for the effect.
3. `outcomes list --state uncertain`, then `outcomes resolve --id <hash> --reconciled executed|not_executed`.
   Unresolved records are kept past the archive horizon and consume ledger
   capacity; `doctor` reports them (`outcome_records_unreconciled`) and warns
   when they reduce capacity below the sizing requirement.
4. If the action must still happen, submit it as a **new** request ID. The old
   ID never replays.

## Requests refused before dispatch

`unavailable_no_execution` and `request_tracking_unavailable_or_conflict` with
reason `tracking_unavailable` mean nothing was sent: a required store (outcome
ledger, audit, vault) could not be written, or (`connector_busy`) every
concurrent call slot of the connector (`max_concurrent_calls`) was in use.
Resubmitting the same request ID is safe once the cause is gone.

## Disk full

On a full state volume Guard refuses new work before dispatch
(`request_tracking_unavailable_or_conflict`, reason `tracking_unavailable`),
`service ready` fails and `doctor` warns. Work already dispatched when the disk
filled is reported as outcome unknown and never replays; its final state is
kept in memory and written when space returns (`service status`
`unsettled_outcomes`, `doctor` warning `outcome_states_pending_write`). A
restart while the disk is full fails closed. Free space (or grow the volume);
the running service recovers without a restart and a restarted one starts
normally. Reconcile the unknown outcomes as above. Service events that could
not be written while full are counted (`audit_event_failures`, `doctor`
warning `service_events_lost`); decision records are never skipped, because a
request that cannot be audited is not executed. A full archive volume only
fails retention jobs (reported in `service status`); requests continue and no
partial segment is left behind.

## Revoking an agent

`agent revoke --agent <id>` (reloads automatically). New requests with the old
credential are denied and that agent's in-flight requests are cancelled
(outcome unknown — reconcile as above). Recycle the agent container, then
`agent reset-taint` only if its stored state was discarded.

## Audit verification failure

`audit verify --with-archives` failing means records, archives or keys changed.
Stop the service, preserve the files, compare against the last external
checkpoint and restore the last verified backup. Do not delete or re-initialize
the ledger.

## Retention

Retention is scheduled inside the service (`retention.scheduled`, required in
production); `service status` shows each job's runs, runs that moved records,
failures, last result and longest duration, and `doctor` warns when a job fails.

- Audit archival (every `audit_archive_interval_seconds` when active events
  exceed `audit_archive_threshold_events`) moves all but the newest
  `audit_archive_keep_events` events into encrypted segments in
  `archive_directory`, in chunks of at most 20,000 events so request audit
  writes wait at most one chunk; continuity is kept and `audit verify
  --with-archives` checks the full chain.
- Outcome archival (every `outcome_archive_interval_seconds`) removes terminal
  records issued before `now − outcome_archive_age_seconds` in chunks of about
  5,000, keeps unreconciled uncertain records and persists the cutoff. Any
  request ID issued at or before the cutoff is rejected afterwards (including
  after clock rollback). `outcomes verify-archives` checks every segment.
- Vault purge (every `vault_purge_interval_seconds`) deletes expired entries.
- `retention run --store outcomes|audit|vault|settlement` runs one job now;
  `audit archive` and `outcomes archive` remain available (through the service
  when it runs, otherwise offline under the state lock).
- Archive segments are retained history: they grow with traffic (about 2–4 KiB
  per request; see capacity planning). Move old segments to long-term storage
  only together with an external `audit checkpoint`.

## Backup and restore

Development source after rc2 includes the encrypted approval database/key pair
in coordinated backups. Existing state requires `init --adopt-existing` while
stopped. Older backups without that pair are rejected by the new restore
command: restore them using their matching release, then explicitly adopt with
the new version. Never infer that historical capacity/soak results validate a
new state format. See [durable approvals](../durable-approvals.md) for snapshot
rollback limits and renewal of restored approvals.

Stop the service, then `backup create --data <dir> --keys <dir>` (separate
private directories; keys never go into the data backup). Verify with
`backup verify`. Restore into empty state/key/archive directories with
`backup restore`; it verifies the audit checkpoint and opens every store.
Restoring an older snapshot loses later deduplication history: reconcile any
work done after the snapshot before resuming.

## Upgrade and rollback

1. `service stop`; `backup create`.
2. Install the new wheel or image.
3. `init --adopt-existing` (opens and verifies existing stores, creates missing
   ones, refuses partial stores).
4. `service start`; `service wait-ready`; `doctor`.

0.5.0rc2 migrates the outcome ledger to schema 3 when it first opens it;
0.5.0rc1 and 0.4.0rc5 then refuse the ledger, and 0.4.0rc5 also refuses an
archived audit ledger (both verified by `tools/upgrade_rollback_drill.py`). Roll
back by stopping the service and restoring the pre-upgrade backup into empty
directories, then starting the old version. Production configurations upgraded
to 0.5.0rc2 must add `service.max_requests_per_second` and an outcome capacity
that `config validate` accepts.

## Key handling

Keys live in `key_directory`, separate from data. Losing a key makes its store
unreadable; there is no recovery path. Rotate the vault key offline with
`keys rotate --store vault` (service stopped; existing references keep working).
Other store keys are not rotatable in this release.

## Egress outage

Connector calls fail with outcome unknown while the proxy is down (the audit
records a fixed reason such as `egress_unavailable` or `egress_denied_503`, shown
by `diagnose`); `ready` reports `egress_proxy: false`. Restore the proxy;
reconcile uncertain outcomes.


## Offline connector-secret and approval key rotation

The staged key-lifecycle commands extend the existing CLI:

```text
enkstein-guard --config guard.json keys rotate --store secrets
enkstein-guard --config guard.json keys rotate --store approvals
```

Schedule downtime, stop the service, and create and verify a private paired
state/key backup first. These commands hold the same exclusive state lock as
the service and refuse while it is running. They authenticate audit and store
state before publishing a new primary key, retain old decrypt keys, and rewrite
ciphertext transactionally without changing credential bindings or ticket
approval/consumption state. JSON output contains only counts, a key fingerprint
and fixed status fields; it never returns a secret, key or ticket payload.

If rotation reports `key_rotation_state_unknown`, the keyring may already have
been extended. Repair the reported storage problem and resume using the current
published key rather than generating another:

```text
enkstein-guard --config guard.json keys rotate --store secrets --resume
enkstein-guard --config guard.json keys rotate --store approvals --resume
```

Resume does not add a key. It is supported only for these two stores. A
`rotated_but_audit_unavailable` or `rotated_but_store_verification_failed` error
explicitly reports that rotation occurred; investigate and recover before
restarting. Preflight audit failure leaves rotation unstarted.

New stores keep the legacy raw key format until explicit rotation. Older
raw-only releases cannot open a rotated keyring; rollback requires the complete
paired backup with its matching release. Retaining keys provides interrupted-
write recovery, not key retirement, secure erasure or rollback resistance.
Restoring an old approval snapshot retains the documented resurrection risk.

This work is staged for a later development version. It is not part of the
frozen rc3.dev3 candidate or its acceptance evidence.

## Offline AI-history key rotation (unreleased development)

The development CLI extends the existing command:

```sh
enkstein-guard --config guard.json keys rotate --store security-history
enkstein-guard --config guard.json keys rotate --store security-history --resume
```

Stop the service first and keep a verified paired data/key backup. Rotation uses
the configured history limits, preserves actor bindings and recorded vote data,
and retains older decrypt keys. If a rewrite fails after key publication, keep
the published ring and use resume; do not restore only one half of a backup.
Opening the store still performs ordinary TTL expiry, so fewer records after
reopening need not indicate failed rotation. A rotated-but-audit-unavailable
error means rotation occurred and the audit problem needs attention before
restart. Old releases require the matching pre-rotation backup. This is not key
retirement, secure erasure or rollback resistance. This development code has no production
acceptance; the preserved dev6 baseline does not include this command choice.

### Identity signing-key rotation

With the service stopped, rotate the HMAC key authenticating issued credential
digests and revocations:

```sh
enkstein-guard --config guard.json keys rotate --store identities
enkstein-guard --config guard.json keys rotate --store identities --resume
```

This preserves credential values, generations, revocations, timestamps and the
identity serial. Credentials need no reissue. Output uses `records_reauthenticated`;
the identity JSON is authenticated, not encrypted. Audit verification precedes
rotation, and the CLI reopens and checks identity state before recording success.
If key publication succeeds but rewriting fails, keep the paired store/keyring
and use `--resume`; it does not add another key. A post-rotation audit failure
reports that rotation already happened. Do not restore only an old key or only
a store. Use and verify a paired offline backup.

Retained signing keys remain trusted and could forge records if compromised.
Rotation provides no retirement, secure erasure, rollback resistance or online
service rotation. See [identity-key-rotation.md](../identity-key-rotation.md) for
the retained-key and recovery contract.
