# Enkstein Guard CLI operator guide (0.5.0rc2)

This guide takes a new operator from installation to a running, inspected and
recoverable single-host deployment. The supported production target is Linux
ARM64 containers using `deployment/compose.production.yaml`; see
[production deployment](production-deployment.md) for the container topology.
The same commands work in the `development` profile on one host for evaluation.

Installing the package does not mediate anything by itself. Protection exists
only for agents that can reach their tools solely through a running Guard
service in the production profile (`enkstein-guard doctor` reports this).

## 1. Install

```sh
python -m pip install dist/deployment/enkstein_guard-0.5.0rc2-py3-none-any.whl
enkstein-guard --version
enkstein-guard doctor
```

Python 3.11+ is required (validated: 3.12 Linux ARM64 glibc and musl, 3.14 macOS
for library tests). Containers install from the hash-locked wheelhouse; see
`tools/build_candidate_image.sh`.

## 2. Output contract and exit codes

Every command (and `--version`) prints exactly one JSON object on stdout
containing `"schema": "enkstein-guard.cli/v1"`; `--help` prints human-readable
usage. Nothing prompts. Errors contain a fixed
`error` code (and, for configuration, a list of `{path, code}`), never exception
text, input values or secrets.

| Exit | Meaning |
|---|---|
| 0 | Success; request allowed or already completed |
| 2 | Policy outcome: denied, approval required or response withheld |
| 3 | Failed safely: invalid input, configuration, state or verification |
| 4 | Service unavailable or not ready |
| 5 | Outcome unknown: the action may have executed — reconcile, never retry blindly |
| 64 | Usage error |

Secrets are accepted only from a private file (mode `0600` or stricter, not a
symlink) or `-` (stdin). No command accepts a secret as an argument.

## 3. Configure

Write a schema-version-2 configuration (no secrets). Start from
[the configuration reference](configuration-reference.md) and validate it:

```sh
enkstein-guard --config guard.json config validate
enkstein-guard --config guard.json policy explain
```

Validation is strict: unknown fields, duplicate JSON keys, wrong types, values
out of range, unknown references and unsafe production settings are rejected
with stable codes such as `peer_binding_required_in_production`,
`shared_agent_uid_forbidden`, `direct_egress_forbidden_in_production`,
`destination_not_on_egress_allowlist`, `endpoint_host_not_canonical` or
`outcome_capacity_insufficient_for_request_rate`. The last one carries a
`detail` with the configured rate, record lifetime, required and configured
capacity and the sustainable rate; `config validate` always prints this
computation as `outcome_sizing` (development profiles get it as a warning).

## 4. Initialize state

```sh
enkstein-guard --config guard.json init
```

Creates, exclusively and with private permissions, the state directory (vault,
audit ledger, outcome ledger, taint store, identity store, connector secret
store, document store) and a separate key directory. It never overwrites or
regenerates an existing store or key. Upgrading from 0.4.0rc5 stores placed at
the configured paths uses `init --adopt-existing` (existing complete stores are
opened and verified, missing ones created; partial stores are refused).

## 5. Register identities

Agents, their tenant, principal, UID, routes, clearance, groups and task are
declared in configuration. Guard issues the bearer credential:

```sh
enkstein-guard --config guard.json agent issue --agent agent-a --output /secure/agent-a.token
enkstein-guard --config guard.json approver issue --approver alice --output /secure/alice.token
enkstein-guard --config guard.json agent list
```

The credential is written once to a new `0600` file and only its SHA-256
digest is stored. Issuing again rotates it. Deliver the file to the agent's
container as a read-only mount owned by the agent UID. Revocation:

```sh
enkstein-guard --config guard.json agent revoke --agent agent-a
```

Two host names that reach the same backend must be declared with one
`data_domain` on their connectors (see the configuration reference); otherwise
Guard treats them as different destinations.

When the service is running, identity commands trigger a reload: new requests
with the old credential are denied and the agent's in-flight requests are
cancelled (recorded as outcome unknown). Agent and approver credentials are
distinct; agent credentials can never approve.

A reload also cancels in-flight work whose authorization it revokes or changes:
the agent lost the route's grant, its tenant, principal or task changed, its
clearance was lowered or a group removed, or the route or the route's connector
changed. Work whose authorization is unchanged or only widened continues; its
response is released only if both the old and the new policy allow it (lower
clearance, higher `produces`, stricter grounding).

## 6. Connectors and secrets

```sh
enkstein-guard --config guard.json connector list
enkstein-guard --config guard.json connector secret-set --name hatz-key --tenant tenant-a \
    --destination ai.example.com --route model.chat --value-file /secure/hatz.key
enkstein-guard --config guard.json connector secret-list
```

Secrets are encrypted at rest and bound to a tenant, destination and routes;
the binding must match the configured route. The listing never shows values.
Supported connector types: `chat_completions` (bearer or `x-api-key`, e.g. the
Hatz header shape), `virustotal_ip`, `retrieval_local` and the synthetic
`fixture` (acceptance only; `doctor` and `status` report it).

Documents for `retrieval_local` are ingested by the operator only:

```sh
enkstein-guard --config guard.json retrieval ingest --tenant tenant-a --collection kb --file docs.jsonl
```

Each JSON line has `doc_id`, `content`, `label`, `principals` and/or `groups`
(and optional `title`). Agents cannot write documents or supply ACLs.

## 7. Start, inspect and stop

```sh
enkstein-guard --config guard.json service start          # foreground; supervise with Compose/systemd
enkstein-guard --config guard.json service wait-ready --timeout 30
enkstein-guard --config guard.json service status
enkstein-guard --config guard.json doctor
enkstein-guard --config guard.json service reload         # re-read policy and identities
enkstein-guard --config guard.json service stop           # drain, then cancel
```

`service start` holds the single-owner state lock (a second instance is refused)
and, in production, refuses to start off Linux, as root, as a UID other than
`deployment.guard_uid`, with any network interface other than loopback, or with
an unhealthy egress proxy. Stale sockets left by a crash are removed only after
a refused connection proves them dead. `ready` succeeds only when the service
socket, audit chain, outcome ledger, vault, egress proxy and service-event
recording are healthy. `reload` applies policy, identity, route, task-boundary,
approver and sensitivity changes; changes to paths, service limits, profile,
agent UIDs, egress, vault, outcome or tenant settings return `restart_required`
and keep the running policy.

`doctor` reports each control as `installed`, `configured`, `active`,
`unavailable` or `unsupported`. `mandatory_enforcement_status` is `active` only
for a running production-profile service with peer binding, no network
interfaces and no synthetic connectors.

## 8. Agent requests

Agents speak one JSON line per connection to the Guard socket (see
`service.guarded_request`). For testing:

```sh
enkstein-guard request --socket /run/guard/guard.sock --credential-file agent.token \
    --route ticket.comment --payload-file payload.json --new-request-id
```

Production requires time-bound request IDs (`<unix-seconds>-<random>`); reuse
the same ID only to resubmit the identical request (for example after approval).
Responses always include `diagnostic_id`. Statuses:

| Status | Executed? | Client action |
|---|---|---|
| `ok` | yes | — |
| `denied` | no (policy) | review policy |
| `approval_required` (with `ticket`, `action_digest`) | no | obtain approval, resubmit identical request with the ticket |
| `response_withheld` | yes, output not released | — |
| `completed_no_replay` | earlier, once | — |
| `in_progress` | being executed | wait; do not resubmit with a new ID |
| `busy` (reason `rate_limited` when over the agent's rate share) | no, not tracked | retry later |
| `unavailable_no_execution` (reason `audit_unavailable`, `vault_unavailable`, `tracking_unavailable`) | no: a required store failed before dispatch (for example a full disk) | restore storage, then resubmit (the same ID is accepted) |
| `request_tracking_unavailable_or_conflict` (reason) | no | fix the request ID or storage; `outcome_capacity_reached` means the ledger is full |
| `request_read_timeout_no_execution`, `invalid_request_or_response` | no | fix the client |
| `outcome_unknown_no_replay`, `execution_or_audit_failed_outcome_unknown`, `timeout_outcome_unknown`, `response_unavailable_outcome_unknown` | maybe | reconcile with the destination; never resubmit blindly |

Guard never retries. When the outcome ledger cannot record a final state (for
example while the disk is full), Guard keeps the state in memory, answers
resubmissions of that ID correctly (never replaying), and writes the state when
storage recovers; a restart before that turns the record into
`outcome_unknown_no_replay`.

## 9. Approvals

Routes with `"approval": "required"` always need a human decision; `"on_demand"`
routes need one only when a control returns require-approval.

```sh
enkstein-guard --config guard.json approvals list
enkstein-guard --config guard.json approvals review --ticket T --approver-credential-file /secure/alice.token
enkstein-guard --config guard.json approvals approve --ticket T --digest D --approver-credential-file /secure/alice.token
```

Review shows the bound route, resource, destination, identities and the payload
with detected sensitive values masked. Approval requires the approver's
credential (scoped to the ticket's tenant) and the exact `action_digest`. The
agent then resubmits the identical request with `--approval T`; the ticket is
consumed immediately before dispatch and never reused. Tickets live in memory
and expire (default 900 s); a restart discards them.

## 10. Audit, diagnostics and outcomes

```sh
enkstein-guard --config guard.json audit verify [--with-archives] [--checkpoint saved.json]
enkstein-guard --config guard.json audit checkpoint --output /external/checkpoint.json
enkstein-guard --config guard.json audit export --output /secure/audit.jsonl [--with-archives]
enkstein-guard --config guard.json audit archive [--keep 10000]
enkstein-guard --config guard.json diagnose --id <diagnostic_id>
enkstein-guard --config guard.json outcomes list --state uncertain
enkstein-guard --config guard.json outcomes resolve --id <hash> --reconciled executed
enkstein-guard --config guard.json outcomes archive
```

`outcomes list` and `outcomes verify-archives` ask the running service (opening
the ledger from a second process would disturb in-flight records); offline
they take the state lock. `verify-archives` checks every outcome segment file
(present, digest, header, record count).

Retention also runs inside the service on the configured schedule
(`retention.*_interval_seconds`): outcome archival, audit archival above the
threshold, vault purge and retry of pending outcome states. `service status`
shows each job's runs, failures, last result and duration; `doctor` warns on
failing jobs, a ledger above 80 % of capacity, pending state writes, and
unreconciled outcomes kept below the archive cutoff
(`outcome_records_unreconciled`; `outcome_capacity_reduced_by_unreconciled_records`
when they push the required capacity over the configured one). Unreconciled
uncertain records stay until resolved, so the sizing headroom does not bound
them.
`enkstein-guard retention run --store outcomes|audit|vault|settlement` runs one
job now. Archive files are retained history and grow with traffic (see
capacity planning); move older segments to long-term storage only together
with an external audit checkpoint.

Store checkpoints outside the host to detect rollback. Export writes only
allowlisted metadata fields to a new `0600` file. `diagnose` explains the final
outcome, the denying or failed controls and the safe next action
(`review_policy`, `obtain_approval`, `reconcile_with_destination_before_new_request`).
Resolving an uncertain outcome records the reconciliation; the request ID still
never replays. Outcome archival keeps unreconciled uncertain records, persists
a cutoff, and from then on rejects any request ID issued at or before it.

## 11. Backup, restore, upgrade, rollback

```sh
enkstein-guard --config guard.json service stop
enkstein-guard --config guard.json backup create --data /backup/data --keys /backup/keys
enkstein-guard --config guard.json backup verify --data /backup/data --keys /backup/keys
enkstein-guard --config guard.json backup restore --data /backup/data --keys /backup/keys   # into empty state/key dirs
```

Backups require the service to be stopped (state lock). Data and keys go to
separate private directories. Restore refuses non-empty targets and verifies
the audit checkpoint and every store. Upgrade: stop, back up, install the new
wheel, `init --adopt-existing`, start. After an upgrade enables time-bound IDs
or archives audit, the older release refuses the stores (fail closed); roll
back by restoring the pre-upgrade backup. See [operations runbook](operations/runbook.md).

## 12. Egress proxy

```sh
enkstein-guard --config guard.json egress check --host ai.example.com --port 443
enkstein-guard --config guard.json egress serve       # separate process/UID with network access
```

The proxy accepts only `CONNECT host:port` for allowlisted destinations from the
Guard UID, resolves names itself and requires every resolved address to be
globally routable unless the rule lists explicit networks. TLS stays end to end.


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
service rotation. See [identity-key-rotation.md](identity-key-rotation.md) for
the retained-key and recovery contract.
