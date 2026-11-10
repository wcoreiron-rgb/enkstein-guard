# Durable exact-action approvals

Guard can persist service approval tickets in an encrypted local SQLite store.
The ordinary `ApprovalBook` API remains unchanged, and callers that omit a
store retain the original fail-closed, in-memory behavior.

## Provisioning and wiring

Store creation is explicit and exclusive:

```python
from enkstein_guard.approval_store import ApprovalStore
from enkstein_guard.approvals import ApprovalBook

store = ApprovalStore.initialize(
    state_directory / "approvals" / "approvals.sqlite3",
    key_directory / "approvals.key",
)

# On later starts, open the existing pair. This never creates or regenerates a key.
store = ApprovalStore(database_path, key_path)
store.verify()

book = ApprovalBook(
    approvers=approver_scopes,
    approver_digests=current_credential_digests,
    ttl=900,
    store=store,
)
```

Product-host integration includes this pair in `StateLayout`:

```text
state/approvals/approvals.sqlite3
keys/approvals.key
```

The initialization/adoption flow creates the pair with
`ApprovalStore.initialize(...)` only when provisioning new state. Normal host
startup constructs `ApprovalStore(database, key)` and passes it as `store=` to
`ApprovalBook`. A missing half, an existing path during initialization, unsafe
permissions, corruption, or a replaced key is an error; startup must not
silently regenerate approval state.

Legacy state is upgraded only through the explicit `init --adopt-existing`
flow. Ordinary runtime startup does not provision a missing approval store.
Coordinated maintenance backups include and authenticate the approval pair;
restore refuses a backup without it or with invalid encrypted records.

## Security properties

- A ticket binds tenant, principal, agent, route, operation, resource,
  destination, policy version, and the canonical payload digest.
- Pending, approved, denied, and consumed transitions are stored atomically.
  Expired and consumed tickets cannot authorize an action and are reclaimed
  during normal store maintenance.
- `BEGIN IMMEDIATE` serializes decisions and consumption across processes. Two
  local instances can both observe an approval, but only one can atomically
  consume it before dispatch; the other fails closed.
- The deciding approver ID and credential digest are part of the encrypted
  record. `ApprovalBook` rechecks the current credential digest and tenant
  scope during both satisfaction and consumption. Credential rotation,
  approver removal, or scope revocation invalidates an older approval.
- The SQLite primary key is only a SHA-256 ticket reference. The complete
  binding, status, approver metadata, and redacted human review are
  Fernet-authenticated ciphertext. Sensitive review content is not stored in
  plaintext.
- Global and per-tenant ticket limits are checked inside the same transaction
  that inserts a ticket.
- Database errors, partial/missing state, record tampering, and key replacement
  surface as approval errors. None is interpreted as approval.

Operators must keep both parent directories private (`0700`) and the database
and key private (`0600`), back up the pair consistently, and restrict the key
to the Guard host identity.

## Scope and limitations

This store supports concurrent processes on one host through SQLite locking.
It is not a distributed consensus service and must not be shared over a network
filesystem for multi-host active/active use. It does not defend against a local
administrator who can read or replace both the database and its key together.
There is no implicit key rotation; rotation requires an explicit future
migration that preserves authenticated records. Authenticated encryption
detects record modification but, without an external monotonic checkpoint,
cannot detect restoration of an older valid database snapshot. A coordinated
full-state restore preserves pending approvals, but restoring an older snapshot
can resurrect approval state that was consumed later. Where that risk is not
acceptable, remove only the restored approval database/key pair while the host
is stopped, run the explicit adoption flow to create an empty pair, and require
fresh approvals. Ticket expiry also relies on a trustworthy host wall clock.
