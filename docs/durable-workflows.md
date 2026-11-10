# Durable single-host workflows

`WorkflowStore` is an opt-in SDK persistence layer for
`ProtectedOrchestrator`. It is not automatically attached by the CLI or
service host. Existing callers that omit `store` keep the in-memory behavior
and monotonic-clock deadline semantics.

```python
from enkstein_guard.orchestration import ProtectedOrchestrator
from enkstein_guard.workflow_store import WorkflowStore

store = WorkflowStore.initialize(
    "/private/state/workflows.sqlite3",
    "/private/keys/workflows.key",
)
guard = ProtectedOrchestrator(
    tools=tools,
    controls=controls,
    vault=vault,
    audit=audit,
    task_boundary_factory=task_boundary_factory,
    store=store,
)

# Start and use workflows. The returned opaque credentials must remain in the
# caller's existing credential system; the workflow store saves only digests.

guard.close()  # Only after all async operations have completed.
```

Reopen an existing store explicitly and pass it to a new coordinator:

```python
store = WorkflowStore(
    "/private/state/workflows.sqlite3",
    "/private/keys/workflows.key",
)
guard = ProtectedOrchestrator(..., store=store)
```

Creation never happens during reopen. Missing, replaced, corrupt, oversized,
or differently keyed state fails closed. The database snapshot is encrypted
and authenticated with Fernet; the key, database, lock file, and their parent
directories must be owned by the current user and inaccessible to group and
other users. The authenticated plaintext snapshot is limited to 16 MiB. Raw
credentials and Python callables are never serialized. Vault artifact tokens
are stored because they are required to reopen an artifact, but their values
remain inside the encrypted snapshot and retain the vault's own scope and
expiry enforcement.

## Recovery behavior

The snapshot preserves workflow identities, credential digests, grants,
delegation ancestry, revocations, budgets, calls and units already spent,
deadlines, sticky labels, artifact handles and vault scopes, memory indexes,
mailboxes, and completed handoff identifiers. Task-boundary control callables
are never serialized: each workflow's controls are rebuilt through the
current `task_boundary_factory` before recovered state is exposed.

Recovery requires an exact declared registry match. The fingerprint includes
route names, tenants, operations, resources, destinations, required control
names, component digests and declared capability pins, accepted and produced
labels, units, approval requirements, and the inspection/classifier shape.
This pins declarations, not the Python semantics of a control callback. Code
owners must separately review and pin the implementation that supplies those
controls.

An operation is durably charged before controls or transport dispatch. Calls
and units are never refunded. A coordinator crash may leave an admitted
operation with an unknown outcome; recovery records it as interrupted, clears
its local active-parallelism slot, and never runs it automatically. Results,
artifacts, delegation, memory, mailbox changes, and revocations are returned
to a caller only after the resulting snapshot is committed. A write failure
before dispatch returns `orchestration_storage_unavailable` and no callback ran.
A failed final commit after dispatch returns `orchestration_outcome_unknown`:
the external side effect may have happened, no result or artifact is released,
and callers must reconcile the destination rather than blindly retry. Either
write failure poisons the coordinator; subsequent access is denied until the
process is stopped and the store is inspected and reopened.

In-memory orchestration approvals are intentionally discarded on recovery.
A restarted workflow must obtain fresh authorization. Durable approval tickets
managed by the separate approval store are outside this workflow snapshot and
must still be revalidated by their owning integration.

## Ownership and clocks

The store uses a nonblocking POSIX file lock and a one-object attachment guard.
Exactly one coordinator may own it. This supports one coordinator on one host;
it is not a distributed lease and makes no active-active or multi-host claim.
Call `close()` only after active work reaches zero. `close()` refuses while an
operation is active, commits quiescent state, and releases ownership.

Durable deadlines use wall-clock epoch time rather than process-local
monotonic time. Each snapshot saves the last observed time. Recovery and later
writes fail closed if the supplied wall clock moves behind that floor. This
assumes a trustworthy, finite wall clock that does not roll backward during
normal operation. Restoring an older but otherwise valid database/key pair can
also restore its older clock floor; this layer cannot detect whole-store
rollback by a host administrator. Protect and back up the database and key as
one versioned unit, and do not present this mechanism as protection from a
host administrator or storage rollback.

## Backup boundary

The CLI service does not automatically attach this SDK store, and `backup create` does not discover or include separately supplied workflow stores. Stop and close the embedding coordinator, then back up the workflow database/key together with its matching vault database/key and trusted registry configuration as a quiescent versioned unit. A workflow snapshot without its vault cannot restore artifact content. Do not copy live SQLite files as ordinary files. Recovery keeps budget charges but does not deduplicate a new caller-initiated external action; reconcile interrupted side effects before retrying.
