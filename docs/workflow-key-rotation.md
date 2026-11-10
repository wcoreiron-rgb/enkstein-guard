# Workflow snapshot key rotation

`WorkflowStore.rotate_key()` is an offline administrative operation for the
encrypted SDK workflow snapshot. Initialization deliberately keeps the legacy
single-Fernet-key file format. The first explicit rotation publishes a compact
ordered JSON keyring whose first entry is the current encryption key and whose
remaining entries are retained decryption keys.

## Preconditions

- The store handle must still hold its exclusive host-local owner lock.
- The handle must not be closed or attached to a coordinator.
- Database, key file, lock file, and their parent directories must continue to
  pass the existing private-path checks.
- The keyring must contain 1–32 unique valid Fernet keys. A normal rotation is
  refused when the ring already contains 32 keys.
- Identity and the complete authenticated snapshot must validate before the
  key file is changed.

Stop and close the coordinator before opening a dedicated `WorkflowStore`
handle and calling `rotate_key()`. Do not rotate a copied database separately
from its matching key file.

## Recovery boundary

Rotation takes a SQLite `BEGIN IMMEDIATE` transaction with `synchronous=FULL`,
rechecks the exact key-file bytes under that writer lock, and validates both
durable records. It then atomically publishes and fsyncs the new primary plus
all retained keys before rewriting identity and snapshot ciphertext together
in one transaction.

If rewriting or commit fails after key publication, the transaction rolls
back. The retained ring can still decrypt the old ciphertext. Release the old
owner, open a fresh handle, verify that the snapshot is readable, and call
`rotate_key(resume=True)`. Resume uses the already-published primary, rewrites
both ciphertext records, and does not add another key.

The result contains only:

- `current_key_fingerprint`: lowercase SHA-256 of the current Fernet key bytes;
- `key_count`: the number of retained keys;
- `records_reencrypted`: snapshot records rewritten (currently one; identity is
  deliberately excluded from this count);
- `resumed`: whether the resume path was requested.

Errors and results do not include key material, filesystem paths, or snapshot
content.

## Security and operational limits

This operation retains every prior decryption key. It does not retire keys,
securely erase key material, or provide rollback resistance. The owner lock is
host-local; rotation does not add multi-host or active-active coordination.
Rotation does not alter snapshot schema or workflow semantics: authenticated
state, spent budgets, grants, labels, memory, artifacts, unknown outcomes, and
no-replay state remain byte-for-byte the same plaintext.
