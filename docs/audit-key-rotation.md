# Offline audit key rotation

The durable audit store supports recoverable offline key rotation without
rewriting existing encrypted records. Rotation converts the legacy raw Fernet
key file into an ordered JSON keyring. The first key encrypts new records; all
retained keys can decrypt active records, metadata, and archived segments.

Existing ciphertext is deliberately not re-encrypted. Each audit chain link is
the SHA-256 digest of the exact preceding ciphertext, so rewriting historical
records would change the chain, archive descriptors, and external checkpoints.
Adding keyring indirection keeps all of those bytes and checkpoints unchanged.

## Operator procedure

1. Stop the Guard host and every audit maintenance or export process. Rotation
   is an offline operation.
2. Preserve the latest external checkpoint and back up the current audit key
   file through the normal protected key-backup process.
3. Run the product CLI while the service is stopped:

   ```console
   enkstein-guard --config /path/to/config.json keys rotate --store audit
   ```

   The command takes the normal offline state lock, rotates and reopens the
   store, verifies the complete archive chain, and appends an
   `audit_key_rotated` event with the new primary. Its stable JSON success
   response includes `store: "audit"`, `rotated: true`, `retained_keys`, and the
   final `checkpoint`. `service_running_or_state_locked` means another owner is
   active. `audit_key_rotation_failed` means rotation or pre-rotation
   verification failed. `rotated_but_audit_unavailable` means the keyring was
   published but the post-rotation reopen, verification, or audit append failed;
   inspect the current keyring and verify the store before retrying.

   Library integrations must instantiate the store with full verification and
   supply the configured archive directory:

   ```python
   audit = DurableAudit(*layout.audit, full_verify_every=0)
   result = audit.rotate_key(archives=layout.archive)
   ```

   If the store has recorded archive segments, omitting `archives` fails closed.
   The method fully verifies the archive chain and active ledger before changing
   the key file. Its result contains `rotated`, the number of `retained_keys`,
   and the unchanged pre-command `checkpoint`; it never returns key material.
   Unlike the product CLI, the library method does not append an audit event.
4. Back up the new keyring before restarting the host. The pre-rotation key file
   cannot encrypt or decrypt records appended with the new primary. Store the
   CLI response's final checkpoint as the new external checkpoint.
5. Open a fresh `DurableAudit` instance, verify that final checkpoint with the
   archive directory, then restart the host. Do not reuse an in-memory instance
   created before rotation. The pre-rotation checkpoint remains useful recovery
   evidence but will not exactly match after the CLI's rotation event.

## Locking and failure behavior

Rotation obtains a zero-wait SQLite exclusive transaction. An active writer
therefore makes rotation fail with `audit_key_rotation_failed`; stop the writer
and retry with a fresh store instance. An idle process cannot be discovered
portably, which is why stopping the host is mandatory. Current writers compare
the key file again after acquiring their SQLite write lock, so a stale process
that wakes after rotation fails before appending with the old primary.

The keyring is written to a private temporary file, flushed, atomically renamed,
and followed by a parent-directory flush. Failure before the rename leaves the
old key file intact. If interruption or a directory-flush error occurs after the
rename, the published keyring already contains both the new and old keys; reopen
the store and run full verification. Do not restore the old key file merely
because the rotation command reported failure: first inspect and verify the
currently published keyring, since the rename may already have completed.

The library rotation method does not write the audit database or archive files.
The CLI appends only its new administrative event and does not rewrite historical
ciphertext. Neither path invalidates historical archive digests or checkpoints.

The JSON keyring remains compatible with legacy stores because the first
rotation imports their raw Fernet key. A pre-keyring Guard binary does not
understand the rotated JSON file and will fail closed; do not roll back to that
binary after rotation without a planned store migration.

## Key retention limit

Old keys remain necessary because historical ciphertext is immutable. The
keyring holds at most 32 keys and there is intentionally no online key-retirement
operation. Reaching that limit requires a separately designed, externally
checkpointed ledger migration; deleting a retained key would make older active
records, metadata, or archive segments unreadable.
