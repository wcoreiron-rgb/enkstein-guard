# Durable approval key rotation

`ApprovalStore.rotate_key()` is an offline, recoverable rotation operation for
the encrypted durable approval store. It changes encryption keys only. Ticket
IDs, exact-action bindings, expiry times, decisions, approver identity and
credential digests, consumption state, and any authenticated revocation
metadata remain unchanged.

This staging API is not yet a service or CLI workflow. Stop the Guard service
and every approval writer before using it. The per-store administrative lock
prevents simultaneous rotations, but it is not a substitute for the host-wide
offline lock that operator integration must apply.

## Key formats

An unrotated store keeps the legacy raw Fernet key file so an old release can
open a newly initialized, unrotated store. The first explicit rotation converts
that file to a compact JSON array:

```json
["current-primary", "retained-old-key"]
```

The current encryption key is first. Old keys remain decrypt-only fallbacks.
The array is strict and bounded to 1–32 unique valid Fernet keys. Empty,
duplicate, malformed, non-string, oversized, public, or symlinked key material
fails closed. A release that only understands the legacy raw key cannot open a
store after its first rotation.

## Rotation sequence

Call the operation only on trusted local paths:

```python
result = approval_store.rotate_key()
```

The store performs these steps:

1. Acquire the stable private `<key-file>.rotation.lock` with a nonblocking
   exclusive file lock.
2. Check the exact key-file bytes cached when this store object opened.
3. Acquire an immediate SQLite write transaction, recheck those exact bytes,
   authenticate the store identity, and validate every ticket.
4. Refuse before changing anything if 32 keys are already retained.
5. Atomically publish and fsync a keyring containing the new primary followed
   by all old keys.
6. Transactionally re-encrypt the identity and every approval ciphertext using
   `MultiFernet.rotate`, then commit and verify the complete store.

Normal mutating operations also recheck the key file after obtaining their
SQLite write lock. A writer that opened before rotation but waited behind the
rotation therefore fails with `approval_store_key_changed`; it cannot append
with the stale primary.

The result contains only fixed metadata: `rotated`, a SHA-256
`key_fingerprint`, `key_count`, encrypted-record count, and `resumed`. It never
contains raw keys, tickets, approval payloads, or binding fields.

## Interrupted rotation and resume

The new+old keyring is durable before database re-encryption begins. If the
process stops or SQLite rolls back after key publication, old database
ciphertexts remain decryptable through the retained old key. Open a fresh store
object and resume:

```python
recovered = ApprovalStore(database, key_file)
result = recovered.rotate_key(resume=True)
```

Resume reuses the current keyring and does not generate another key. It
authenticates every record again and transactionally completes re-encryption.
Do not repeatedly call ordinary rotation after a post-publication failure;
doing so would add another retained key instead of repairing the interrupted
generation.

Pre-publication write failure leaves the original key file in place. A record
validation failure or full keyring is rejected before publication. A database
update failure rolls back all identity/ticket changes while the retained
keyring keeps the logical store readable.

## Approval semantics

Rotation does not authorize, approve, renew, unconsume, or move a ticket. An
approved ticket remains bound to the same tenant, principal, agent, route,
operation, resource, destination, policy version, payload digest, approver, and
approver credential digest. A consumed ticket remains consumed and cannot be
replayed. Existing tenant filtering and exact-action comparisons remain
authoritative.

## Limits and rollback

Old keys are retained for recovery. This version does not implement key
retirement, secure erasure, external rollback detection, or a claim that old
backups have become unreadable. Coordinated backups include the current
keyring; restoring an older authenticated snapshot also restores its older key
and approval state. Apply the ordinary durable-approval snapshot cautions,
including the possibility that a snapshot predating consumption can resurrect
a then-pending or approved ticket.
