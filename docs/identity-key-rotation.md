# Identity signing-key rotation

`IdentityStore.rotate_key()` is an offline, recoverable operation for the HMAC
key that authenticates identity credential records. HMAC authenticates the JSON
store; it does **not** encrypt identity IDs, credential digests, generations,
timestamps, revocation state, serial, or other authenticated metadata.

This staging API is not yet a service or CLI workflow. Stop the Guard host and
all identity writers before using it. The per-store lock prevents simultaneous
local rotation and writing, but it is not a substitute for the host-wide
offline lock that integration must provide.

## Key format and validation

New stores continue to initialize with the legacy raw 64-character hex key.
Opening legacy raw keys preserves the prior `bytes.fromhex` compatibility:
uppercase and ASCII whitespace, including a trailing newline or whitespace
between encoded bytes, are accepted when the decoded value is exactly 32
bytes. The exact original file bytes are still cached for stale-key detection.
Key-file reads are bounded to 8 KiB.
The first ordinary rotation replaces it with a compact JSON array containing
the new primary first and every retained signing key after it:

```json
["current-64-character-hex-key","retained-64-character-hex-key"]
```

JSON rings are canonical compact arrays of 1–32 unique lowercase hex values,
each decoding to exactly 32 bytes. Empty, duplicate, malformed, noncanonical,
oversized, public, non-regular, or symlinked key material fails closed. A
release that only understands the legacy raw key cannot open a rotated store.

The identity envelope must contain its v1 schema, agent and approver maps, and
nonnegative serial. Every known credential record field is validated: the
identity name, SHA-256 digest, positive generation, nonnegative issue time, and
optional nonnegative revocation time. Additional authenticated metadata is
preserved without re-serialization into a reduced schema; invalid known fields
are rejected before key publication.

## Rotation and recovery

Call rotation only on trusted local paths:

```python
result = identity_store.rotate_key()
```

The operation acquires an in-object nonblocking rotation guard, the object's
reentrant lock, and the stable private `<identity-store>.lock` file lock. It
then checks the exact cached key-file bytes, authenticates the envelope under
any retained key, and validates the complete body. Only after validation does
it atomically publish and fsync the new-plus-retained ring. Finally, it
atomically reauthenticates the exact same body under the current primary.

Rotation does not increment `serial`, issue or replace credentials, change a
digest or generation, or clear revocation. Normal writers check the cached
key-file bytes after acquiring the writer lock, so a handle opened before
rotation cannot sign with a stale primary.

The result contains only fixed operational metadata:

- `current_key_fingerprint`: SHA-256 of the decoded current signing key
- `key_count`: current plus retained signing keys
- `records_reauthenticated`: total agent and approver records
- `resumed`: whether resume mode was requested

`verify()` performs full key, HMAC, body, and record validation and returns
only `records` and `serial`; it does not return credential digests.

If failure occurs after the ring is published but before the envelope rewrite,
the unchanged envelope is still verifiable under its retained old key. Open a
fresh handle and finish without generating another key:

```python
recovered = IdentityStore(identity_file, key_file)
result = recovered.rotate_key(resume=True)
```

Resume reuses the published primary and does not grow the ring. A corrupt or
schema-invalid envelope and a full ring are rejected before publication.
Backups must keep the authenticated identity file and its matching key file
together.

## Security limits

Retained signing keys remain fully trusted HMAC keys. If any retained key is
compromised, it can forge identity records; retained keys are not merely
read-only verification material. This version provides no key retirement,
secure erasure, external rollback detection, rollback resistance, multi-host
coordination, or online host reload guarantee. Those require separate policy
and lifecycle designs.
