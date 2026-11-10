# Encrypted AI history key rotation

`SecurityHistoryStore.rotate_key()` is an offline administrative operation for
the encrypted AI security-history store. Initialization continues to create a
single raw Fernet key. Legacy raw key bytes, including Fernet-compatible
trailing whitespace, remain exact because those bytes also key the existing
selector HMACs. The first explicit rotation replaces that legacy file
with an ordered JSON keyring whose first entry is the current encryption and
selector key and whose remaining entries are retained decryption keys.
Keyrings contain 1 to 32 valid, unique keys; encodings that decode to duplicate
Fernet key material are rejected so row-to-selector authentication is
unambiguous.

## Safety model

Rotation acquires a stable, private, nonblocking administrative lock and an
SQLite `BEGIN IMMEDIATE` transaction with `synchronous=FULL`. It authenticates
the configured store identity and every history row before publishing a key.
It then durably publishes the fresh primary plus every retained key, including
an fsync of the containing directory, before transactionally rewriting the
identity ciphertext, history ciphertext, and actor and tenant selectors.

History selectors are HMACs derived from a Fernet key. A row is therefore
authenticated by decrypting it with one retained key and checking both its
actor and tenant selectors with that same key. This makes the database
reopenable if the post-publication rewrite rolls back. A later
`rotate_key(resume=True)` reuses the already-published primary and does not add
another key.

The successful result contains only:

```text
current_key_fingerprint  SHA-256 of the current raw Fernet key (64 lowercase hex)
key_count                number of retained keys, including the current key
records_reencrypted      logical history rows rewritten
resumed                  whether the current primary was reused
```

Rotation preserves row IDs, logical records, application timestamps and
expiry, actor isolation, configured TTL, and capacity. Rotation itself does
not purge expired rows; ordinary open/verify/read/write behavior retains its
existing TTL purge semantics. Same-object operations are serialized with
rotation, and a handle whose key file changed out of process remains stale and
is rejected.

## Failure and recovery

- `security_history_key_rotation_busy` means another administrator holds the
  rotation lock. Retry after that operation finishes.
- `security_history_keyring_full` means the bounded 32-key ring cannot accept
  another primary. No automatic retirement is performed.
- A failure before key publication leaves the old key file in place.
- A failure after key publication may leave the database on the retained old
  key. Open a fresh store handle and run `rotate_key(resume=True)`.
- Other rotation failures are fixed, sanitized errors and must be treated as
  an unknown rotation state until the store is reopened and verified.

The keyring is recoverable key retention, not a key-retirement mechanism. This
operation does not provide rollback resistance or claim secure erasure of old
key material. Operators must keep the database, keyring, and rotation lock in
private, non-symlink paths, and back up the database and keyring as one security
boundary.
