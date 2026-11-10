# Connector secret key rotation

`SecretStore.rotate_key()` is an offline administrative operation for the key
that encrypts connector credentials. Stop the guard host and every maintenance
writer before rotating. Host and CLI service-lock integration is separate from
this store-level API.

## Storage format and compatibility

New stores continue to initialize with the legacy raw Fernet key file. Opening
a store accepts either that raw key or a JSON keyring containing 1–32 unique,
valid Fernet keys. The first JSON key is the current encryption key; the rest
are retained decrypt keys. The legacy file is converted to a JSON keyring only
by an explicit rotation.

Key files, database files, their parent directories, and the stable
`<database>.rotation.lock` file must be private, regular, owner-controlled
paths. Symlinks and group/world permissions fail closed. A loaded store also
remembers the exact key-file bytes, so an ordinary read or writer opened before
another rotation is rejected instead of continuing with stale key material.
`set()` and `remove()` repeat that check after `BEGIN IMMEDIATE`.

## Rotation and recovery

Call the API only while the service is offline:

```python
result = secret_store.rotate_key()
```

The operation acquires the nonblocking administrative lock and a SQLite write
transaction, refreshes and validates the current keyring, identity marker, and
every encrypted secret record, then durably publishes the new primary together
with all old keys. It re-encrypts the identity marker and every record in one
transaction using `MultiFernet.rotate()`. Valid record plaintext is not decoded
and re-serialized during the ciphertext update, so names, values, tenant and
destination bindings, routes, and `updated_at` remain byte-for-byte unchanged.
An authenticated record with missing, extra, duplicate, or incorrectly typed
fields is rejected before key publication.

If failure occurs after the keyring is published, the old keys remain present,
so a new `SecretStore` can still read the rolled-back database. After resolving
the cause, finish the interrupted rewrite without generating another key:

```python
result = secret_store.rotate_key(resume=True)
```

Resume uses the current keyring as-is. It validates the complete store again
and re-encrypts all records under the existing primary key.

The returned dictionary contains only fixed operational metadata:

- `current_key_fingerprint`: SHA-256 fingerprint of the current encoded key
- `key_count`: current plus retained decrypt keys
- `records_reencrypted`: number of connector secret records processed
- `resumed`: whether resume mode was requested

It never contains keys, secret values, connector payloads, or provider output.
Errors use fixed `IdentityError` reason codes and do not include underlying
exception text.

## Fail-closed conditions

Rotation is rejected when another rotator holds the administrative lock, the
keyring already contains 32 keys, paths or permissions are unsafe, the keyring
is malformed, the database identity is invalid, or any secret record cannot be
authenticated and decoded. A failed transactional rewrite rolls back all
ciphertext updates.

## Security boundary and limitations

This mechanism retains prior keys to make interruption recovery possible. It
does **not** retire old keys, securely erase key material, detect restoration of
an older complete database-and-keyring pair, or provide rollback resistance.
Those require a separately designed retirement and external checkpoint policy.
Rotation also does not widen connector scope: `SecretBroker` continues to
enforce the original tenant, route, and destination bindings after restart.
