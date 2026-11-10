# Security history validation cache

`SecurityHistoryStore` keeps a bounded, per-instance cache of successfully
authenticated history rows. The cache avoids repeating Fernet decryption and
record-schema validation when an unchanged store is scanned repeatedly. It does
not replace any store-wide validation.

Every `verify`, `recent`, and `record` operation still:

- checks the database and key paths, permissions, identity, and configured
  capacity, TTL, and per-actor capacity;
- runs a whole-table scalar count and length-validity preflight, then reads the
  full six-column SQL row set;
- enforces global and per-actor row limits across all tenants and actors;
- validates expired row bodies before applying TTL and purging them; and
- observes rows inserted or changed through another store handle or direct SQL.

The preflight is one SQLite aggregate returning `COUNT(*)` and a `MAX(CASE ...)`
invalid-length flag. It explicitly treats NULL actor, tenant, or ciphertext
lengths as invalid. SQLite returns NULL for `MAX` over an empty table, so only
the scalar pair `(0, NULL)` is accepted for an empty store. A nonempty store must
return an integer count within global capacity and an integer zero invalid flag.
Malformed scalar results, invalid lengths, oversized ciphertext, and excess row
counts fail before ciphertext rows are materialized. A successful preflight is
always followed by the unchanged full six-column query in the same transaction;
its result is not cached and does not narrow the row query.

A cached decode is reused only when the row ID resolves to the exact same SQL
tuple `(id, actor, tenant, created, expires, record)` and the exact key-file
bytes match the epoch under which that tuple was successfully decrypted and
validated. A changed or new row runs the existing authenticated decrypt,
schema, TTL-shape, actor-selector, and tenant-selector validation path. Inserts
are not added to the cache from request values.

The cache stores only immutable raw-row tuples and frozen `HistoryRecord`
values; `HistoryRecord.signals` is a tuple. It does not store request payloads
or mutable record dictionaries. TTL is compared with the current clock on every
operation, including cache hits. Rows removed by TTL purge or per-actor ring
rollover are evicted during the removing operation, and IDs absent from the next
full SQL scan are pruned before row decoding.

The cache uses least-recently-used eviction and has both of these hard bounds:

- 4,096 entries
- 8 MiB of accounted bytes

Per-entry accounting includes ciphertext bytes, actor and tenant selector bytes,
all decoded record and signal string bytes, and an explicit 256-byte fixed
overhead for the entry's remaining fields and references. This accounting limit
is a deterministic application bound, not a claim about secure erasure or the
process allocator's resident-memory usage. Python object, allocator arena, and
other RSS overhead can be higher and should be measured separately.

The cache is cleared when the key-file epoch changes, after successful history
re-encryption, and when integrity validation fails. Key rotation publication,
rollback, resume, and stale-handle behavior remain governed by the existing
key-file and SQLite transaction protocol. The database schema, key formats,
configuration, public API, and on-disk record bytes are unchanged.
