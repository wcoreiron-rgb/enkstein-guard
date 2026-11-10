# Vault tenant reservations

CLI configuration: `tenants[].vault_bytes` (all or none) becomes the explicit
`tenant_limits`; without it each configured tenant receives an equal share.
Since 0.5.0rc1 accounting uses an index rebuilt from authenticated records at
every open instead of decrypting every record on each write.

The local vault stores tenant capacity reservations in the encrypted
`tenant-reservations-v1` metadata record. The encrypted envelope repeats that
alias, so moving another metadata value into its place fails the vault integrity
check. Key rotation re-encrypts this record with the rest of the vault metadata.

Production hosts should call `configure_tenants([...])` during trusted bootstrap,
before accepting agent requests. The vault divides its bounded data capacity
evenly among the supplied tenant names, capped by the configured per-tenant
default. Repeating bootstrap with tenants already covered by the record is safe.
Adding a tenant is rejected because changing reservations requires a future
explicit administrative migration.

For compatibility, an unconfigured empty vault binds the first `put` to that
trusted scope's tenant. The binding is persisted atomically with the value. All
later writes from an unknown tenant are rejected, including after restart.

Passing `tenant_limits={...}` at initialization creates exact reservations whose
sum must fit within half of `max_bytes`. A later constructor may repeat the same
limits, but cannot widen or shrink them. Every tenant name must satisfy the same
non-empty, 256-character bound used by vault scopes, and every reservation must
be a positive integer.

When opening a legacy vault without reservation metadata, the vault can infer and
persist a reservation if stored entries belong to at most one tenant. A legacy
vault containing multiple tenants must be opened once with explicit limits that
cover every stored tenant. Operators should choose those limits from the
deployment's known tenant allocation; the vault does not infer a multi-tenant
split from traffic history.
