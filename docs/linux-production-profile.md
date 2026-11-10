# Linux/Docker production profile (SDK bootstrap)

> For the CLI product, the supported production deployment is
> [production-deployment.md](production-deployment.md) (`compose.production.yaml`,
> configuration profile `production-linux-peer-bound`), which adds a
> network-less Guard and an independent egress proxy. This page describes the
> same peer-binding rules for hosts that bootstrap `GuardService` from Python.

This profile requires a Linux host and separate container OS UIDs for Guard and each agent. Installing the Python package alone does not establish this boundary.

## Trusted deployment configuration

Run Guard as UID/GID 10001:10001. Assign each agent a distinct nonzero UID (for example 11001 and 11002) with socket-access group 10001. Configure GuardService with an immutable peer_bindings map from each UID to its exact (tenant_id, principal_id, agent_id), socket_group=10001, and per_peer_connections=4. The total reserved connections must fit max_connections. Unsupported platforms and overcommitted reservations fail startup.

Guard owns the shared socket directory, mode 0710, and the socket, mode 0660. Mount that directory read-only into agents; keep Guard state, its bootstrap registry, vault keys, connector credentials, and outcome ledger inaccessible to agents. Bind each agent only its own credential. Do not share the host Docker socket, host network, privileged mode, or Guard UID. Keep agent network access disabled and use admitted Guard connectors for external actions.

Linux SO_PEERCRED identifies the caller before a request frame is read. Unknown UIDs are rejected; a valid credential belonging to a different registered identity is rejected. Each registered UID has a separate connection quota, so silent connections within one quota cannot consume another agents reserved admission slots.

## Operational boundaries

This is admission isolation, not a guarantee against host resource exhaustion. Socket backlog, shared CPU, memory, disk, synchronous vault work, and host availability still need monitoring and capacity planning. Never map mutually untrusted agents to the same UID. Legacy GuardService instances without peer_bindings retain the same-UID preauthentication starvation risk.

Configure all vault tenant reservations during trusted bootstrap before exposing agents. Persisted reservations cannot be silently expanded or shrunk; multi-tenant legacy vaults require explicit limits and a reviewed migration.

Task boundaries must be created by trusted workflow startup with business-approved record IDs, operations, and field constraints. Structural validation does not establish factual correctness or prove a requested business action is appropriate. Keep authoritative authorization and concurrency checks in the downstream service.

The Compose acceptance scripts use synthetic credentials and local fixture transports. They do not constitute live ServiceNow, Hatz, or VirusTotal integration acceptance, an external penetration test, or complete OWASP/ATLAS coverage.
