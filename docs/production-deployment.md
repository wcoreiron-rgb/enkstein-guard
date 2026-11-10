# Production deployment: single-host Linux/Docker, peer-bound profile

Supported: one Docker host running Linux ARM64 containers, the
`production-linux-peer-bound` profile and `deployment/compose.production.yaml`.
Not supported: multiple Guard hosts sharing state, high availability, other CPU
architectures, Windows, Kubernetes or cloud-specific isolation.

## Topology

| Service | UID:GID | Network | Mounts | Role |
|---|---|---|---|---|
| `initialize` | 0:0 (CHOWN/FOWNER/DAC_OVERRIDE only) | none | all Guard volumes | sets ownership/modes once |
| `egress` | 10002:10003 | `egress` bridge (only member with outbound access) | egress socket volume, bootstrap (ro) | `enkstein-guard egress serve` allowlist proxy |
| `guard` | 10001:10001 + group 10003 | **none** (loopback only) | IPC, admin, state, keys, archive, egress socket (ro), bootstrap (ro) | `enkstein-guard service start` |
| `agent` | per-agent UID (e.g. 11001):10001 | none | IPC socket (ro), its own token (ro) | untrusted workload |

All long-running containers (`egress`, `guard`, `agent`) run read-only, drop
all capabilities, set `no-new-privileges` and have PID/memory/CPU limits. The
one-shot `initialize` container runs as root with only `CHOWN`, `FOWNER` and
`DAC_OVERRIDE`, no network and no limits, and exits after setting ownership.
Agents never see state, keys, connector secrets, the admin socket or the egress
socket.

Enforcement layers:

1. **Kernel/network**: Guard and agents have no network interfaces; only the
   egress proxy can reach the network, and only for allowlisted destinations
   (it resolves names itself and checks every resolved address).
2. **Peer identity**: Guard reads each caller's Linux UID with `SO_PEERCRED`
   before reading the request and binds it to exactly one configured
   tenant/principal/agent; a credential stolen from another agent is rejected,
   and each UID has its own connection quota.
3. **Policy**: credential digest, route grant, sensitivity clearance and taint
   and audit for every request; task boundaries and approvals on the routes
   configured with them.

## First deployment

```sh
# Deploy by digest once the image is signed; the tag is shown for readability.
export GUARD_IMAGE=enkstein-guard:0.5.0rc2 GUARD_BOOTSTRAP_DIR=/srv/guard/bootstrap
docker compose -f deployment/compose.production.yaml up initialize
docker compose -f deployment/compose.production.yaml run --rm --no-deps guard \
    --config /bootstrap/guard.json init
docker compose -f deployment/compose.production.yaml run --rm --no-deps \
    -v /srv/guard/credentials:/credentials guard --config /bootstrap/guard.json \
    agent issue --agent agent-a --output /credentials/agent-a.token
# chown the token to the agent UID and mode 0400 before mounting it into the agent
docker compose -f deployment/compose.production.yaml run --rm --no-deps -T guard \
    --config /bootstrap/guard.json connector secret-set --name hatz-key --tenant tenant-a \
    --destination ai.example.com --route model.chat --value-file - < /secure/hatz.key
docker compose -f deployment/compose.production.yaml up -d egress guard
docker compose -f deployment/compose.production.yaml exec guard \
    enkstein-guard --config /bootstrap/guard.json doctor
```

`guard.json` (read-only bootstrap) contains no secrets. Keep the bootstrap
directory, credentials directory and backups outside agent reach.

## Day-2 operations (inside the guard container, as UID 10001)

```sh
docker compose -f deployment/compose.production.yaml exec guard enkstein-guard --config /bootstrap/guard.json service status
docker compose -f deployment/compose.production.yaml exec guard enkstein-guard --config /bootstrap/guard.json approvals list
docker compose -f deployment/compose.production.yaml exec guard enkstein-guard --config /bootstrap/guard.json agent revoke --agent agent-a
docker compose -f deployment/compose.production.yaml exec guard enkstein-guard --config /bootstrap/guard.json audit verify
```

The admin socket accepts only the Guard UID. Approver credentials should be
supplied on stdin or via a file in the container's private tmpfs, then removed.

## Sizing, storage and logs

- State (`guard-state`) holds the active stores; they plateau once scheduled
  retention runs (see [capacity planning](operations/capacity-planning.md)).
  Keep it on its own volume with free-space monitoring: when it fills, Guard
  refuses new work before dispatch and recovers by itself once space returns
  (see the runbook, "Disk full").
- Archives (`guard-archive`) are retained history and grow with traffic; give
  them a separate volume. A full archive volume only fails retention jobs.
- The egress proxy writes one JSON line per tunnel decision to stdout; configure
  Docker log rotation (for example `--log-opt max-size`) on the host.
- `service.max_requests_per_second` and `outcomes.capacity` must satisfy the
  sizing rule that `config validate` checks.

## Executed acceptance

The container checks use synthetic credentials, a synthetic TLS upstream and
disposable Compose projects:

- `deployment/test_production_profile.py`: readiness with peer binding,
  loopback-only Guard and a healthy proxy; task boundary allow/deny; ungranted
  route denial; stolen cross-UID credential denial; the model connector reaching
  the upstream only through the proxy with the brokered key and a tokenized
  email; provider-side fetch and tool fields refused before dispatch; tainted
  summary denial; exact-action approval and replay denial; Guard direct-network,
  unlisted-host and wrong-port denial; proxy rejection of a non-Guard UID; forced
  kill/restart with duplicate suppression; revocation; audit verification and
  secret-free export and logs.
- `deployment/test_production_capacity.py` and `deployment/test_production_soak.py`:
  load from several network-less agent containers with their own UIDs through
  peer binding, the egress proxy and TLS (targets in `docs/operations/`).
- `deployment/test_production_disk_full.py`: tmpfs-backed state and archive
  volumes filled under load.

Results for each candidate are in `verification/<version>/` (0.5.0rc2:
`verification/0.5.0rc2/`; 0.5.0rc1: `verification/cli-v1/`).

## Limits

Admission and egress isolation do not protect against a compromised container
host, kernel escapes, or processes started outside this profile. Shared CPU,
memory, disk and socket backlog need host monitoring. The egress proxy is a
destination allowlist, not content inspection. One Guard instance owns one state
directory; there is no failover.
