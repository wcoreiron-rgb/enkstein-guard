# Capacity planning and measured results

Targets were committed before measurement and their SHA-256 digests are
embedded in every report:

- [`capacity-targets.json`](capacity-targets.json) — development-profile request
  path, T-01 to T-09 (defined 2026-10-28T00:03:00Z);
- [`capacity-targets-production.json`](capacity-targets-production.json) —
  production-profile capacity and concurrency, P-01 to P-05 (defined 2026-10-28T18:05:00Z);
- [`soak-targets.json`](soak-targets.json) — production-profile soak with
  scheduled retention, S-01 to S-08 (defined 2026-10-28T18:08:00Z, revised once at
  18:08:30Z before any soak measurement; the revision note is in the file).

They are single-host v1 acceptance requirements, not service-level agreements.
The 0.5.0rc1 version of this page is kept in
[`../release/capacity-planning-0.5.0rc1.md`](../release/capacity-planning-0.5.0rc1.md).

## Sizing rules

- **Request rate.** `service.max_requests_per_second` (required in production)
  is shared equally by the configured agents; each agent gets a token bucket
  with that share and a burst of twice the share (at least 1). Excess requests
  answer `busy:rate_limited` before anything is tracked or sent.
- **Outcome ledger.** Every tracked request occupies one record until scheduled
  archival removes it, which happens only after
  `retention.outcome_archive_age_seconds` and at most
  `retention.outcome_archive_interval_seconds` later. Size

  `outcomes.capacity ≥ 1.1 × max_requests_per_second × (outcome_archive_age_seconds + outcome_archive_interval_seconds + outcomes.clock_skew_seconds)`

  and give the busiest tenant enough of its equal share of capacity for its
  agents' share of the rate. Production validation fails with
  `outcome_capacity_insufficient_for_request_rate` (the detail gives the required
  capacity and the sustainable rate); development validation warns.
  `config validate`, `service status` and `doctor` show the calculation.
  Example: 40 req/s, archive age 1 h, interval 5 min, skew 300 s →
  1.1 × 40 × 4,200 = 184,800 records (the acceptance deployments use 200,000).
  The formula bounds reconciled traffic only: uncertain outcomes stay in the
  ledger until an operator resolves them, past the archive horizon, and the 10 %
  headroom is a planning margin, not a bound on them. `service status` reports
  them as `retained_below_cutoff`; `doctor` warns (`outcome_records_unreconciled`,
  and `outcome_capacity_reduced_by_unreconciled_records` once they push the
  requirement above the configured capacity).
- **Vault.** Live tokenized values ≤ `vault.max_entries`; each tokenizing request
  adds up to one entry per distinct sensitive value, kept for
  `token_ttl_seconds`. Sustained rate ≈ `max_entries / token_ttl_seconds` values/s.
  Expired entries are deleted on insert and by the scheduled purge.
- **Audit.** About two to four events per request. Scheduled archival moves
  events above `retention.audit_archive_threshold_events` to segments, keeping
  `audit_archive_keep_events`; startup verification time grows linearly with
  active events (≈1 s per 100,000).
- **Archives.** Archived outcome records and audit segments are retained history
  and grow with traffic (soak S-08 measured the growth per request); rotate the
  archive volume according to your retention policy.
- **Connections.** `max_connections` bounds concurrent requests; in production
  each agent UID reserves `per_peer_connections`. `max_concurrent_calls` bounds
  calls per network connector (default 16); a full connector answers
  `unavailable_no_execution` (`connector_busy`) without sending anything.

## Production profile (0.5.0rc2)

Deployment: `deployment/compose.production.yaml` with the acceptance overlay —
network-less Guard (UID 10001, limited to 1 CPU and 512 MiB), egress proxy
(UID 10002), synthetic TLS upstream reachable only through the proxy, and four
network-less agent containers with separate UIDs (11001–11004) in two tenants;
load is generated inside the agent containers. Host: Colima VM with 4 vCPU and
6 GiB (Docker Engine 29.5.2). The synthetic upstream answers immediately, so
provider latency is excluded. Image `sha256:a18a86b7…`.

### Capacity and concurrency (`verification/0.5.0rc2/production-capacity.json`)

All five targets met (`doctor` reported mandatory enforcement `active` for
this deployment). Every phase required every launched agent to exit 0, and
rate-driven agents to issue at least 95 % of their offered requests.

| Target | Requirement | Result |
|---|---|---|
| P-01 sustained mixed load: 4 agents × 5 req/s, 600 s | 0 non-ok; p50 ≤ 100, p95 ≤ 300, p99 ≤ 750 ms; Guard RSS ≤ 256 MiB, fds ≤ 256; egress RSS ≤ 96 MiB; 0 duplicate executions; resubmitted completed IDs answer `completed_no_replay` | 12,000 requests, 0 non-ok; p50 14.2 / p95 31.7 / p99 73.8 ms; Guard 42.2 MiB, 12 fds, 6 threads; egress 37.3 MiB; 9,603 upstream executions, 0 duplicates; 80/80 probes `completed_no_replay`; 3,000 requests per agent |
| P-02 saturation: 4 agents × 4 closed-loop clients, 120 s | only `ok` / `busy:rate_limited`; ok ≥ 0.9 × 40 req/s × 120 s; admitted per agent ≤ 1.1 × share; ok p95 ≤ 1,000 ms; tracked = executed | 4,876 ok (≥ 4,320), 32,749 rate-limited; 1,219 ok per agent (limit 1,340); p95 16 ms; tracked 4,876 = ok; 3,853 upstream executions = model calls ok |
| P-03 fairness: flooder (8 clients, beyond its 4 connections) vs light agent at 2 req/s, 120 s | light ok ≥ 99 %, light p95 ≤ 500 ms; flooder only ok/busy | light 240/240 ok, p95 32 ms; flooder 1,217 ok, 3,926 busy, 11,977 rate-limited |
| P-04 Guard killed under load at 40 s (4 agents × 5 req/s, 120 s; every 10th chat answered after 2 s) | 0 duplicate executions; every lost response resubmitted, answered `ok`, `completed_no_replay` or `outcome_unknown_no_replay`; ≥ 1 lost after admission; ready ≤ 60 s | ready 3.9 s after restart; 55 lost (52 refused while Guard was down, 3 in flight); resubmissions 52 `ok`, 3 `outcome_unknown_no_replay`; 0 duplicates over 16,521 executions |
| P-05 provider-side fetch and tool fields | refused before dispatch; 0 upstream requests | `image_url`, `web_search`, hosted tool, `store`: denied; 0 upstream requests |

### Soak (`verification/0.5.0rc2/production-soak.json`)

All eight targets met over 10,800 s (4 agents × 2 req/s; outcome archival every
300 s at 3,600 s age; audit archival every 300 s above 20,000 events keeping
5,000; vault purge every 60 s; token TTL 300 s; sampled every 60 s).

| Target | Requirement | Result |
|---|---|---|
| S-01 availability | 0 non-ok; every agent completes ≥ 95 % of offered requests | 86,400 requests, 0 non-ok; 21,600 per agent |
| S-02 latency | p95 ≤ 300, p99 ≤ 750 ms; every 60 s window p99 ≤ 2,000 ms | p50 17.3 / p95 28.5 / p99 65.4 ms; worst window p99 219 ms |
| S-03 memory | Guard RSS ≤ 256 MiB; last-hour max ≤ first-hour max + 32 MiB; egress ≤ 96 MiB | 43.0 MiB max (first hour 40.7, last hour 43.0); egress 36.9 MiB |
| S-04 fds and threads | fds ≤ first sample + 16; threads ≤ 64 | fds 9 → 14; threads ≤ 7 |
| S-05 active stores | outcomes ≤ 37,000; audit active ≤ 35,000; vault live ≤ 2,000, expired ≤ 1,000; state ≤ 256 MiB and end ≤ 1.15 × two-hour mark | 31,180; 24,079; 537 and 11; 53.4 MB, ratio 1.002 |
| S-06 retention on schedule | outcome runs with records ≥ 20, audit ≥ 6, vault purges ≥ 60; 0 failures | 25 (57,760 records), 8 (153,898 events), 181; 0 failures; longest run 0.79 s |
| S-07 integrity and no replay | audit chain with archives and outcome archives verify; 0 duplicates; recent IDs `completed_no_replay`; archived IDs refused as expired | verified (25 segments, 57,760 records); 0 duplicates over 69,418 executions; 200/200; 40/40 `request_id_expired` |
| S-08 archive growth | ≤ 4,096 bytes per tracked request | 2,583 bytes |

## Development profile (0.5.0rc2, all nine targets met)

Run inside the candidate image (no network, read-only root, UID 10001) on the
same 4-vCPU Colima VM, development profile on one OS user with a synthetic
fixture connector (`verification/0.5.0rc2/operational-acceptance-container.json`,
directly bound to the executed image ID). It measures the request path without
peer binding, preflight or the egress proxy.

| Target | Requirement | Result |
|---|---|---|
| T-01 sustained | 25 req/s ≥ 300 s; p50 ≤ 50, p95 ≤ 150, p99 ≤ 300 ms; 0 errors | 7,500 ok in 300 s; p50 6.1 / p95 9.0 / p99 13.6 ms |
| T-02 burst | 32 closed-loop clients 60 s; only ok/busy | 44,124 ok, p95 48 ms |
| T-03 populated vault | ≥ 8,000 live entries, 4 tenants; tokenizing p95 ≤ 250 ms; 0 cross-tenant restores | 8,000 entries; p95 3.3 ms; 0/40 cross-tenant restores |
| T-04 audit | 100,000 events: append p95 ≤ 25 ms, full verify ≤ 60 s, archive ≤ 120 s | 104,247 events; append p95 0.15 ms; verify 1.4 s; archive 2.8 s |
| T-05 outcome ledger | 9,000/10,000 records: begin+finish p95 ≤ 25 ms; archived IDs accepted 0 | p95 0.41 ms; 0/50 accepted |
| T-06 startup | populated state ready ≤ 30 s | 4.1 s (104,248 audit events, 180,100 outcomes, 8,201 vault entries) |
| T-07 memory | Guard RSS ≤ 256 MiB | 41.4 MiB max (T-01 and T-02) |
| T-08 exhaustion | recovery ≤ 5 s; process alive | busy during the connection flood; recovered in 0.06 s; oversized frame rejected; alive |
| T-09 slow dependencies | control timeout +100 ms; transport timeout +500 ms | denied at 205 ms (0.2 s timeout); outcome unknown at 1,015 ms (1 s timeout) |

Informational: a 180,000-record service ledger (capacity 200,000) kept
begin+finish p95 at 0.9 ms; archival removed the 128,132 records older than the
cutoff (the 51,868 records written by the preceding groups were too young).

## Not covered

Multi-day soak; hosts other than this VM size; live provider latency; HA or
multi-host operation (unsupported in v1).
