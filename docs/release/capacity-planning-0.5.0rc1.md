# Capacity planning and measured results

Targets were committed before measurement in
[`capacity-targets.json`](capacity-targets.json) (defined
2026-10-28T00:03:00Z; the reports embed its SHA-256). They are single-host v1
acceptance requirements, not service-level agreements.

## Sizing rules

- **Outcome ledger.** Every tracked request occupies one record until archived,
  and archival only removes records older than `retention.outcome_archive_age_seconds`
  (which must exceed the request window). Size
  `outcomes.capacity ≥ peak_rps × (outcome_archive_age_seconds + archive_interval)`.
  Example: 25 req/s, 1 h request window, archive hourly at 2 h age →
  25 × (7200 + 3600) = 270,000 records. With the defaults (10,000 records, 24 h
  window) sustained throughput is only about 0.1 req/s, so production
  configurations must raise capacity or shorten the window.
- **Vault.** Live tokenized values ≤ `vault.max_entries`; each tokenizing request
  adds up to one entry per distinct sensitive value, kept for
  `token_ttl_seconds`. Sustained rate ≈ `max_entries / token_ttl_seconds` values/s.
- **Audit.** About two to four events per request. Archive when
  `audit.active_events` exceeds `retention.audit_archive_threshold_events`;
  startup verification time grows linearly with active events (≈1 s per 100,000).
- **Connections.** `max_connections` bounds concurrent requests; in production
  each agent UID reserves `per_peer_connections`.

## Results (0.5.0rc1, all nine targets met)

Primary run: inside the candidate container (`enkstein-guard:0.5.0rc1`, no
network, read-only root, UID 10001) on a Colima VM with **2 vCPU and 4 GiB** —
fewer CPUs than the 4-vCPU reference, so conservative. Evidence:
`verification/cli-v1/operational-acceptance-container.json`. A second run on the
4-vCPU Linux sandbox (glibc, Python 3.12.12) evaluated T-02 to T-06, T-08 and
T-09 (seven verdicts); T-01 exceeds that environment's 3-minute command limit
and T-07 was sampled during T-02 only:
`verification/cli-v1/operational-acceptance-linux-sandbox.json`.

Four unrelated containers from another local project auto-started with the VM
and were running during the container run; a sample taken afterwards showed
them idle (at most 0.06 % CPU each, about 660 MiB memory in total). The container report predates image-ID recording in the
runner; its binding to the image is inferred from timestamps
(`verification/cli-v1/container-acceptance-run.json`). Later runs record the ID.

Both runs use the **development profile on one OS user** with a synthetic fixture
connector. The production profile adds peer binding, the socket group,
preflight and the egress proxy; its behaviour is covered by the container
acceptance checks, not by these performance figures.

| Target | Requirement | Container result | Sandbox result |
|---|---|---|---|
| T-01 sustained | 25 req/s ≥ 300 s; p50 ≤ 50, p95 ≤ 150, p99 ≤ 300 ms; 0 errors | 7,500 ok in 300 s; p50 5.2 / p95 7.8 / p99 12.1 ms | not run (command limit) |
| T-02 burst | 32 closed-loop clients 60 s; only ok/busy | 36,575 ok (≈610 req/s), p95 60 ms | 15,901 ok, p95 177 ms |
| T-03 populated vault | ≥ 8,000 live entries, 4 tenants; tokenizing p95 ≤ 250 ms; 0 cross-tenant restores | 8,000 entries; p95 3.5 ms; 0/40 cross-tenant restores | p95 6.1 ms; 0/40 |
| T-04 audit | 100,000 events: append p95 ≤ 25 ms, full verify ≤ 60 s, archive ≤ 120 s | append p95 0.14 ms; verify 1.0 s; archive 1.7 s | 1.0 ms; 0.8 s; 1.4 s |
| T-05 outcome ledger | 9,000/10,000 records: begin+finish p95 ≤ 25 ms; archived IDs accepted 0 | p95 0.61 ms; 0/50 accepted | 1.75 ms; 0/50 |
| T-06 startup | populated state ready ≤ 30 s | 4.0 s (100,501 audit events, 180,100 outcomes, 8,201 vault entries) | 3.2 s |
| T-07 memory | Guard RSS ≤ 256 MiB | 41.1 MiB max (T-01 and T-02) | 38.1 MiB (sampled during T-02; no verdict) |
| T-08 exhaustion | recovery ≤ 5 s; process alive | busy during a 40-connection flood; recovered in 0.07 s; 2 MB frame rejected; alive | 0.07 s |
| T-09 slow dependencies | control timeout +100 ms; transport timeout +500 ms | denied at 201 ms (0.2 s timeout); outcome unknown at 1,017 ms (1 s timeout) | 204 ms; 1,024 ms |

Informational: a 180,000-record ledger (capacity 200,000) kept begin+finish p95
at 2.7 ms (container) / 4.8 ms (sandbox).

## Not covered

Multi-hour or multi-day soak; multi-UID peer-bound fairness under sustained load
(the container peer test exercises fairness during a flood, not throughput);
live provider latency; hosts other than these two environments; disk-full
behaviour of SQLite stores.
