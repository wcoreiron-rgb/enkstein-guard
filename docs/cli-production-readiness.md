# CLI production readiness register

**Newer source is under development as 0.5.0rc3.dev1.** The register below
describes the preserved rc2 wheel/image only; it does not accept the newer
source. See [current development validation](release/development-0.5.0rc3.dev1.md)
and the [original requirements register](original-requirements-roadmap.md).

Authoritative task register for the Enkstein Guard CLI release candidate
**0.5.0rc2**. Supported scope: **one Guard host, Linux/Docker ARM64, profile
`production-linux-peer-bound`, operated only through the `enkstein-guard` CLI**
(`deployment/compose.production.yaml`). Anything outside that scope is listed as
unsupported rather than claimed. The 0.5.0rc1 register is preserved as released
in `docs/release/cli-production-readiness-0.5.0rc1.md`.

Status values: **passed** (acceptance criteria met by executed evidence),
**passed (scoped)** (met within the stated scope; residual risk listed),
**blocked (external)** (needs credentials, access, authorization or a party
outside this workspace), **scope limitation** (explicitly not provided;
documented instead), **confirmed gap** (an attack the candidate does not
prevent; never counted as prevented or accepted).

## Candidate identity

| Item | Identity |
|---|---|
| Wheel | `dist/deployment/enkstein_guard-0.5.0rc2-py3-none-any.whl`, SHA-256 `d63cbe6583aa1510a65cf7d553d67305e2f53b0e8a528faa024ad24e33c4ae2f` (package files digest `7e6beb1001e5a89d894bc3b05aa483723a36a0d7b06322ed66cf7b2a3a953dd5`) |
| Image | `enkstein-guard:0.5.0rc2`, image ID / manifest digest `sha256:a18a86b722683e469a1cedea64a0193cb86d0e8420d615c75870e316f6dfe7ee` |
| Revision | content digests (the workspace is not a version-control checkout): source `b360a3cf6ebf655a532b368736a85136bc43f2f1dca101b8774efeb65b26a0e6`, tests `a6b2b06f8eac27a02bb9e2929527baf5309aa87ead331d9227e784f6fdf8cf77`, tools `00d73974349da8137adb09448fba5d3c6d2e1f855cabf18476c3fa75321ddefc`, deployment `d84e444c0a675bbe260e426ae2bfd97a662701b5424e16f06ef837537fd51143`, acceptance definitions `9a5edb02edf713627da2f3c170962c3fef3f9ed02544c12aab5d405cc9a531b9` |
| Superseded runs | chain 3, build wheel `cbc38df4…` / image `sha256:e6ab75f7…`: failed P-01 (F-10), `verification/0.5.0rc2-superseded/chain3-20261028T195333Z/NOTE.md`; chain 4, this build with the earlier soak harness: no soak report (F-17, F-18), `verification/0.5.0rc2-superseded/chain4-20261028T210318Z/NOTE.md`. Neither counts as evidence here |
| Final run | chain 5, 2026-10-29T00:58:27Z to 04:25:32Z (Mac and container), Linux sandbox reports at 01:00Z, identity/snapshot/mapping checks at 04:27Z |
| Container host | Colima profile `enkstein-rc2` on macOS 27 (Apple silicon): Ubuntu 24.04.4 VM, kernel 6.8.0-117, 4 vCPU, 6 GiB, Docker Engine 29.5.2 with the containerd image store |

Every report in `verification/0.5.0rc2/` carries an identity header
(`tools/evidence.py`, schema `enkstein-guard.evidence/v1`): candidate version,
wheel SHA-256 and a digest of the Guard package files actually imported (or
installed in the image) compared with the wheel; for container runs the image
ID, tags, repository digests and an in-image probe of the installed package,
Python distributions and Alpine packages; SHA-256 and policy version of every
Guard configuration used; the dependency inventory compared with the hash
lock; the five revision digests above; and the runner environment (plus the
Docker engine for container runs). `tools/verify_evidence.py` checks every
report against the candidate and records each report's SHA-256 in
`evidence-check.json`; no exemptions exist.

Docker uses the containerd image store here, so the image ID is the image
manifest digest (repository digest `enkstein-guard@sha256:a18a86b7…`). Trivy
reports the image *config* digest
`sha256:3286e4b1bec4849a8fcf94a4caf39201596c6e615e1d0dc6b2181d41b0c30fe8`; the
eight layer DiffIDs it scanned equal the image's `RootFS.Layers`, and the scanned
archive was saved from the image ID itself (`alpine-os-scan.provenance.json`).

Configuration hashes are recorded for every report that runs a configured
Guard (production profile, disk-full, operational, capacity, soak). Unit and
scenario suites build their configurations inside the test code; those are
identified by the tests revision digest.

## Release decision

**Production acceptance is NOT achieved.** All seven locally executable
acceptance items of this candidate pass (A-1 to A-7 below), and every
requirement that can be executed in this workspace passes its acceptance
criteria within the scope stated for it. What remains is listed in three
separate groups at the end of this register: external blockers (live Hatz and
Cisco acceptance, hosted CI, publisher signing, an independent human security
review), unsupported features, and unresolved security limitations (eight
confirmed gap scenarios and the residual risks). See
[release decision](release/release-decision-0.5.0rc2.md).

## Evidence summary (`verification/0.5.0rc2/`)

| Evidence | Result |
|---|---|
| `linux-core-tests.json` — installed release wheel with exactly the hash-locked dependency set, Linux ARM64 glibc, Python 3.12.12 | 346 passed, 7 skipped, 0 failed, 0 errors (353 executed); the 7 skipped tests are the macOS-only worker sandbox |
| `macos-core-tests.json` — macOS arm64, Python 3.14.5, fresh virtual environment with the release wheel | 350 passed, 3 skipped, 0 failed, 0 errors (353 executed); skipped: two network-namespace egress tests and the tmpfs disk-full test (Linux only) |
| `macos-optional-sdk-tests.json` — Python 3.11 engines environment, release wheel imported from a private target | 4 passed, 0 skipped, 0 failed, 0 errors (4 executed) (AGT, NeMo, LangGraph real; Cisco inspection boundary mocked) |
| `attack-scenarios.json` (equal outcomes in `macos-attack-scenarios.json`) | 30 prevented, 4 benign allowed, 8 confirmed gaps, 0 skipped, 0 failed, 0 errors (42 executed); gate `blocked_known_gaps` |
| `container-production-profile.json` | 38/38 production-profile checks, separate UIDs, egress proxy, synthetic TLS upstream |
| `production-disk-full.json` | 20/20 disk-full checks (full state and archive volumes) |
| `production-capacity.json` | 5/5 production capacity targets met |
| `production-soak.json` | 8/8 soak targets met |
| `operational-acceptance-container.json` | 9/9 development-profile targets met (development profile, one OS user, inside the image) |
| `container-isolation.json`, `peer-isolation.json` | passed (legacy factory profile; forced restart, two-UID flood fairness, stolen credential) |
| `alpine-os-scan.provenance.json` | gate `no_high_critical_findings`, 0 findings of any severity in the current scanner snapshot |
| `upgrade-rollback-drill-rc5.json`, `upgrade-rollback-drill-rc1.json` | passed (0.4.0rc5 → 0.5.0rc2 and 0.5.0rc1 → 0.5.0rc2; older releases refuse the schema-3 outcome ledger after migration, backups restore) |
| `unlabelled-detection-evaluation.json` | 54 synthetic cases; precision/recall and every miss and false positive listed |
| `container-acceptance-run.json`, `container-acceptance-run.log` | every container report names image ID `sha256:a18a86b7…`, shows the wheel's package installed in the image, and passed; the musl lock pins the release wheel |
| `evidence-check.json` | every report bound to this candidate (version, wheel, installed package, revision, dependencies and lock, environment, configuration and its preserved copy, image) |
| `release-snapshot-check.json` | `tools/verify_release_snapshot.py` over the five configured container reports and the scan pair, with the wheel, image ID, musl lock (pip-only absence) and revision digests passed explicitly |
| `configurations/` | the exact synthetic Guard configurations of the five configured reports (no secret values) |
| `rc1-evidence-preserved.sha256` | hashes of the 0.5.0rc1 evidence; unchanged |

`tools/check_readiness_register.py` confirms that the cited paths exist, that
the counts and fractions written here equal the reports, that fractions count
every defined target (a target without a verdict counts as not met), that the
run record and identity check are current, and that the packaged OWASP/ATLAS
mapping matches the Linux reports; it writes register-check.json next to the
reports.

## 0.5.0rc2 acceptance items

### A-1 Capacity and concurrency through the production deployment — passed (scoped)
- Deployment: `deployment/compose.production.yaml` with the acceptance overlay
  (`deployment/acceptance/compose.acceptance.yaml`): network-less Guard (UID
  10001), egress proxy (UID 10002), synthetic TLS upstream reachable only from
  the egress network (`deployment/acceptance/upstream.py`; every request carries
  a unique marker and the upstream counts executions per marker), four
  network-less agent containers with separate UIDs (11001–11004) and
  credentials in two tenants; load generated inside the agent containers
  (`deployment/acceptance/load_agent.py`). No real credentials.
- Targets committed before measurement: `docs/operations/capacity-targets-production.json`
  (defined 2026-10-28T18:05:00Z). Harness: `deployment/test_production_capacity.py`,
  `deployment/production_harness.py`.
- Result (5/5 production capacity targets met):
  - P-01: 12,000 requests from four agents (3,000 each), 0 non-ok; p50 14.2 /
    p95 31.7 / p99 73.8 ms; Guard 42.2 MiB RSS, 12 fds; egress 37.3 MiB; 9,603
    upstream executions with 0 duplicates; 80 resubmitted IDs `completed_no_replay`.
  - P-02: 4,876 ok and 32,749 `busy:rate_limited`; 1,219 ok per agent (limit
    1,340 = 1.1 × share); ok p95 16 ms; tracked requests = ok; 3,853 upstream
    executions = model calls ok.
  - P-03: the light agent 240/240 ok (p95 32 ms) while the flooder was held to
    its connections and rate share.
  - P-04: Guard killed at 40 s and ready again in 3.9 s; 55 responses lost (52
    refused while down, 3 executed or admitted in flight); every one resubmitted:
    52 `ok`, 3 `outcome_unknown_no_replay`; 0 duplicate executions over 16,521.
  - P-05: image URL, web search, hosted tool and `store` requests denied before
    dispatch; 0 upstream requests.
- Found and fixed by this harness before the final run: F-6, F-7, F-8 and F-10
  (see Findings). F-10 made the previous build fail P-01 (1 of 12,000 requests
  withheld); that run is kept in
  `verification/0.5.0rc2-superseded/chain3-20261028T195333Z/NOTE.md`. The next
  build passed all five targets in chain 4, whose soak harness then deadlocked
  (F-17); that run is kept in
  `verification/0.5.0rc2-superseded/chain4-20261028T210318Z/NOTE.md`, and the
  figures above are from the final run.
- Residual risk: one host and one VM size; the synthetic upstream answers
  immediately, so provider latency is excluded; Guard limited to 1 CPU / 512 MiB
  by the compose file.

### A-2 Exact identity in every report; directly bound operational run — passed
- Implementation: `tools/evidence.py` (header), `tools/verify_evidence.py`
  (binding check, per-report digests), `tools/record_container_run.py` (container
  run record), container runners that resolve the tag once and run the image ID
  (`tools/run_container_acceptance.sh`, `tools/run_operational_acceptance_container.sh`).
- The rc1 operational report predated image recording and was bound by
  timestamps. The rc2 operational run executes the resolved image ID, embeds
  the in-image probe of that ID and the Docker engine, and is checked like every
  other container report.
- The lock comparison is strict (F-13): no other version, nothing extra, and
  nothing pinned missing except the build-only `pip` in the runtime image. The
  exact acceptance configurations are kept in `verification/0.5.0rc2/configurations/`
  and checked against the recorded hashes (F-16).
- Evidence: `evidence-check.json`, `container-acceptance-run.json`,
  `release-snapshot-check.json` (`tools/verify_release_snapshot.py`: wheel,
  image ID, locks with pip-only absence, revision digests, raw scan hash and
  recomputed severity counts, all supplied explicitly).
- Limits: macOS reports are supplementary (not a supported platform) and are not
  hash-locked: the fresh macOS environment carries its own `pip`, and the optional
  SDK run imports the candidate from a private target over the unlocked engines
  environment; both differences are recorded in the report headers.

### A-3 Multi-hour soak with bounded storage and scheduled retention — passed (scoped)
- Targets committed before measurement: `docs/operations/soak-targets.json`
  (defined 2026-10-28T18:08:00Z; one revision at 18:08:30Z, before any soak
  measurement, recorded in the file; two later revisions before the final run
  are stricter only: agent participation, and resubmission of recent and of
  archived request IDs). Harness: `deployment/test_production_soak.py`.
- Run: same production topology as A-1, 4 agents × 2 req/s for 3 h, retention
  scheduled inside the service (outcome archival every 300 s at 3,600 s age,
  audit archival every 300 s above 20,000 events keeping 5,000, vault purge
  every 60 s, token TTL 300 s), sampled every 60 s.
- Result (8/8 soak targets met):
  - S-01: 86,400 requests from four agents (21,600 each), 0 non-ok.
  - S-02: p50 17.3 / p95 28.5 / p99 65.4 ms over the run; worst 60-second
    window p99 219 ms, retention windows included.
  - S-03: Guard RSS 40.7 MiB maximum in the first hour, 43.0 MiB in the last
    (+2.3 MiB); egress 36.9 MiB.
  - S-04: Guard fds 9 → 14, threads ≤ 7.
  - S-05: outcome records ≤ 31,180, active audit events ≤ 24,079, vault live
    entries ≤ 537 and expired ≤ 11; state 53.4 MB, end/two-hour ratio 1.002.
  - S-06: outcome archival 36 runs, 25 with records (57,760 archived); audit
    archival 36 runs, 8 with records (153,898 events); vault purge 181 runs;
    0 failures; longest run 0.79 s; an operator retention run mid-soak succeeded.
  - S-07: audit chain with archives verified; 25 outcome archive segments
    (57,760 records) verified; 69,418 upstream executions, 0 duplicates; 200/200
    recent resubmissions `completed_no_replay`; 40/40 resubmissions of IDs
    archived hours earlier refused (`request_id_expired`).
  - S-08: 2,583 archive bytes per tracked request.
- Scope: three hours, not multi-day. Archives are retained history and grow with
  traffic by design (S-08 bounds the growth per request); archive storage is the
  operator's to rotate.

### A-4 Disk-full and failed-write behaviour of vault, audit and outcome stores — passed
- Container (`deployment/test_production_disk_full.py`, `deployment/acceptance/compose.diskfull.yaml`):
  20/20 disk-full checks. The Guard state volume (vault, audit and outcome ledger)
  is a 24 MiB tmpfs filled to 100 % while a request is in flight; the archive
  volume is a separate 8 MiB tmpfs filled during retention.
  - In flight when the disk filled: `execution_or_audit_failed_outcome_unknown`;
    its resubmission answers `outcome_unknown_no_replay`, before and after recovery.
  - New work while full is refused before dispatch
    (`request_tracking_unavailable_or_conflict:tracking_unavailable`); the
    upstream received nothing while the disk was full.
  - Guard reports not ready while full and does not become ready on restart while
    full; `doctor` warns `service_events_lost` and `outcome_states_pending_write`
    (asserted: `doctor_warns_while_full`).
  - After space is freed: ready in 1.4 s, new work succeeds, the in-flight request
    is recorded uncertain, the audit chain verifies, and the upstream saw every
    marker exactly once (no request executed twice).
  - A full archive volume fails retention with `audit_archive_failed` (exit 3)
    without affecting requests and leaves no partial segment; retention succeeds
    after space is freed and the chain verifies with archives.
- Unit (`tests/test_failure_modes.py`): per-store injected failures before and
  after dispatch (ledger, audit, vault, taint); audit or vault unavailable before
  dispatch → `unavailable_no_execution` with the ledger record abandoned;
  denials stay denials when the ledger fails; a completed action whose ledger
  write fails is released once, kept unsettled in memory, retried by the
  settlement job and never replayed (uncertain after a restart); archive
  failures leave no partial files; a real ENOSPC on a 4 MiB tmpfs in a user and
  mount namespace (Linux only) fails closed and recovers.

### A-5 Destination aliases and label-stripping paths — passed (scoped)
- Investigated: every connector path that writes data to a destination and every
  path that reads data back, including provider-side behaviour.
- Fixed (with adversarial regression tests): F-1 (exploitable in 0.5.0rc1),
  F-2, F-3, F-4, F-5, F-11 (stale authorization across a reload), F-12 and
  review finding 2 (see Findings). Tests: `tests/test_host.py` (reload revoking
  a grant or narrowing an agent or route cancels in-flight work; widening does
  not),
  `tests/test_providers.py` (text-only chat allowlist), `tests/test_product_config.py`
  (canonical hosts, `data_domain`, backend grouping), `tests_adversarial/test_product_scenarios.py`
  (provider-side fetch refused, declared alias round trip denied, undeclared DNS
  alias known gap), container check `agent_provider_side_fetch_and_tools_refused`,
  production target P-05.
- Scope decision (explicit, not an acceptance): DNS-level aliases are declared by
  the operator with `connectors[].data_domain`, not discovered. An undeclared
  alias (two host names served by one backend) can still lower a label; this is
  confirmed gap 8, documented in `docs/data-protection.md`. As a hint only,
  validation warns (`connectors_may_alias_one_backend`) when network connectors
  to different host names under one parent domain do not all declare a
  `data_domain`.

### A-6 Outcome-ledger capacity versus rate, retention window and archive interval — passed
- Implementation: `service.max_requests_per_second` (required in production;
  per-agent token buckets), `outcome_sizing()` in `productconfig.py`:
  capacity ≥ 1.1 × rate × (archive age + archive interval + clock skew), and the
  busiest tenant's equal share must hold its agents' share. Production
  validation fails with `outcome_capacity_insufficient_for_request_rate` and a
  detail giving required capacity and sustainable rate; development validation
  warns. `config validate` prints the sizing; `status` reports it with the
  retention counters; `doctor` warns on insufficient sizing, a ledger near
  capacity, an over-full tenant share and failing retention. Scheduled
  retention (`retention.scheduled`, required in production) archives outcomes
  and audit events and purges the vault inside the service.
- Unreconciled uncertain outcomes are kept past the archive horizon until an
  operator resolves them; the formula does not bound them, so `status` reports
  them (`retained_below_cutoff`) and `doctor` warns, also when they reduce the
  capacity below the requirement (F-15).
- Evidence: `tests/test_product_config.py`, `tests/test_cli.py`,
  `tests/test_failure_modes.py` (rate limiting, scheduled retention, retained
  count), P-02 (admitted rate per agent within 1.1 × its share), soak S-05/S-06.

### A-7 Test reporting — passed
- Core and scenario reports count passed, skipped (with reasons), failed and
  errors separately ("346 passed, 7 skipped, …, 353 executed"); a skipped
  scenario is `skipped`, never prevented; the mapping builder refuses skipped
  component tests.
- F-9 (found during the final evidence run): the operational report listed
  verdicts only for targets whose group ran, so a crashed group read as all
  targets met, and its container runner exited 0 after a failed group. Fixed:
  every defined target receives a verdict (not run = not met), the runner
  propagates failure, the run record requires verdicts for every defined target,
  and the register check counts fractions against the target definitions and
  refuses fractions from an aborted harness.
- F-14: capacity and soak phases now fail unless every launched agent exits 0
  and issues at least 95 % of its offered requests, and the restart target
  requires real lost-response coverage (see Findings).

## Requirements

### R-BASE-01 Establish baseline truth — passed
- Evidence: `verification/cli-v1/baseline.json` (0.4.0rc5 baseline). For rc2 the
  0.5.0rc1 evidence is preserved and hash-checked (`rc1-evidence-preserved.sha256`).

### R-CLI-01 Secure initialization and strict configuration validation — passed
- Evidence: `tests/test_product_config.py` (including shipped examples, canonical
  host spelling, sizing), `tests/test_cli.py`, upgrade drills (adopt).
- Residual risk: configuration is trusted; a malicious operator can weaken policy.

### R-CLI-02 Service startup, readiness, status, shutdown — passed
- Evidence: `tests/test_host.py`, `tests/test_cli.py`, container `guard_ready`,
  `restart_duplicate_suppressed`; disk-full restart behaviour (A-4).
- Residual risk: foreground process supervised by Compose/systemd; no HA.

### R-CLI-03 Agent identity, permissions and revocation — passed
- Evidence: `tests/test_identities.py`, `tests/test_host.py`, container
  `agent_revoked_agent_denied`, `agent_stolen_credential_denied`.
- Residual risk: credential files must be delivered securely by the operator.

### R-CLI-04 Policy and task-boundary configuration — passed
- Evidence: `tests/test_host.py`, container `agent_task_boundary_*`.
- Residual risk: boundaries validate request facts, not business truth.

### R-CLI-05 Connectors without credentials in arguments or logs — passed (scoped)
- Evidence: `tests/test_identities.py`, `tests/test_cli.py`, `tests/test_egress.py`,
  container `upstream_got_brokered_key`, `logs_secret_free`, `audit_export_secret_free`.
- New in rc2: production refuses one provider secret value for two tenants
  (`secret-set` and service start); `doctor` reports existing ones (F-4).
- Scope: `chat_completions` (incl. the Hatz header shape), `virustotal_ip`,
  `retrieval_local`, synthetic `fixture`. External inspection engines are SDK-only.

### R-CLI-06 Authenticated exact-action approvals — passed (scoped)
- Evidence: `tests/test_approvals.py`, `tests/test_host.py`, container approval checks.
- Residual risk: tickets live in memory (a restart discards them — fail closed).

### R-CLI-07 Audit verification and safe export — passed
- Evidence: `tests/test_retention.py`, `tests/test_durable_audit.py`, `tests/test_cli.py`,
  container `audit_chain_verified`, `audit_export_secret_free`, disk-full and soak
  chain verification with archives.
- Residual risk: rollback detection needs an external checkpoint.

### R-CLI-08 Diagnostics for denied, refused, failed and uncertain actions — passed
- rc2 distinguishes refused before dispatch (`unavailable_no_execution` with fixed
  reasons such as `connector_busy`, `egress_denied_503`, `egress_unavailable`,
  `provider_tls_failed`, `audit_unavailable`, `vault_unavailable`; CLI exit 4)
  from denied and from outcome unknown (fixed failure codes recorded in audit).
- Evidence: `tests/test_failure_modes.py`, `tests/test_host.py`, `tests/test_egress.py`,
  `tests/test_cli.py`, `docs/operations/runbook.md`.

### R-CLI-09 JSON output, exit codes, noninteractive, safe errors — passed
- Evidence: `tests/test_cli.py`.

### R-CLI-10 doctor control states — passed
- Evidence: `tests/test_cli.py`, container `doctor_only_reports_synthetic_connector`.

### R-DP-01 Sensitivity classification and propagation — passed (scoped)
- Evidence: `tests/test_sensitivity.py`, `tests/test_host.py`, `tests/test_product_config.py`,
  adversarial scenarios, container `agent_tainted_summary_to_model_denied`,
  `agent_declared_context_response_withheld`, `upstream_never_saw_raw_email`.
- rc2: backends are connected components of (tenant, canonical destination) and
  declared `data_domain`, so a write through one name cannot be read back below
  its clearance through a declared alias or a spelling variant.
- Residual risk: taint is per agent identity and resettable by operators; labels
  are not tracked for copies outside Guard's routes or under an undeclared alias
  (gap 8); non-card sensitive numbers need field rules.

### R-DP-02 Declared confidential data cannot reach unauthorized destinations — passed (scoped)
- rc2 closes the provider-side path (F-1): chat requests are limited to text
  messages and function tools, so a provider cannot be asked to fetch URLs,
  run hosted tools or store the conversation.
- Residual risk: undeclared confidential knowledge already inside an agent is not
  recognized (gaps 4 and 5).

### R-DP-03 Unlabelled-data detection evaluated — passed
- Evidence: `unlabelled-detection-evaluation.json`, `docs/data-protection.md`.
- Result: declared context (enforced by default) precision 0.917 / recall 0.367
  (1 false positive); heuristics (monitor-only by default) 0.75 / 0.50 (5 false
  positives); both enforced 0.80 / 0.80. Synthetic corpus only; heuristic
  detection does not recognize every confidential value.

### R-DP-04 Retrieval authorization before model context — passed (scoped)
- Evidence: `tests/test_retrieval.py`, adversarial retrieval scenarios, container `agent_retrieval_*`.
- Residual risk: generic tool connectors used for retrieval bypass this (gap 6).

### R-DP-05 Retrieval adversarial tests — passed
- Evidence: `tests/test_retrieval.py`, container checks.

### R-DEP-01 Mandatory peer-bound production profile — passed
- Evidence: `tests/test_product_config.py`, `tests/test_host.py`, container profile, `peer-isolation.json`.

### R-DEP-02 Independent egress restriction with bypass tests — passed (scoped)
- Evidence: `tests/test_egress.py`, container `guard_*_blocked`, `egress_rejects_non_guard_uid`.
- rc2: tunnels end 0.25 s after Guard closes its side (F-6); connection setup
  failures are refused before dispatch (F-7).
- Residual risk: destination allowlist only, no content inspection.

### R-DEP-03 Single-host scope explicit — passed
- Evidence: state lock, `doctor` (`high_availability: unsupported`), documentation.

### R-OPS-01 Concurrent tenants and populated vaults — passed
- Evidence: T-03, P-01 (two tenants, four agents, production profile).

### R-OPS-02 Sustained operation and resource exhaustion — passed (scoped)
- Evidence: P-01 to P-04 (production profile), soak S-01 to S-08, T-01/T-02/T-07/T-08
  (development profile), A-4.
- Residual risk: one host size; three-hour soak, not multi-day.

### R-OPS-03 Slow or unavailable inspectors and providers — passed
- Evidence: T-09, `tests/test_host.py`, `tests/test_runtime.py`, `tests/test_egress.py`.

### R-OPS-04 Cancellation and uncertain outcomes — passed
- Evidence: `tests/test_host.py`, `tests/test_failure_modes.py`, disk-full checks.

### R-OPS-05 Restart and duplicate suppression — passed
- Evidence: `tests/test_cli.py`, container restart check, P-04, disk-full
  `no_request_executed_twice`, soak S-07.

### R-OPS-06 Backup, restore, upgrade, rollback — passed
- Evidence: `tests/test_maintenance.py`, `tests/test_retention.py` (ledger schema
  migration), `upgrade-rollback-drill-rc5.json`, `upgrade-rollback-drill-rc1.json`.
- Note: rollback to 0.5.0rc1 or earlier after migration needs the pre-upgrade
  backup (the old releases refuse the schema-3 outcome ledger).

### R-OPS-07 Safe retention — passed
- rc2: retention runs on a schedule inside the service (A-6); archival is
  chunked with pauses so request-path writes are not starved; archives are
  verified against the policy counters (`outcomes verify-archives`).
- Evidence: `tests/test_retention.py`, `tests/test_failure_modes.py`, T-04, T-05, soak S-06/S-07.

### R-OPS-08 Capacity targets defined before measurement — passed
- Evidence: `docs/operations/capacity-targets.json`,
  `docs/operations/capacity-targets-production.json`, `docs/operations/soak-targets.json`
  (definition digests embedded in every report), `docs/operations/capacity-planning.md`.

### R-OPS-09 Key maintenance — passed (scoped)
- `keys rotate --store vault`; other store keys are not rotatable; key loss is unrecoverable.

### R-INT-01 Live Cisco AI Defense acceptance — blocked (external)
- Prepared: `docs/integrations/live-acceptance.md`, `tools/live_integration_check.py`
  (refuses without `--i-have-authorization`). Mocked SDK tests are not live acceptance.

### R-INT-02 Live Hatz acceptance — blocked (external)
- Prepared as above. Needed: nonproduction endpoint, model and key, plus authorization.

### R-INT-03 DefenseClaw evaluation — passed (carried from 0.5.0rc1)
- Evidence: `docs/security/defenseclaw-evaluation.md`,
  `verification/cli-v1/component-scanner-evaluation.json`. Not re-executed for
  rc2; the Guard code it exercised is byte-identical (`admission.py`
  `cfa94752635a5882616857882385a8ad027015944c63e67263efe32e50b4d9f7`,
  `orchestration.py` `1fffe87642fd6a3db5386ecaf10e00deefee30a1de44e1f283966d2619c15a43`).

### R-REL-01 Hosted CI — blocked (external)
- Prepared: `.github/workflows/verify.yml`, `.github/workflows/security-validation.yml`
  (versioned evidence directory, AppArmor user-namespace step). No run exists; untested.

### R-REL-02 Reproducible dependency locks — passed
- Evidence: Linux core tests and the image ran on exactly the locked sets
  (`evidence-check.json`); provenance records the rebuilt wheel's members.

### R-REL-03 Publisher signing and provenance — blocked (external) for signing
- Done: `tools/build_provenance.py` (unsigned provenance in `dist/release-0.5.0rc2/`),
  `docs/release/publisher-signing-requirements.md`.

### R-REL-04 External review package — blocked (external) for the review itself
- Done: `docs/external-review/README.md` (rc2). No independent human review has
  occurred; AI-assisted reviews are not substitutes.

### R-REL-05 Versioned OWASP/ATLAS mappings — passed
- Evidence: `coverage.json`, `atlas-evidence.json` (mapping 2.1), regenerated from
  the final Linux reports as the last step before provenance (byte-identical to
  the packaged files, so the wheel is unchanged); `--check` passes.
- Result: 20 OWASP rows, 9 with confirmed gaps; 17 ATLAS techniques — 9 with
  scenario and component evidence, 2 scenario only, 3 component only, 1 confirmed
  gap, 2 scope limitations. No category or technique is declared fully accepted.

### R-SCOPE-01 Training/model poisoning — scope limitation (gap 2)
### R-SCOPE-02 Factual grounding — passed (scoped; gap 3)
### R-SCOPE-03 Malicious-component handling — passed (scoped; not malware detection; gap 1)
- Integrity pins detect changed components; they do not detect malware.
### R-SCOPE-04 Unsupported surfaces — passed
- Streaming is rejected; multimodal parts, hosted tools, web search and provider
  storage are rejected on chat routes (rc2) as well as on tokenize routes;
  `doctor` reports `windows`, `cloud_isolation`, `high_availability`,
  `network_agent_messaging` and non-ARM64 architectures `unsupported`.

## Confirmed gaps

Expected failures: attacks the candidate does not prevent. They are not
prevented attacks and are not accepted by this register.

1. Correctly pinned component misusing declared capabilities (LLM04/ASI04).
2. Training-data/model poisoning (LLM05; scope limitation).
3. Unsupported claim with a real citation (LLM07).
4. Undeclared, unlabelled hidden context (LLM08).
5. Paraphrased declared context (LLM08).
6. Generic tool connector used for retrieval (LLM09).
7. Same-UID starvation in legacy shared-UID mode (LLM06/ASI08); the production profile requires peer bindings.
8. Undeclared DNS-level alias of a destination lowers a label (LLM02; scope decision A-5).

## Findings (0.5.0rc2)

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| F-1 | High (exploitable in 0.5.0rc1) | `chat_completions` passed request bodies through except `model`/`stream`: image/file/audio parts, hosted tools, web search and provider storage reached the provider, which could fetch attacker URLs outside the egress allowlist and clearance checks. The rc1 statement "multimodal parts are rejected" held only for tokenize routes. | Text-only allowlist `providers.chat_request_allowed` (control C-PROVIDER); tests, scenario, container check, P-05 |
| F-2 | Medium | Endpoint and allowlist host spellings were not canonical, so one destination could appear as two | Canonical host names required in configuration |
| F-3 | Medium | Aliases of one backend were separate destinations for the round-trip rule | `connectors[].data_domain` (C-DOMAIN); undeclared aliases = gap 8 |
| F-4 | Medium | One provider secret value could serve two tenants (shared provider-side state) | Refused in production at `secret-set` and service start; `doctor` reports |
| F-5 | Low | Fixture destinations differing only by case were separate backends | Canonicalized |
| F-6 | High (availability; latent in rc1) | The egress proxy kept a tunnel until both sides closed; a lingering destination held proxy slots, and at 20 req/s 54 % of requests became outcome unknown | Tunnel ends 0.25 s after Guard closes its side |
| F-7 | Medium | Connector slot exhaustion and tunnel/TLS setup failures were reported as outcome unknown although nothing was sent | `unavailable_no_execution` with fixed reasons; `max_concurrent_calls` per connector |
| F-8 | Medium | A refused connection closed with unread input reset the client, hiding the answer | Bounded input discard before close; client reads the answer after a failed write |
| F-9 | Medium (reporting) | Operational verdicts omitted targets that did not run; the runner exited 0 after a failed group | Fixed (A-7) |
| F-10 | Medium (availability; latent in 0.5.0rc1) | The retrieval identifier was a bare random 16-digit hex value; about 4 in 100,000 are all digits and Luhn-valid, the payment-card detector raised the response to confidential and Guard withheld it from internal-cleared agents (failed P-01 of the previous build). Fail-closed, so no disclosure, but nondeterministic loss of valid responses | Identifier `rt_` + hex (one word, no detector can match); regression tests in `tests/test_retrieval.py` and `tests/test_host.py` fail on the previous build |
| F-11 | Medium (authorization; latent in 0.5.0rc1) | A reload cancelled in-flight work only when an agent's credential changed. Work admitted before a reload that removed the agent's route grant, changed its tenant, principal, task, clearance or groups, or changed the route or its connector still dispatched and released its response; release also ignored a raised `produces` of the current route (lower taint than the new policy required) | Reload cancels in-flight work whose authorization it revokes or changes (`host.authorization_changed`); release requires the current grant and identity and applies the stricter `produces`, clearance and grounding of both policies; `tests/test_host.py` reload tests fail on the previous build |
| F-12 | Low | `data_domain` was compared case-sensitively, so "Notes" and "notes" declared one backend as two | Compared case-insensitively; `tests/test_product_config.py` |
| F-13 | Medium (evidence) | The identity header's lock comparison ignored pinned packages missing from the environment, so an image without a locked runtime dependency would still read as a lock match | Strict match: only the build-only `pip` may be absent, and only in the runtime image |
| F-14 | Medium (reporting) | Capacity and soak verdicts did not require every launched agent to run (a failed agent dropped out of the totals), and the restart target P-04 could pass without any response lost after Guard admitted the request | Every phase requires all agents to exit 0 with ≥ 95 % of offered requests; P-04 makes some upstream calls slow so executed requests are in flight at the kill, and requires every lost response resubmitted and at least one admitted-then-lost request (targets revised, stricter only) |
| F-15 | Low (diagnostics) | Unreconciled uncertain outcomes are kept past the archive horizon and consume capacity, but sizing diagnostics did not show them | `retained_below_cutoff` in status; `doctor` warnings `outcome_records_unreconciled` and `outcome_capacity_reduced_by_unreconciled_records` |
| F-16 | Low (evidence) | The disk-full harness recorded `doctor` warnings without asserting them; acceptance configurations were hashed but not kept | Check `doctor_warns_while_full`; exact configurations preserved in `verification/0.5.0rc2/configurations/` and checked against the recorded hashes by `tools/verify_evidence.py` |
| F-17 | Medium (evidence harness) | The soak harness waited for the agents' `docker compose run` processes to exit without reading their output; at the end of a three-hour run the summaries filled the pipe and the run never finished (chain 4, kept as history with its samples) | Agent output is read while the agents run (`AgentRun` in `deployment/production_harness.py`), also in the capacity harness |
| F-18 | Medium (evidence harness) | The soak's dedup probes resubmitted the first completed request IDs, which a three-hour run has archived and Guard correctly refuses as expired, so S-07 could not pass | Probes resubmit recent IDs; S-07 additionally requires the earliest, archived IDs to be refused as expired (soak targets revised, stricter only) |

F-11 to F-16 were raised by an AI-assisted review loop that runs beside this
work (`docs/loop-review-status.md`; not independent, not a human assessment);
each was reproduced or inspected here before it was fixed, and F-11's
regression tests fail on the previous build. The same loop contributed
`tools/verify_release_snapshot.py` (with `tests/test_release_snapshot.py`), a
verifier that checks the candidate's container reports and scan only against
inputs passed explicitly (wheel, image ID, locks, revision digests); its
verdict is `release-snapshot-check.json`.

A separate AI-assisted review of the rc2 changes (not independent) reported
eight further findings, all fixed before the final evidence run and recorded in
`docs/release/0.5.0rc2-worklog.md`: retention contention with request-path
writes; a `data_domain` that split a backend; the register check treating known
gaps as accepted; evidence-check exemptions and missing per-report digests;
missing directory fsync; in-flight records eligible for archival and unverified
segment counts; shared secrets refused only at `secret-set`; unbounded draining
of refused connections.

## Scope decisions (explicit)

1. DNS-level aliases are declared, not discovered (A-5, gap 8). Shared IP
   addresses are not treated as aliases.
2. Development-profile operational targets (T-01 to T-09) remain one-user
   measurements of the request path; production-profile capacity is measured
   separately (P-01 to P-05). Neither substitutes for the other.
3. The soak is three hours (multi-hour, as required), not multi-day.
4. macOS evidence is supplementary and not hash-locked (A-2).
5. The component scanner evaluation is carried from 0.5.0rc1 (R-INT-03).

## Remaining work

### External blockers

| Requirement | Needed |
|---|---|
| R-INT-02 live Hatz acceptance | nonproduction endpoint, model and key; authorization for synthetic traffic |
| R-INT-01 live Cisco AI Defense acceptance | nonproduction API key; authorization |
| R-REL-01 hosted CI | repository with GitHub Actions (ARM64 runner) |
| R-REL-03 publisher signing | attested builder, publisher identity, key custody or Sigstore identity |
| R-REL-04 independent security review | an independent human reviewer (package prepared) |

### Unsupported features (v1 scope)

High availability and multi-host operation; streaming responses; multimodal
inputs; Windows, cloud isolation and network agent messaging; architectures
other than ARM64; rotation of store keys other than the vault's; durable
approval tickets across restarts; multi-day soak evidence.

### Unresolved security limitations

The eight confirmed gaps above, and these residual risks: labels are not tracked
for data copied outside Guard's routes; taint is per agent identity and
resettable by operators; sensitive numbers other than card numbers sent as JSON
numbers need field rules; heuristic detection is monitor-only by default and
misses paraphrase and undeclared facts; integrity pins are not malware
detection; audit rollback detection needs an external checkpoint; key loss is
unrecoverable; egress is a destination allowlist without content inspection;
a reload that adds checks (new declared context, field rules or inspection
controls) applies them to work admitted afterwards, while in-flight work that
already passed the old checks completes, with its response classified under
both policies; undeclared aliases are only hinted at
(`connectors_may_alias_one_backend`, a parent-domain heuristic).
No finding from this candidate's own analysis is open, but no independent
assessment has been made.

## Document status

| Document | Status |
|---|---|
| `docs/release/cli-production-readiness-0.5.0rc1.md`, `docs/release/capacity-planning-0.5.0rc1.md` | rc1 versions as released (historical; F-1 corrects the rc1 multimodal statement) |
| `docs/current-status.md`, `docs/completion-acceptance.md`, `docs/operations/capacity-planning.md` | Updated for rc2 |
| `docs/configuration-reference.md`, `docs/cli-operator-guide.md`, `docs/operations/runbook.md`, `docs/production-deployment.md`, `docs/data-protection.md` | Updated for rc2 (rate limit, sizing, scheduled retention, refused-before-dispatch, disk full, aliases) |
| `docs/security/validation-rc4.md`, `docs/security/validation-rc5.md`, `docs/security/coverage-acceptance.md` | Historical |

## Operating notes

- Mac-side commands were prefixed with `rtk proxy` per `the local development command-wrapper policy`; the
  Linux sandbox has no `rtk`, so commands there ran directly.
- Container runs used a separate Colima profile `enkstein-rc2` so that the
  default profile, whose start also starts an unrelated project's containers,
  stayed stopped. The profile is stopped after the runs and the Docker context
  restored to `default`.
- No real credentials, external messages, publishing or paid services were used.

## Next actions (external)

1. Provide nonproduction Hatz and Cisco credentials and authorization; run
   `tools/live_integration_check.py` and the end-to-end procedure.
2. Push to a hosted repository and run both workflows.
3. Establish publisher identity and sign `dist/release-0.5.0rc2/`.
4. Commission an independent security review using `docs/external-review/`.
