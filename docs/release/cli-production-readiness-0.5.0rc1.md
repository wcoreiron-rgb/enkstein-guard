# CLI production readiness register

Authoritative task register for the Enkstein Guard CLI release candidate
**0.5.0rc1**. Supported scope: **one Guard host, Linux/Docker ARM64, profile
`production-linux-peer-bound`, operated only through the `enkstein-guard` CLI**
(`deployment/compose.production.yaml`). Anything outside that scope is listed as
unsupported rather than claimed.

Status values: **passed** (acceptance criteria met by executed evidence),
**passed (scoped)** (met within the stated scope; residual risk listed),
**blocked (external)** (needs credentials, access, authorization or a party
outside this workspace), **scope limitation** (explicitly not provided;
documented instead).

Evidence paths are relative to the project root. Unless stated otherwise,
evidence was produced with the release wheel
`dist/deployment/enkstein_guard-0.5.0rc1-py3-none-any.whl`
(SHA-256 `0998c1d81fa7931bc7b5d5d1ea36a3ed0debbd94ce9dc526ccf42822c0dfcc61`)
and image `enkstein-guard:0.5.0rc1`
(`sha256:933edccc1269678a771913f2a9a474116e296195f8871e5664b79646079a337c`;
its exported config digest `sha256:8ed1885091641b770cba67fc5c8bbf296f754e927999b3101ee39e9982f351a2`
is the ImageID Trivy reports, because Docker uses the containerd snapshotter).
0.4.0rc5 evidence is historical and is not counted for changed behaviour.

**Evidence profiles.** The container acceptance checks run the production
profile with separate UIDs. The operational (capacity/latency) runs, the
in-process host tests and the product attack scenarios run the development
profile on one OS user; they exercise the same request path without peer
binding, the socket group, preflight or the egress proxy.

## Release decision

**Production acceptance is NOT achieved.** Every requirement that can be
executed in this workspace passes its acceptance criteria within the scope and
evidence profiles above. The remaining requirements depend on external input:
live Hatz and Cisco acceptance (credentials and authorization), hosted CI
(repository access), publisher signing (publisher identity and key custody) and
an independent human security review. Seven confirmed gap scenarios remain
documented limitations. See [release decision](release/release-decision-0.5.0rc1.md).

## Evidence summary

| Evidence (`verification/cli-v1/`) | Result |
|---|---|
| `linux-core-tests.json` — installed wheel with the exact locked dependency set, Linux ARM64 glibc, Python 3.12.12 | 305 run, 0 failures, 7 skips (macOS-only worker sandbox) |
| `macos-core-tests.json` — macOS arm64, Python 3.14.5; release wheel unpacked into a private target that shadows the unmodified 0.4.0rc5 copy in `.venv` (so the report's dependency list names both) | 305 run, 0 failures, 2 skips (Linux-only network namespace / `SO_PEERCRED`) |
| `macos-optional-sdk-tests.log` — Python 3.11 | 4 passed (AGT, NeMo, LangGraph real; Cisco inspection boundary mocked) |
| `attack-scenarios.json` (and `macos-attack-scenarios.json`) | 38 scenarios: 27 prevented, 4 benign allowed, **7 confirmed gaps** (expected failures, never counted as prevented); gate `blocked_known_gaps` |
| `container-production-profile.json` | 37/37 checks, production profile, separate UIDs |
| `container-isolation.json`, `peer-isolation.json` | passed (legacy factory profile; two-UID flood fairness and stolen credential) |
| `alpine-os-scan.provenance.json` | 0 findings in the current scanner snapshot (musl fix pinned) |
| `operational-acceptance-container.json` | 9/9 predefined targets met (2 vCPU, development profile) |
| `operational-acceptance-linux-sandbox.json` | 7/7 evaluated targets met (T-01 not runnable there; T-07 sampled only) |
| `upgrade-rollback-drill.json` | passed (0.4.0rc5 → 0.5.0rc1) |
| `unlabelled-detection-evaluation.json` | 54 synthetic cases; misses and false positives listed |
| `component-scanner-evaluation.json` | executed; decision recorded |
| `container-acceptance-run.json` (`tools/record_container_run.py`), `container-acceptance-run.log` | every container report that records an image names this image ID and passed; the build lock pins the release wheel. The operational report predates image recording, so its binding is inferred from timestamps and listed as unbound |
| `register-check.json` (`tools/check_readiness_register.py`) | cited paths exist; the counts written here equal the evidence; the run record is current; the packaged mapping matches the Linux reports |

Core-test reports list, per ATLAS technique, the referenced component tests;
a technique without component tests reports `null`, not a pass.

## Requirements

### R-BASE-01 Establish baseline truth — passed
- Acceptance: installed package, source version, tests and evidence hashes verified before changes; expected failures counted as gaps.
- Evidence: `verification/cli-v1/baseline.json`, `baseline-rc5-linux-core-tests.log`, `baseline-rc5-attack-scenarios.json`.
- Result: `.venv` held 0.4.0rc5 identical to source; the rc5 manifest's development-key signature (tamper evidence, not publisher identity) and its 12 hashes verified; 194 tests ran (187 passed, 7 skipped); 23 scenarios = 14 prevented, 3 benign, 6 gaps.
- Historical statements re-checked (see "Document status").

### R-CLI-01 Secure initialization and strict configuration validation — passed
- Implementation: `productconfig.py` (schema 2), `init [--adopt-existing]`, `config validate|show`.
- Acceptance: private exclusive creation, never regenerates keys; unknown/duplicate/mistyped/out-of-range fields rejected with stable `{path, code}`; no secrets accepted in configuration or arguments.
- Evidence: `tests/test_product_config.py` (including shipped examples), `tests/test_cli.py`, upgrade drill (adopt).
- Residual risk: configuration is trusted; a malicious operator can weaken policy.

### R-CLI-02 Service startup, readiness, status, shutdown — passed
- Implementation: `service start|ready|wait-ready|status|stop|reload`, state lock, production preflight, stale-socket recovery, drain-then-cancel.
- Evidence: `tests/test_host.py` (preflight, restart, egress outage), `tests/test_cli.py` (kill -9 restart, second instance refused), container `guard_ready`, `restart_duplicate_suppressed`.
- Residual risk: foreground process supervised by Compose/systemd; no HA.

### R-CLI-03 Agent identity, permissions and revocation — passed
- Implementation: `agent issue|revoke|list|reset-taint`, `approver issue|revoke|list`; digests only; reload cancels in-flight work of changed credentials.
- Evidence: `tests/test_identities.py`, `tests/test_host.py`, container `agent_revoked_agent_denied`, `agent_stolen_credential_denied`.
- Residual risk: credential files must be delivered securely by the operator.

### R-CLI-04 Policy and task-boundary configuration — passed
- Evidence: `tests/test_host.py` (task boundary, reload), container `agent_task_boundary_*`; `policy explain`.
- Residual risk: boundaries validate request facts, not business truth.

### R-CLI-05 Connectors without credentials in arguments or logs — passed (scoped)
- Evidence: `tests/test_identities.py`, `tests/test_cli.py`, `tests/test_egress.py` (key only in the upstream header), container `upstream_got_brokered_key`, `logs_secret_free`, `audit_export_secret_free`.
- Scope: `chat_completions` (incl. the Hatz header shape), `virustotal_ip`, `retrieval_local`, synthetic `fixture`. External inspection engines are SDK-only.

### R-CLI-06 Authenticated exact-action approvals — passed (scoped)
- Evidence: `tests/test_approvals.py`, `tests/test_host.py`, adversarial service approval scenario, container approval checks.
- Residual risk: tickets live in memory (a restart discards them — fail closed); review masks only detected values; approvals apply only to routes configured with them.

### R-CLI-07 Audit verification and safe export — passed
- Evidence: `tests/test_retention.py`, `tests/test_durable_audit.py`, `tests/test_cli.py`, container `audit_chain_verified`, `audit_export_secret_free`.
- Residual risk: incremental pre-write verification detects interior deletion within 64 appends or at the next full verification; rollback detection needs an external checkpoint.

### R-CLI-08 Diagnostics for denied, failed and uncertain actions — passed
- Evidence: `tests/test_host.py`, `tests/test_cli.py` (`diagnose`), container `model_diagnosis`.
- Residual risk: egress/connect failures are conservatively reported as outcome unknown.

### R-CLI-09 JSON output, exit codes, noninteractive, safe errors — passed
- Evidence: `tests/test_cli.py` (one JSON object per command and for `--version`; exit codes 0/2/3/4/5/64; no prompts; no echo). `--help` prints human-readable usage.

### R-CLI-10 doctor control states — passed
- Evidence: `tests/test_cli.py`, container `doctor_only_reports_synthetic_connector`.
- Result: enforcement is `active` only for a running production-profile service with peer binding, a loopback-only Guard and no synthetic connectors; installation alone is never reported as enforcement.

### R-DP-01 Sensitivity classification and propagation — passed (scoped)
- Implementation: `sensitivity.py` (levels, detectors including card numbers sent as JSON numbers, field rules, declared context, durable taint, clearance control); service release checks; PrivateAI controls; orchestrator classifier labels; production round-trip rule (`produces_below_destination_clearance`).
- Evidence: `tests/test_sensitivity.py`, `tests/test_host.py`, `tests/test_product_config.py`, adversarial numeric-card and delegated-child scenarios, container `agent_tainted_summary_to_model_denied`, `agent_declared_context_response_withheld`, `upstream_never_saw_raw_email`.
- Residual risk: taint is per agent identity and resettable by operators; labels are not tracked for copies outside Guard's routes or under a second destination name; non-card sensitive numbers need field rules.

### R-DP-02 Declared confidential data cannot reach unauthorized destinations — passed (scoped)
- Scope: data that passed through Guard or was declared to Guard. Summaries are covered by taint, delegated children by workflow labels, round trips through the same tenant destination by the production `produces` rule.
- Residual risk: undeclared confidential knowledge already inside an agent is not recognized (confirmed gap).

### R-DP-03 Unlabelled-data detection evaluated — passed
- Evidence: `verification/cli-v1/unlabelled-detection-evaluation.json`, `docs/data-protection.md`.
- Result: declared context (enforced by default) P 0.92 / R 0.37 (1 FP); heuristics (monitor-only by default) P 0.75 / R 0.50 (5 FP); both enforced P 0.80 / R 0.80. Every miss and false positive is listed. Default enforcing recall on this corpus is therefore 0.37.

### R-DP-04 Retrieval authorization before model context — passed (scoped)
- Evidence: `tests/test_retrieval.py`, adversarial retrieval scenarios, container `agent_retrieval_*`.
- Residual risk: generic tool connectors used for retrieval bypass this (confirmed gap); external backends may learn approximate counts.

### R-DP-05 Retrieval adversarial tests — passed
- Cross-tenant, forged metadata, mixed permissions, unauthorized IDs and denied-content leakage into responses, errors and audit are each tested (`tests/test_retrieval.py`, container checks).

### R-DEP-01 Mandatory peer-bound production profile — passed
- Evidence: `tests/test_product_config.py` (missing, shared, Guard-UID and duplicate identities rejected), `tests/test_host.py` (preflight), container profile, `peer-isolation.json`.

### R-DEP-02 Independent egress restriction with bypass tests — passed (scoped)
- Evidence: `tests/test_egress.py` (network namespace: no direct route, no DNS; allowlist, ports, IP literals, metadata/rebinding, mixed resolution, protocol abuse, peer UID), container `guard_*_blocked` and `egress_rejects_non_guard_uid` (a socket-group member with a non-Guard UID receives the proxy's own 403).
- Residual risk: destination allowlist only, no content inspection; a compromised host is out of scope.

### R-DEP-03 Single-host scope explicit — passed
- Evidence: state lock (second instance refused), `doctor` (`high_availability: unsupported`), documentation.

### R-OPS-01 Concurrent tenants and populated vaults — passed
- Evidence: T-03 (8,000 live entries across 4 tenants, p95 3.5 ms, 0/40 cross-tenant restores).

### R-OPS-02 Sustained operation and resource exhaustion — passed (scoped)
- Evidence: T-01 (300 s at 25 req/s, p99 12.1 ms, 0 errors), T-02, T-07 (41 MiB), T-08; vault/outcome/approval capacity limits in unit tests.
- Residual risk: development-profile measurements; no multi-hour soak; host-level exhaustion needs operator limits.

### R-OPS-03 Slow or unavailable inspectors and providers — passed
- Evidence: T-09, `tests/test_host.py::EgressOutageTests`, `tests/test_runtime.py` control timeouts.

### R-OPS-04 Cancellation and uncertain outcomes — passed
- Evidence: `tests/test_host.py` (revocation and shutdown cancel → `outcome_unknown_no_replay`), `outcomes resolve`.

### R-OPS-05 Restart and duplicate suppression — passed
- Evidence: `tests/test_cli.py` (kill -9), container restart check, `container-isolation.json` (forced restart).

### R-OPS-06 Backup, restore, upgrade, rollback — passed
- Evidence: `tests/test_maintenance.py`, `tests/test_cli.py`, `verification/cli-v1/upgrade-rollback-drill.json`.

### R-OPS-07 Safe retention — passed
- Evidence: `tests/test_retention.py`, T-04, T-05.
- Residual risk: retention runs on operator command, not on a schedule.

### R-OPS-08 Capacity targets defined before measurement — passed
- Evidence: `docs/operations/capacity-targets.json` (defined 2026-10-28T00:03:00Z; hash embedded in the reports), `docs/operations/capacity-planning.md`.

### R-OPS-09 Key maintenance — passed (scoped)
- `keys rotate --store vault` (offline; references keep working, `tests/test_cli.py`). Other store keys are not rotatable in this release; key loss is unrecoverable.

### R-INT-01 Live Cisco AI Defense acceptance — blocked (external)
- Prepared: `docs/integrations/live-acceptance.md`, `tools/live_integration_check.py` (refuses without `--i-have-authorization`).
- Needed: nonproduction API key through approved secret handling and authorization for synthetic traffic. Mocked SDK tests are not live acceptance.

### R-INT-02 Live Hatz acceptance — blocked (external)
- Prepared as above. Needed: nonproduction endpoint, model and key, plus authorization.

### R-INT-03 DefenseClaw evaluation — passed
- Evidence: `docs/security/defenseclaw-evaluation.md`, `verification/cli-v1/component-scanner-evaluation.json`. Decision: platform not adopted (second executor); Skill Scanner recommended as optional offline pre-admission step; the gap stays open.

### R-REL-01 Hosted CI — blocked (external)
- Prepared: `.github/workflows/verify.yml`, `.github/workflows/security-validation.yml` (pinned action SHAs, installed-wheel tests, mapping check, container acceptance on `ubuntu-24.04-arm`). Ubuntu 24.04 restricts unprivileged user namespaces, which the egress namespace test needs, so the workflows lift that restriction on the ephemeral runner; if the test is still skipped, the mapping check fails closed. Needed: a hosted repository with Actions. No run exists; the workflows are untested.

### R-REL-02 Reproducible dependency locks — passed
- Evidence: musl and glibc locks regenerated with dependency hashes identical to 0.4.0rc5's; Linux core tests ran on exactly the locked set; `dist/release-0.5.0rc1/reproducibility.json` (rebuilt wheel members identical; archive bytes differ by zip timestamps).

### R-REL-03 Publisher signing and provenance — blocked (external) for signing
- Done: `tools/build_provenance.py`, `dist/release-0.5.0rc1/provenance.intoto.json` (unsigned), `docs/release/publisher-signing-requirements.md`. Needed: attested builder, publisher identity and key custody.

### R-REL-04 External review package — blocked (external) for the review itself
- Done: `docs/external-review/README.md`. No independent human review has occurred; AI-assisted reviews (including the one that informed this candidate) are not substitutes.

### R-REL-05 Versioned OWASP/ATLAS mappings — passed
- Evidence: `src/enkstein_guard/coverage.json` (schema 2: controls, scenarios, executed outcomes and residual risk per requirement), `src/enkstein_guard/atlas-evidence.json`, `tools/build_framework_mapping.py --check` passes against the final Linux reports.
- The builder fails closed: it refuses failed, errored or changed scenarios, an unsuccessful core report, and any referenced component test that did not pass. The macOS report is therefore refused (AML.T0025's network-namespace test is Linux-only), as intended.
- Result: 20 OWASP rows, 8 with confirmed gaps; 17 ATLAS technique IDs validated against the pinned 2026.09 dataset — 9 with scenario and component evidence, 2 scenario only, 3 component only, 1 confirmed gap (AML.T0029) and 2 scope limitations (AML.T0020, AML.T0018). No category or technique is declared fully accepted.

### R-SCOPE-01 Training/model poisoning — scope limitation
- Model identity pinned by configuration; retrieval content operator-ingested with digests; poisoned answers not detected (confirmed gap scenario).

### R-SCOPE-02 Factual grounding — passed (scoped)
- Citation provenance and quote checks; semantic support of claims not verified (confirmed gap scenario).

### R-SCOPE-03 Malicious-component handling — passed (scoped; not malware detection)
- Supported control: hash pinning plus a declared-capability static check. Misuse of declared capabilities is not detected (confirmed gap scenario); scanner evaluation recorded.

### R-SCOPE-04 Unsupported surfaces — passed
- Streaming and multimodal parts are rejected; `doctor` reports `windows`, `cloud_isolation`, `high_availability`, `network_agent_messaging` and non-ARM64 architectures `unsupported`; documented in README and guides.

## Confirmed gaps (documented limitations)

1. Correctly pinned component misusing declared capabilities (LLM04/ASI04).
2. Training-data/model poisoning (LLM05; scope limitation).
3. Unsupported claim with a real citation (LLM07).
4. Undeclared, unlabelled hidden context (LLM08).
5. Paraphrased declared context (LLM08).
6. Generic tool connector used for retrieval (LLM09).
7. Same-UID starvation in legacy shared-UID mode (LLM06/ASI08); the production profile requires peer bindings.

## Findings from the AI-assisted documentation review (resolved)

A separate AI-assisted pass compared these documents with code and evidence.
Resolved before the final evidence run: card numbers sent as JSON numbers
bypassed classification and tokenization (fixed and tested); data could lose its
level through a write/read round trip via another route (production
`produces` rule); register count errors, scope statements, image tag, `doctor`
entry, `--version`/`coverage` output contract, legacy evidence image binding and
the egress UID check precision. This was not an independent human review.

## Document status (historical statements verified)

| Document | Finding | Action |
|---|---|---|
| `docs/current-status.md` | Accurate for 0.4.0rc5 | Rewritten for 0.5.0rc1; rc5 numbers kept as history |
| `docs/completion-acceptance.md` | Rows predate the CLI product | Updated with current evidence and pointers here |
| `docs/production-operations.md` | "No retention service", "verifies the complete ledger on each append" and "no database migration" no longer true | Updated; SDK statements kept |
| `docs/security/validation-rc5.md`, `docs/security/validation-rc4.md` | Historical validations | Marked historical |
| `docs/security/coverage-acceptance.md` | Planning matrix ("planned" rows) superseded by the packaged mapping | Marked superseded |
| `docs/linux-production-profile.md`, `docs/deployment-profile.md`, `docs/mandatory-service.md` | Describe SDK/factory profiles; still valid there | Point to `production-deployment.md` / the operator guide |
| `docs/task-boundaries.md`, `docs/vault-reservations.md` | Accurate for the SDK | CLI configuration notes added |

## Operating notes

- Shell execution: Mac-side commands were prefixed with `rtk proxy` per
  `the local development command-wrapper policy`; the Linux sandbox has no `rtk`, so commands there ran directly.
- Container acceptance ran on the operator's Colima VM, which was stopped before
  this work, started for these runs and stopped afterwards. Starting it also
  auto-started four containers from an unrelated local project
  (`secure-ai-intake-router`: api, worker, postgres, n8n). They were not
  touched. They were running during the measurements; a sample taken afterwards
  showed them idle (at most 0.06 % CPU each, about 660 MiB memory in total).
  They stopped again with the VM.
- Docker cleanup removed only this session's superseded image and tag
  (`d5f2020d…`, `enkstein-guard:rc6`); older images, volumes and caches were left.

## Next actions (external)

1. Provide nonproduction Hatz and Cisco credentials and authorization; run
   `tools/live_integration_check.py` and the end-to-end procedure.
2. Push to a hosted repository and run both workflows.
3. Establish publisher identity and sign `dist/release-0.5.0rc1/`.
4. Commission an independent security review using `docs/external-review/`.
