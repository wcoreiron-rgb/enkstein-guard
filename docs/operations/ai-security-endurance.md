# Synthetic AI-security endurance

`deployment/test_ai_security_endurance.py` is a separate, fixed endurance
harness for the AI inspection path. It does not widen or replace the bounded
AI capacity characterization, and its committed regression thresholds are not
production SLAs.

The default command is plan-only. It validates the public operator
configuration and the locked target document, prints the derived plan, and
does not invoke Docker or create processes:

```sh
PYTHONPATH=src \
python deployment/test_ai_security_endurance.py
```

`--plan` is an explicit synonym. Execution requires `--run` and a root-reviewed
candidate wheel, image, dependency lock, and revision:

```sh
PYTHONPATH=src \
GUARD_TEST_IMAGE=enkstein-guard:<candidate> \
python deployment/test_ai_security_endurance.py --run
```

The only accepted override is an explicit integer `--duration 30..10799`.
That runs a smoke/harness check and writes
`production-ai-security-endurance-smoke.json`. Its report always has
`full_acceptance_eligible=false`, `full_acceptance_passed=false`, and
`passed=false`, even when `short_smoke_passed=true`. Omitting `--duration`
runs the fixed 10,800-second profile and writes
`production-ai-security-endurance.json`.

## Fixed profile

- four actors with distinct UIDs and agent credentials, evenly split across
  tenants `a` and `b`;
- 64 retained AI-security votes per actor and global history capacity 256;
- 256 ordinary protected-route warmup calls, with no direct database seed;
- 10,800 measured seconds at 2 requests/second/actor: exactly 21,600 calls per
  actor and 86,400 total;
- at most four concurrent calls per actor, fresh request IDs, no retries, and a
  bounded 75-second drain;
- 60-second agent progress windows plus Guard, egress, store, storage, and
  retention samples;
- service limiter 40 requests/second, outcome capacity 200,000, 3,600-second
  archive age, and 300-second outcome/audit archive intervals.

Warmup must finish for every actor, produce exactly 256 successes, fill the
history to 256, and produce equal inspector, business, and successful-call
counters with zero unknown calls. Measurement does not start if this gate
fails. The history TTL is 21,600 seconds, so the fixed per-actor windows remain
full through the three-hour measurement.

## Isolation and privacy invariants

The harness reuses the reviewed production topology. Guard and all load actors
are networkless. A separate egress proxy owns the only allowed network path to
the fixed local TLS upstream. Each tenant has one business connector and one
security-inspector connector, using four distinct synthetic credentials in
total. Inspector routes are never granted to agents. Both business and
inspection routes retain `privacy=tokenize`; no denial, privacy, or policy
control is weakened.

The upstream persists only bounded counters and SHA-256 credential buckets. It
does not retain prompts, responses, or raw credential values. It fsyncs its
counter file before each response, so latency includes synthetic counter-fsync
overhead. This deterministic fixture does not test provider WAN behavior or
real-model robustness.

## Locked regression targets

Targets live in `deployment/ai-security-endurance-targets.json`; the harness
rejects changed IDs, load parameters, or requirements. The report binds the
target SHA-256 to the evidence header's deployment-tree digest.

- AE-01: complete 256-call warmup and exactly 86,400 successful measured calls,
  zero errors, all four actors complete, and the full 10,800-second interval.
- AE-02: p95 at most 1,000 ms, p99 at most 2,000 ms, and every 60-second-window
  p99 at most 5,000 ms.
- AE-03: Guard RSS at most 256 MiB, egress RSS at most 96 MiB, and last-hour
  Guard peak no more than 32 MiB above first-hour peak.
- AE-04: Guard file descriptors at most 256 and threads at most 64.
- AE-05: history never above 256 and exactly 256 after warmup and at end; active
  state at most 256 MiB.
- AE-06: zero retention failures and successful audit-with-archives and outcome
  archive integrity verification.
- AE-07: in each phase, inspector calls equal business calls equal successes,
  unknown calls are zero, exactly two inspector and two business credential
  hash buckets are observed and disjoint, and two engines are configured.
- AE-08: complete image, wheel, installed-package, dependency-lock, raw saved
  configuration, policy, revision, and target identities with no missing
  measurements.

The load actor emits a sparse one-millisecond histogram, bounded at 120,000 ms,
plus 60-second aggregates. The parent pumps actor stdout and stderr throughout
the run, preventing child pipes from filling while retaining only windows and
the final summary.

## Evidence interpretation

The report keeps warmup and measurement counters separate and records complete
upstream snapshots, full pre-warmup/post-warmup/final security-history status,
actual measurement elapsed time, per-actor completion, retention status, an
operator vault-retention run, audit verification with archives, and outcome
archive verification. The exact public `guard.json` used by the run is
preserved by the standard evidence header; normalized internal defaults are not
serialized as operator input.

Every process/store sample is also appended and fsynced as one JSON line in a
unique `.local-deploy/ai-security-endurance-progress-<project>.jsonl` file. The
report exposes its absolute path so an operator can inspect actual state while
the run is active. Full evidence requires at least 181 samples spanning the
three-hour interval, no gap above 90 seconds, and complete Guard and egress RSS,
FD, thread, active-state, and security-history metrics in every sample. Missing
middle samples or fields fail closed. All four retention job failure counters
must likewise be present, integer, nonnegative, and zero.

The parent bounds measurement supervision at the requested duration plus the
actor's 75-second drain and 120 seconds of container/startup grace. At that
deadline it kills still-owned actor processes, then project-local cleanup tears
down remaining project containers. Timeout and partial runs still write a
failed report. Candidate identity requires all five revision axes: source,
tests, tools, deployment, and definitions.

Counters prove aggregate phase execution only. They do **not** prove that a
per-request marker was never executed twice, and this harness makes no
duplicate-execution claim. Standard production target P-04 remains the separate
no-replay evidence. A shortened run is useful only for checking harness wiring;
it is never a full endurance pass.
