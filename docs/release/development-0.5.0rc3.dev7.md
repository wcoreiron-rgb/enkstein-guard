# Development validation — 0.5.0rc3.dev7

Unreleased candidate. Installed tests, production structure, finite AI-history
characterizations, scan and preflight identity checks passed. Full capacity
passed all five targets; the fresh three-hour soak passed all eight targets. No full product,
production, independent human review, OWASP or ATLAS acceptance is declared.

## Candidate identity

- Wheel SHA256: `2265023e23108ffc8efc5b3d442b2989f33b89959d9b11e3716a1f0c84ba64f1`.
- Image: `enkstein-guard:0.5.0rc3.dev7`, Linux ARM64.
- Image ID: `sha256:0a83043ff5082ba0d618b5803c4275ef2b45f4206fa3bf6ab3c79045a89ff591`.
- Package SHA256: `7f58c7e7af194ea3a4297ffc03f1ebe24d6d82511e0e01ec711db0daf53121ce`.
- Exact 181-file input snapshot and both dependency locks are preserved under
  `verification/0.5.0rc3.dev7/`; the image package matches the wheel.

All candidate inputs remain frozen during validation. The validated dev6
artifacts/evidence are preserved and do not validate this changed candidate.

## Changes

The offline CLI supports `keys rotate --store security-history`, including
resume, retained-key actor/tenant selector rekeying, paired backup/restore and
normal TTL expiry on reopen. Legacy raw key bytes remain compatible. Cleanup
releases the SQLite writer before administrative/per-object locks and cannot
leak raw errors. Stale or concurrent writers cannot publish obsolete selectors.

The SDK WorkflowStore supports offline retained-key rotation before attaching
a coordinator. Exclusive ownership, budgets, grants, state and no-replay semantics
are preserved; attached, closed and unowned stores refuse rotation. Both stores
publish a durable retained keyring before transactional re-encryption and resume
without ring growth. Key retirement, secure erasure and rollback resistance are
not provided. No arbitrary SDK workflow CLI or IdentityStore HMAC-key rotation
was added.

The vendor inventory and four new optional contract tests identify the exact
AGT/NeMo interfaces, versions and failure behavior. These still require explicit
trusted SDK bootstrap; CLI security_engines does not activate vendor factories.
Cisco's remote boundary remains mocked. No blanket vendor/category claim follows.

## Executed checks

| Check | Result |
|---|---|
| Installed macOS wheel | 545 passed, 3 Linux-only skips; 548 executed |
| Installed native Linux wheel | 541 passed, 7 macOS-only skips; 548 executed; exact locked dependencies |
| Optional SDKs | 8 passed, zero skips; Cisco mocked |
| Attack scenarios | 42 prevented in scenario, 7 benign, 7 confirmed gaps; 56 executed, no unexpected failure/skip |
| Packaged mapping 2.3 | Matches current reports; 20 OWASP rows, 17 selected ATLAS techniques; no full-category acceptance |
| Production boundary | 38/38 passed |
| Disk-full recovery | 20/20 passed |
| Synthetic AI production wiring | 40/40 passed |
| Refreshed exact-image scan | No findings at 2026-11-07T07:25:50Z; networkless scan after public DB refresh; unfixed findings not ignored |
| Explicit preflight snapshot | Passed three production reports plus scan and exact candidate/lock/revision/configuration identities |
| Full capacity | 5/5 passed; sustained 12,000 requests, zero non-ok/duplicates, p99 54.96 ms |
| Capacity identity snapshot | Passed four production reports plus scan and exact candidate/lock/revision/configuration identities |
| Fresh three-hour soak | 8/8 passed; full 10,800 seconds, 86,400 successful requests, zero non-ok/duplicates/retention failures, p99 71.3 ms |
| Final snapshot/root recheck | Both passed all five production reports plus scan, exact wheel/image/locks/revisions and actual saved configuration hashes |

Root reviewed every structural verdict and actual saved configuration hash.
All four installed reports match the candidate. Skips and gaps are not passes.
Earlier staged source regressions are preserved separately: 87 focused checks,
548 full core checks with 3 skips, 8 optional checks and 3 workflow recovery cases.

## AI-history observations

| Local synthetic profile | Warmup | Measured requests | Total client p99 |
|---|---|---|---|
| Two actors, 16 retained votes each | 32/32 succeeded; 32 records full | 40/40 succeeded; zero errors/drain | 53.17 ms |
| Four actors, 64 retained votes each | 256/256 succeeded; 256 records full | 120/120 succeeded; zero errors/drain | 193.18 ms |

Root verified histories remained full, inspector/business counters and credential
separation, exact candidate/revision identity and saved configurations. Separate
report directories preserve each configuration. Measurements include synthetic
counter fsync overhead; they are not production SLOs or real-model robustness.

The standard full-capacity/soak profile does not enable optional AI assessment.
AI-enabled multi-hour endurance and larger-scale history performance remain
unvalidated; the finite observations above do not close those requirements.

## Local validation closure

The detached exclusive driver completed at 2026-11-07T10:46:00Z. Root reviewed
all eight full-soak verdicts, 86,400 successful requests, zero non-ok or duplicate
execution, and zero retention failures. Guard RSS peaked at 43.3 MiB; active
state ended at 54,473,463 bytes and archives at 223,150,431 bytes. Both the driver
snapshot and root explicit recheck passed all five production reports plus scan,
exact candidate/dependency/revision identities and actual saved configurations.
`closure.json` and `soak-root-review.json` preserve the review; progress samples
were copied into evidence. No elapsed-time inference substitutes for reports.

Both processes exited; no owned running container remained. Dedicated Colima
profile enkstein-rc2 stopped successfully at 2026-11-07T11:10:28Z. Global Docker
context is default; default profile and unrelated resources were untouched.
Old interrupted-run evidence volumes remain retained. Do not rerun this driver.
This is a scoped local milestone; broader production acceptance remains open.

Seven attack gaps, real-model robustness, wider platforms/integrations, vendor
CLI activation, publisher signing, hosted CI, live test credentials and independent
human review remain open. The original requirements register governs completion.
