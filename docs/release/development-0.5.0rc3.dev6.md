# Development validation — 0.5.0rc3.dev6

Unreleased candidate. Structural checks and scoped AI-history characterization
passed. Full capacity passed all five targets; the fresh three-hour soak passed
all eight targets. Final snapshot and root recheck passed. No full product,
production, independent human review, OWASP or
MITRE ATLAS acceptance is declared. Seven attack gaps remain open.

## Candidate identity

- Wheel SHA256: `6b594013cf977a0a56e8bf0dea23f29c9bd66f4da11c17ed2a1845d8943ac1e6`.
- Image: `enkstein-guard:0.5.0rc3.dev6`, Linux ARM64.
- Image ID: `sha256:0715c0d3ce3abe36cb37e58868ecdc053c4d03162c37a6d283569566c56e2cff`.
- Package SHA256: `211e57aafaf18da8f0fa4617df70d846a29ad209039c4ac70d7474bebd09f964`.
- Exact 177-file source/test/tool/deployment/definition snapshot and both locks:
  `verification/0.5.0rc3.dev6/frozen-candidate.json` and `source-snapshot/`.

The image probe matches the wheel package and confirms pinned zlib 1.4-r0 and
musl/musl-utils 1.2.6-r3. All candidate inputs are frozen during validation.

## What changed

The existing offline CLI key-rotation command now covers connector secrets and
approval storage, with explicit resume, stale-writer refusal, fixed partial
failure reporting, and paired backup/restore. Rotation preserves secret scopes
and approval bindings/consumption. It requires downtime and retains old decrypt
keys; it does not provide key retirement, secure erasure or rollback resistance.
Old releases need a matching pre-rotation backup after the keyring format changes.

The AI-path characterization harness fills each configured actor history through
ordinary protected requests before measurement. Its config builder validates
public configuration without serializing internal normalized fields. Shared
bootstrap seeds the local kb collection only when declared. Real CLI serialization
and model-only bootstrap regressions cover those handoffs; product validators
and security policies were not relaxed.

The failed dev4 image build and dev5 characterization remain preserved with
their wheels, images where created, locks, exact snapshots, reports and logs.
The earlier 523-test dev6 bootstrap is superseded by the final 524-test input.
No earlier result substitutes for this candidate.

## Executed checks

| Check | Result |
|---|---|
| Installed macOS wheel | 521 passed, 3 Linux-only skips; 524 executed |
| Installed native Linux wheel | 517 passed, 7 macOS-only skips; 524 executed; exact locked dependencies and privileged namespace fixtures |
| Optional SDKs | 4 passed; Cisco mocked |
| Attack scenarios | 42 prevented in scenario, 7 benign, 7 confirmed gaps; 56 executed; no unexpected failure or skip |
| Packaged mapping 2.3 | Matches installed reports; 20 OWASP rows and 17 selected ATLAS techniques; no full-category acceptance |
| Production boundary | 38/38 passed |
| Disk-full recovery | 20/20 passed |
| Synthetic AI production wiring | 40/40 passed |
| Refreshed exact-image scan | No findings in the snapshot at 2026-11-07T03:25:22Z; networkless scan after public DB refresh; unfixed findings not ignored |
| Explicit preflight snapshot | Passed over all three production reports plus scan, exact wheel/image/locks and revision identities |
| Full capacity | 5/5 passed; sustained 12,000 requests, zero non-ok/duplicates, p99 58.56 ms |
| Capacity snapshot | Passed over four production reports plus scan and exact candidate/lock/configuration/revision identities |
| Fresh three-hour soak | 8/8 passed, 10,800 seconds, 86,400 successful requests, zero duplicates; p99 75.31 ms |
| Final snapshot and root recheck | Passed all five production reports plus scan, exact identities and saved configuration hashes |

Root verified every structural verdict and actual saved configuration hash.
All four installed reports match the frozen candidate; native dependencies match
the lock. Skips and confirmed gaps are not passes. Supplemental SDK/macOS results
are not represented as the Linux container environment.

## Executed AI-history observations

| Synthetic profile | Warmup | Measured requests | Total client p99 |
|---|---|---|---|
| Two actors, 16 retained votes each | 32/32 succeeded; 32 records full | 40/40 succeeded, zero errors/drain | 54.52 ms |
| Four actors, 64 retained votes each | 256/256 succeeded; 256 records full | 120/120 succeeded, zero errors/drain | 139.9 ms |

Histories remained full after measurement. Root verified exact candidate/revision
identity, saved configurations, inspector/business counters and separate tenant
credentials. The reports occupy separate directories so their configurations are
preserved. These are finite local synthetic TLS observations, including counter
fsync overhead. They do not establish real-model robustness, production SLOs,
maximum supported storage performance or endurance.

## Local validation closure

The existing detached driver completed at 2026-11-07T06:44:55Z. Root reviewed
all eight soak targets, the full-duration flags, every report identity and the
actual saved configurations. A second explicit snapshot check passed over all
five production reports plus scan. The three-hour run had 86,400 successful
requests, no duplicate execution, and no retention failures; p99 was 75.31 ms.
Guard RSS peaked at 43.3 MiB. Active state ended near 53.45 MB; archives ended
near 223.18 MB, or 2,583.1 bytes per tracked request for this synthetic workload.

The exact input snapshot, locks, reports and progress samples remain preserved.
Driver and phase processes exited; no owned containers remained. Docker context
was default and the dedicated validation VM was stopped. Unrelated resources
and the default VM profile were untouched. See closure.json for report hashes.

This closes this exact local Linux ARM64 candidate's validation milestone.
Seven attack gaps, real-model robustness, broader platform/integration work,
publisher signing, hosted CI, live integration credentials and independent human
review remain open. The original requirements register still governs completion.
Any later changed code needs a new version and fresh evidence; these results
cannot validate staged or future source.
