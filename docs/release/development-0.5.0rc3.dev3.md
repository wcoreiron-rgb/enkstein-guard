# Development validation — 0.5.0rc3.dev3

Unreleased development candidate. Structural and installed-wheel validation
passed; full capacity, endurance and final snapshot validation also passed. No production or
independent human security acceptance is declared.

This iteration retains the integrated AI security engine and corrects the
synthetic production fixture's ordering. Its benign sensitive request now runs
before adversarial cases accumulate three recorded denial votes. The existing
sequence-risk policy remains unchanged. The failed rc3.dev2 report and exact
169-file input snapshot, wheel, image and both locks are preserved.

Fresh source, installed-wheel, container and identity checks are required for
this version. Earlier-version results are historical evidence, not acceptance
of this candidate. In particular, the passing dev1-to-dev2 adoption/backup/
rollback drill remains identified as that exact version pair.

## Frozen candidate and verified checks

- Wheel SHA256: `d4f51e226e7d21acc6b07ea9da6564872259483febecba868a5ee539c0b5c138`.
- Package-content SHA256: `07644b7bdb0284056a240ad906de0700b7c8115384ab034864c24c3bbf448dff`.
- Image: `enkstein-guard:0.5.0rc3.dev3`, Linux ARM64.
- Image ID: `sha256:472d3bfa4bdf5a29be8419d60181f046cf274c54f6b6c0112c43f3f1b0804bbc`.
- Exact input and dependency-lock identities: `verification/0.5.0rc3.dev3/frozen-candidate.json`.

| Executed check | Result |
|---|---|
| macOS installed wheel, Python 3.14 | 481 passed, 3 platform skips; 484 executed, zero failures/errors |
| Native Linux installed wheel, Python 3.12 | 477 passed, 7 macOS-only skips; 484 executed, zero failures/errors; exact locked dependencies and privileged namespace fixtures |
| Optional SDK installed-wheel checks | 4 passed; AGT/NeMo/LangGraph real, Cisco mocked |
| Attack scenarios | 42 prevented in scenario, 7 benign allowed, 7 confirmed gaps; 56 executed, zero unexpected failures/skips |
| Packaged mapping 2.3 | Matches fresh candidate reports; 20 OWASP rows, 17 selected ATLAS techniques, no full-category acceptance |
| Production boundary | 38/38 passed |
| Disk-full recovery | 20/20 passed |
| Synthetic production AI profile | 40/40 passed; 7 inspection and 3 business calls, sensitive request allowed, denied requests withheld |
| Exact-image vulnerability scan | No findings in the refreshed scanner snapshot at 2026-11-06T15:22:40Z; scan offline after public DB refresh |
| Explicit preflight snapshot | Passed with the wheel, image, both locks, all three structural reports, configuration/revision identities and scan |
| Full capacity | 5/5 passed; sustained 12,000 requests, zero non-ok, p99 97.79 ms; no duplicates through the forced restart/retry scenario |
| Capacity snapshot identity | Passed explicit verification over all four completed production reports plus scan |
| Three-hour soak, fresh attempt 2 | 8/8 passed, full 10,800 seconds, 86,400 requests, zero non-ok or duplicate markers; p99 91.72 ms and no retention failures |
| Final explicit snapshot and root recheck | Passed over all five production reports, scan, exact wheel/image/locks/configuration/revisions; preserved configuration file hashes also verified |

All four installed-wheel report identities match the candidate. The image
package matches the wheel, and runtime dependencies match the musl lock.
macOS and optional SDK environments remain supplemental; they do not claim
to match the native Linux deployment lock. Skipped tests are not passes.

The frozen driver is `verification/0.5.0rc3.dev3/run-frozen-acceptance.py`.
Inspect its status, actual processes and final reports before recording a pass.
It deliberately leaves `production_accepted` false even after local success.

AI inspection uses a tokenized bounded copy and a fixed internal brokered
provider. Strict assessment results cannot grant access, rewrite actions or
override deterministic denial. The history supplies actor-scoped rolling
context, while audit records final combined decisions and execution outcomes.

Seven known attack gaps, live-model robustness, AI-enabled capacity/full-history
performance, wider platforms/integrations and external release gates remain
open. See the original requirements register, AI security operator guide and
AI history sizing notes.

## Local frozen-run closure

The detached retry completed at 2026-11-07T02:28:12Z. Its accepted report and
final verdict remain under `verification/0.5.0rc3.dev3/soak-attempt-2/`.
`final-snapshot-recheck.json` records root's explicit second check. All eight
soak verdicts passed. The interrupted first attempt remains separate and
unaccepted, despite its captured successful request totals.

A matching 169-file input snapshot and both locks are preserved. The completed
retry cleaned its own containers; none remained at review. Docker context was
default, and the dedicated validation VM was stopped. Seven synthetic evidence
volumes from the interrupted attempt remain preserved for review.

These results validate the recorded single-host local profile. They do not
measure real-model robustness or AI-enabled full-history capacity, close the
seven attack gaps, establish full OWASP/ATLAS coverage, or satisfy publisher,
live-integration and independent human review gates. Staged dev4 changes are
not represented by these results and require fresh candidate validation.
