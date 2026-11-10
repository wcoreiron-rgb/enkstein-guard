# Current status — 0.5.0rc2

The CLI product (`enkstein-guard`) is a release candidate for one Linux/Docker
ARM64 host in the `production-linux-peer-bound` profile. **Production
acceptance is not achieved**: live provider acceptance, hosted CI, publisher
signing and an independent human review are outstanding external
dependencies. The authoritative status is the
[readiness register](cli-production-readiness.md); the decision record is
[release decision 0.5.0rc2](release/release-decision-0.5.0rc2.md).

Executed with the release wheel and image, every report identity-bound
(`verification/0.5.0rc2/evidence-check.json`):

- Core tests: Linux ARM64 (Python 3.12.12, exact locked dependency set) 346
  passed, 7 skipped (macOS-only worker sandbox), 0 failed; macOS (Python 3.14.5)
  350 passed, 3 skipped (Linux-only), 0 failed; optional SDK tests 4 passed.
- 42 attack scenarios: 30 prevented, 4 benign allowed, 8 confirmed gaps.
- Production deployment with separate agent UIDs, egress proxy and synthetic
  TLS upstream: 38/38 profile checks; capacity and concurrency 5/5 production capacity targets met;
  3-hour soak with scheduled retention 8/8 soak targets met; disk-full and
  failed-write behaviour 20/20.
- Development-profile operational targets 9/9; legacy isolation and two-UID
  fairness; image scan without findings; upgrade drills from 0.4.0rc5 and 0.5.0rc1.

## Previous candidates (historical)

- 0.5.0rc1 (2026-10-28): [register as released](release/cli-production-readiness-0.5.0rc1.md),
  evidence in `verification/cli-v1/`. Its chat route passed provider-side fetch
  and tool fields through (fixed in rc2, F-1), and its operational report was
  bound to the image by timestamps only.
- 0.4.0rc5 (2026-10-20): 194 core tests on macOS, 23 attack scenarios; Guard
  itself had unrestricted outbound network access and outcome retention was
  manual. See [rc5 validation](security/validation-rc5.md).
