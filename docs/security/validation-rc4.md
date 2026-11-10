# Security validation result — 0.4.0rc4

> Historical record for 0.4.0rc4. Current status and evidence for 0.5.0rc1 are in
> [cli-production-readiness.md](../cli-production-readiness.md).

**Release gate: blocked.** The assessment is executed; it is not a production
security sign-off. Existing projects and live agents remain untouched.

## Attack evidence

23 synthetic scenarios span all 20 OWASP LLM/Agentic category rows: 14 attack
attempts prevented in the configured boundary, three benign operations allowed,
and six confirmed gaps. Tests simulate an already-compromised planner; they do
not measure a real model's resistance to every natural-language injection.
Eight MITRE ATLAS technique IDs are mapped in these scenarios; selected component
evidence is also packaged. This is not complete technique prevention coverage.
Official source snapshots and hashes are in verification/references.

Confirmed gaps:

1. Correctly pinned malicious tools are not automatically classified as malware.
2. Training-data/model-weight poisoning is not detected by the memory controls.
3. Fabricated citations and unsupported claims lack grounding verification.
4. Unlabelled confidential context can be echoed when it matches no sensitive pattern.
5. Generic retrieval routes do not supply document-level vector-store ACLs.
6. Same-UID socket peers can sustain pre-authentication admission starvation.

`python tools/verify_attack_scenarios.py --output verification/attack-scenarios.json`
returns exit 2 while known gaps remain, and exit 1 for unexpected regressions.
Expected failures are counted as confirmed gaps, not prevented attacks. Non-assertion
errors in gap probes are treated as errors, not quietly accepted gaps.

## Exact-image scan

Trivy 0.75.0, pinned by image digest, scanned an exported image offline without
Docker socket access. The final image ID, archive/report hashes and scan time are
in verification/os-image-scan.provenance.json. No unfixed findings are suppressed.

Baseline: 45 High OS instances and four High Python-library instances.
After base refresh and removal of unnecessary pip/ensurepip runtime artifacts:
zero Critical, 44 High OS instances across eight CVEs, zero Python findings, and
no High finding with an available fixed version in this database snapshot.
Medium/Low/Unknown findings remain in the full JSON. Absence of a fix is not a
waiver or evidence of non-exploitability. Reachability triage and base remediation
are still required before release.

`python tools/scan_image.py --image enkstein-guard:security-review --refresh-db`
returns exit 2 on any High/Critical finding. Subsequent offline reruns can omit
--refresh-db when a populated cache exists. Scanner/network provenance is saved.
The runtime image no longer includes pip: build/install new dependencies in the
wheelhouse and rebuild; do not mutate running containers.

## Review and fixes

See independent-review-rc4.md for the separate AI-assisted review. Fixed findings
cover cross-tenant ledger capacity consumption, abandoned blocking HTTP work,
denied-request vault growth, per-payload quadratic tokenization work, and incorrect
unknown-outcome handling during cleanup failure. Regression tests accompany fixes.
Open findings include shared-socket fairness, bounded synchronous vault accounting,
optional explicit vault reservations, and outcome retention management.

Final package verification: 161 core tests passed on macOS; Linux ran 161 with
seven macOS-only skips; four optional integration tests passed. Restricted Linux
container and forced-restart checks passed. Cisco/HTTP service boundaries remain
mocked in integration tests; no live provider validation was added by this work.

## Automation and release evidence

.github/workflows/security-validation.yml defines attack and image gates using
pinned action/scanner versions. It has not run on hosted GitHub runners. Its gates
are expected to block until gaps and High findings are resolved; reports upload
on failure. Private repositories may need a permitted ARM64 runner label.

The locally signed evidence bundle is dist/security-rc4. The development public
key is separate; this is tamper evidence for local artifacts, not independent
publisher identity or third-party certification. Full OWASP acceptance remains
zero categories; scenario coverage is reported separately.
