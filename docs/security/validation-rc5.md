# Linux/Docker validation — 0.4.0rc5 (historical)

> Historical record for 0.4.0rc5. Current status and evidence for 0.5.0rc1 are in
> [cli-production-readiness.md](../cli-production-readiness.md). Statements below
> about Guard's unrestricted outbound access and manual outcome retention describe
> rc5 and are superseded for the CLI production profile.

October 20, 2026. Local release candidate; not published or production signed off.

## Implemented boundaries

- Linux SO_PEERCRED binds each OS UID to its tenant, principal and agent before
  payload reading. Valid stolen credentials from another identity are rejected.
  Per-UID quotas reserve application connection capacity for registered agents.
- Compose separates Guard and agent UIDs, restricts socket access, mounts agent
  files read-only, disables agent networking and applies resource limits.
- Encrypted persisted vault reservations are established during trusted bootstrap.
  PrivateAI reserves its tenant; orchestration reserves registered tool tenants.
- Trusted startup creates immutable task boundaries pinned to generated workflow
  IDs, routes, resources, destinations, operations and exact payload schemas.
  Delegated agents inherit enforcement. The factory is optional for compatibility;
  deployments requiring task restrictions must configure it.

## Executed evidence

- Installed wheel: 194 core tests passed on macOS.
- Exact final Alpine image: 187 passed, seven platform skips, no failures.
- Optional SDKs: four passed, external service calls mocked.
- Separate container UIDs: stolen credential rejected; three connection-quota
  exhaustion rounds while another tenant completed 20 requests.
- Restricted-container, forced-restart and durable duplicate checks passed.
- Legacy vault upgrade, rotation and restart drill passed.
- Attack suite: 23 scenarios, 14 prevented, three benign, six confirmed gaps;
  expected gate exit 2 with no unexpected regressions.

Evidence is in verification/readiness-*, peer-isolation.json, container-isolation.json
and alpine-os-scan*. Scan provenance binds the exact image and report hashes.
The updated CI definition has not run on hosted GitHub runners.

## Image change

Compose/CI select pinned Python 3.12 Alpine, hash-locked musllinux dependencies,
removed pip/ensurepip and pinned zlib 1.3.2-r1. OS package retrieval requires network
during build; Python installation uses the local wheelhouse. The scanner ran
offline without Docker socket access and suppressed no unfixed findings. The final
scan reports zero findings in the current database snapshot. Future builds must
scan again; this result does not establish that all vulnerabilities are absent.
The previous Debian image remains a legacy alternative with unresolved findings.

## Open release requirements

The six attack gaps are described in validation-rc4.md. Linux peer binding addresses
socket admission only in this profile; legacy same-UID mode remains vulnerable.
Malicious pinned tools, model/training poisoning, grounding, unlabelled confidential
context and document-level retrieval authorization still need application defenses.

Shared CPU/backlog/host exhaustion, synchronous vault accounting and durable outcome
retention require operational controls. Real connector acceptance, independent human
security review, trusted publisher identity and full category acceptance remain
outstanding. No complete OWASP or MITRE ATLAS protection is claimed. Development
signatures and AI-assisted review do not replace those requirements.
