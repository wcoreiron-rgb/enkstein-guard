# Release decision — Enkstein Guard 0.5.0rc2

Date: 2026-10-28. Decision: **release candidate complete for the local scope;
production acceptance NOT achieved.** Not published. 0.5.0rc1 and its evidence
are preserved unchanged ([rc1 decision](release-decision-0.5.0rc1.md)).

## Artifacts

| Artifact | Identity |
|---|---|
| Wheel | `enkstein_guard-0.5.0rc2-py3-none-any.whl`, SHA-256 `d63cbe6583aa1510a65cf7d553d67305e2f53b0e8a528faa024ad24e33c4ae2f` |
| Image | `enkstein-guard:0.5.0rc2`, image ID / manifest digest `sha256:a18a86b722683e469a1cedea64a0193cb86d0e8420d615c75870e316f6dfe7ee` (config digest `sha256:3286e4b1…0fe8`; Python 3.12 Alpine ARM64, pinned base digest, hash-locked wheelhouse) |
| Superseded build | wheel `cbc38df4…`, image `sha256:e6ab75f7…` — failed P-01 (F-10); kept as history, not released |
| Evidence | `verification/0.5.0rc2/` — every report identity-bound (`evidence-check.json`) |
| Provenance | `dist/release-0.5.0rc2/` (unsigned) |

## What changed since 0.5.0rc1

- Security fix: chat requests limited to text messages and function tools
  (provider-side fetch, hosted tools, web search, multimodal parts and provider
  storage were passed through in rc1 — F-1); canonical destination names,
  declared `data_domain` aliases, refusal of provider secrets shared across
  tenants.
- Reliability fixes found by the production-profile harnesses: egress tunnels
  released when Guard closes (F-6); nothing-sent failures reported as
  `unavailable_no_execution` instead of outcome unknown (F-7); refused
  connections answered instead of reset (F-8); retrieval identifiers that the
  card detector could mistake for card numbers, which withheld about 4 in
  100,000 retrieval responses (F-10; the build before this fix failed P-01 and
  is kept as superseded history).
- Authorization across reloads: in-flight work whose grant, identity, clearance,
  groups, route or connector a reload revokes or changes is cancelled, and
  release applies the stricter of both policies (F-11); `data_domain` compared
  case-insensitively, with a warning for likely undeclared aliases.
- Diagnostics and evidence: unreconciled outcomes reported against sizing;
  strict lock comparison; agent-participation gates and real lost-response
  coverage in the restart target; preserved acceptance configurations; an
  explicit-input snapshot verifier contributed by the review loop.
- Operations: request-rate limit per agent; outcome-ledger sizing validated
  against rate, archive age, interval and clock skew; retention scheduled inside
  the service; outcome ledger schema 3 (older releases refuse it; restore the
  pre-upgrade backup to roll back).
- Evidence: identity header in every report, identity check without
  exemptions, explicit passed/skipped/failed/error counts, verdicts for every
  defined target.

## Passed (executed evidence, supported scope)

- Production-profile capacity and concurrency with separate agent UIDs and the
  egress proxy: 5/5 production capacity targets met.
- Multi-hour (3 h) soak with scheduled retention and bounded active stores:
  8/8 soak targets met.
- Disk-full and failed-write behaviour of the vault, audit and outcome stores:
  20/20 disk-full checks plus unit tests with real ENOSPC.
- Production container profile 38/38; legacy isolation and peer fairness;
  development-profile targets 9/9; upgrade drills from 0.4.0rc5 and 0.5.0rc1.
- Core tests: Linux 346 passed, 7 skipped (macOS-only), 0 failed; macOS 350
  passed, 3 skipped (Linux-only), 0 failed; optional SDK 4 passed.
- Attack scenarios: 30 prevented, 4 benign allowed, 8 confirmed gaps (42 executed).
- Image scan: no findings in the current scanner snapshot.
- OWASP/ATLAS mapping regenerated from the final reports (unchanged bytes).

## Not passed — external dependencies

| Requirement | Needed |
|---|---|
| Live Hatz acceptance | nonproduction endpoint, model and key; authorization for synthetic traffic |
| Live Cisco AI Defense acceptance | nonproduction API key; authorization |
| Hosted CI | repository with GitHub Actions (ARM64 runner) |
| Publisher signing | attested builder, publisher identity, key custody or Sigstore identity |
| Independent security review | an independent human reviewer (package prepared) |

## Unsupported features (v1)

HA and multi-host operation, streaming, multimodal inputs, Windows, cloud
isolation, network agent messaging, non-ARM64 architectures, durable approval
tickets, rotation of non-vault store keys; no multi-day soak evidence.

## Unresolved security limitations

Eight confirmed gap scenarios (pinned components misusing declared
capabilities; training/model poisoning; unsupported claims with real
citations; undeclared and paraphrased hidden context; generic tool connectors
used for retrieval; legacy shared-UID starvation; undeclared DNS aliases) and
the residual risks listed in the [readiness register](../cli-production-readiness.md).
No finding from this candidate's own analysis is open; no independent
assessment has been made.

## Conditions for production acceptance

All five external items completed with recorded evidence in the readiness
register, no new high-severity findings from the independent review, and a
fresh image scan of the signed image digest at deployment time. No complete
OWASP or MITRE ATLAS protection is claimed.
