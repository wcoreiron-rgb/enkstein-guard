# Release decision — Enkstein Guard 0.5.0rc1

Date: 2026-10-28. Decision: **release candidate complete for the local scope;
production acceptance NOT achieved.** Not published.

## Artifacts

| Artifact | Identity |
|---|---|
| Wheel | `enkstein_guard-0.5.0rc1-py3-none-any.whl`, SHA-256 `0998c1d81fa7931bc7b5d5d1ea36a3ed0debbd94ce9dc526ccf42822c0dfcc61` |
| Image | `enkstein-guard:0.5.0rc1`, `sha256:933edccc1269678a771913f2a9a474116e296195f8871e5664b79646079a337c` (config digest `sha256:8ed18850…51a2`; Python 3.12 Alpine ARM64, pinned base digest, hash-locked wheelhouse) |
| Provenance | `dist/release-0.5.0rc1/` (unsigned) |

## Passed (executed evidence, supported scope)

- CLI: secure initialization and strict validation; lifecycle with production
  preflight and crash recovery; agents/approvers with digest-only credentials,
  rotation and revocation with in-flight cancellation; policy and task
  boundaries with validated reload; connector secrets from files/stdin only;
  exact-action approvals; audit verify/checkpoint/export/archive; diagnostics;
  stable JSON and exit codes; `doctor` control states.
- Data protection: trusted classification (including card numbers sent as JSON
  numbers), durable per-agent taint and route clearances — an agent's summaries
  cannot leave through Guard to lower-cleared destinations, and in production
  data written to a destination cannot be read back below that destination's
  clearance — privacy tokenize/restore routes, declared-context withholding,
  retrieval authorization before context, citation grounding;
  unlabelled-detection evaluation reported.
- Deployment: mandatory peer-bound profile; network-less Guard with independent
  allowlisting egress proxy; bypass attempts denied (namespace and container).
- Operations: all nine capacity/latency targets met (measured in the
  development profile on one OS user; production-profile behaviour is covered by
  the container checks); restart and duplicate suppression; backup/restore;
  0.4.0rc5 upgrade and fail-closed rollback; safe retention with archived IDs
  never re-executing.
- Release hygiene: reproducible dependency locks and wheel members; image scan
  with zero findings in the current scanner snapshot; versioned OWASP/ATLAS
  control-to-scenario mapping consistent with executed results.

## Not passed — external dependencies

| Requirement | Needed |
|---|---|
| Live Hatz acceptance | nonproduction endpoint, model and key; authorization for synthetic traffic |
| Live Cisco AI Defense acceptance | nonproduction API key; authorization |
| Hosted CI | repository with GitHub Actions (ARM64 runner) |
| Publisher signing | attested builder, publisher identity, key custody or Sigstore identity |
| Independent security review | an independent human reviewer (package prepared) |

## Accepted limitations (confirmed gaps, documented)

Pinned components misusing declared capabilities; training/model poisoning
(scope limitation); unsupported claims with real citations; undeclared or
paraphrased hidden context; generic tool connectors used for retrieval;
legacy shared-UID starvation (production profile requires peer binding);
labels are not tracked for data copied outside Guard's routes (or exposed under
a second destination name); sensitive numbers other than card numbers sent as
JSON numbers need field rules; in-memory approvals; operator-triggered
retention; no HA; single host.

## Conditions for production acceptance

All five external items above completed with recorded evidence in the
readiness register, no new high-severity findings from the independent review,
and a fresh image scan of the signed image digest at deployment time.
No complete OWASP or MITRE ATLAS protection is claimed.
