# Development validation — 0.5.0rc3.dev1

November 5, 2026. **Unreleased; full product/production acceptance is not achieved.**
Three Codex implementation agents and root completed this iteration. Opus was
not used. Historical rc2 and rc3.dev0 artifacts and evidence are preserved.

## Implemented and integrated

| Requirement | Implemented behavior | Practical limit |
|---|---|---|
| Default model privacy | Chat connectors default to vault tokenization before controls/dispatch; detected numeric card values tokenize; output protection remains; explicit operator reasons required for model plaintext/restore exceptions | Heuristic text/JSON detection; undeclared prose and paraphrases remain gaps. Provider auth headers still use the intended brokered credential |
| Restart-safe orchestration | Optional encrypted WorkflowStore preserves budgets, labels, grants, revocation, artifacts, memory and deliveries; exclusive coordinator ownership; admission charged before dispatch; current registry validated on recovery | Single-host SDK attachment; not automatic CLI-service workflow storage, multi-host consensus, rollback protection or a durable execution queue |
| Safe uncertain outcomes | Pre-dispatch storage failure denies execution; failed final commit after dispatch raises `orchestration_outcome_unknown`; recovery keeps spent budget and never automatically replays interrupted work | Caller must reconcile external side effects; a new caller-initiated action is not deduplicated by this SDK store |
| Source-extractive output | Strict configured mode releases only authorized exact source spans in a bounded answer/citations schema; tested chat adapter unwraps completed assistant JSON and discards provider metadata | Proves text provenance, not source truth or semantic entailment. Selected source spans can still mislead. Legacy citation mode retains its documented gap |
| Honest CLI diagnostics | Doctor/policy output shows privacy exceptions without their freeform reasons, distinguishes configured tokenization, and labels durable orchestration as an explicitly attached SDK feature | Installing the wheel still does not intercept unrelated agents or processes |

Important operator references: [model privacy](../default-model-privacy.md),
[workflow recovery](../durable-workflows.md), [extractive mode](../extractive-grounding.md),
and [chat response contract](../extractive-chat-adapter.md).

## Frozen build

- Wheel: `dist/deployment/enkstein_guard-0.5.0rc3.dev1-py3-none-any.whl`.
- Wheel SHA-256: `179355c4df0e34127acc357a554059133a4a90348e10224f6b1ed50de26fb6c8`.
- Package-content digest: `99792bf26bd9def280f186213e7c559957415c13adda4a4e3b12d07aaf3592f7`.
- Image: `enkstein-guard:0.5.0rc3.dev1`.
- Image ID: `sha256:0d50e545aaef473db49fd1ce0c7113f47bc2f99924081f064ce1bcff90f3d34c`.
- Evidence directory: `verification/0.5.0rc3.dev1/`. Both native Linux and musl
  locks were updated before final installed-wheel/image measurement. Prior locks
  were preserved in that directory.

## Validation

| Executed check | Result |
|---|---|
| macOS installed wheel, Python 3.14 | 431 passed, 3 Linux-only skips, 0 failures/errors; 434 executed |
| Linux installed wheel, Python 3.12, exact hash-locked dependencies in isolated environment | 427 passed, 7 macOS-only skips, 0 failures/errors; 434 executed |
| Optional installed-wheel SDK checks, Python 3.11 | 4 passed; AGT/NeMo/LangGraph real, Cisco mocked |
| Adversarial suite | 36 prevented in scenario, 6 benign allowed, 7 confirmed gaps; 49 executed, no unexpected failures or skips |
| Real subprocess death | A coordinator is killed after a synthetic side effect; restart retains the charge and refuses a repeated action when its budget is exhausted |
| In-flight policy tightening | Citation-to-extractive reload cannot release unsupported prose; tested through real Guard IPC and document retrieval |
| Packaged mapping 2.2 | Matches executed scenarios and required passing component tests; 20 OWASP rows, 17 selected ATLAS techniques; no full-category acceptance |
| New image production boundary | 38/38 passed; wheel package and dependency lock match |
| New image disk-full recovery | 20/20 passed; wheel package and dependency lock match |
| Refreshed image scan | No findings in scanner snapshot; image/dependency identity recorded |
| New image full capacity | 5/5 passed: 12,000 sustained requests, zero non-ok, p99 66.41 ms; zero duplicates through forced restart |
| New image three-hour soak | 8/8 passed; 86,400 requests, zero non-ok/duplicates, scheduled retention without failures |
| Combined final production snapshot | Passed; explicitly rechecked against the expected wheel, image, lock, configuration and revision inputs |

The macOS/optional environments contain development or SDK distributions and
are not a match for the deployment's native Linux lock. Their reports retain
that fact; they are supplementary tests of the matching imported wheel content.
The installed-wheel Linux suite and production image use their exact locks.
Skipped platform tests are not passes, and test counts do not estimate attack
protection percentages. All seven existing confirmed gaps remain explicit.

## Running work and completion ownership

`verification/0.5.0rc3.dev1/run-frozen-acceptance.py` runs full capacity, full
three-hour soak and the explicit final snapshot verifier sequentially. Inspect
`acceptance-run-status.json` and actual process/report state. Do not start a
duplicate job, change frozen inputs or retag the image while it is running.
The active `enkstein-guard-completion-loop` checks progress every 30 minutes,
uses Codex only and reports meaningful changes. It must verify every verdict
and identity before recording a pass. A driver failure remains a failure.

## Open original requirements

The [full requirements register](../original-requirements-roadmap.md) remains
open. It includes remaining key lifecycles, wider OS/cloud/architecture support,
distributed state, streaming/multimodal paths, useful additional engine reuse,
live ServiceNow/Hatz/VirusTotal/Cisco acceptance, the seven attack gaps, hosted
CI, publisher signing and independent human review. No live credentials were
used, no repository was published or changed remotely, and no original
upstream application files were modified.

## Capacity checkpoint — 2026-11-06T04:43:07+00:00

`capacity-snapshot-check.json` passes explicit wheel/image/dependency/config/revision binding for production boundary, disk-full and capacity plus the scan. The three-hour soak and combined final snapshot remain pending. No frozen code or acceptance definitions changed.

## Final frozen-run closure — 2026-11-06T09:22:08+00:00

All capacity (5/5) and soak (8/8) targets passed. The three-hour run completed 86,400 requests with zero non-ok responses or duplicate execution. `final-snapshot-check.json` and `final-snapshot-recheck.json` both pass. This establishes the recorded local frozen-build results only; full product/external acceptance remains open. No acceptance processes or containers remained at review. The Docker context was restored to default and the dedicated VM was stopped after the run. New AI security engine work remains isolated in staging and is not represented by these results.
