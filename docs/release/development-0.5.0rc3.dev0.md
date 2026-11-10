# Development validation — 0.5.0rc3.dev0

October 29, 2026. **Unreleased; production acceptance is not achieved.**
This is a new build, not the rc2 candidate. Historical rc2 evidence is preserved.

## Implemented in this batch

- Product-host approvals persist as authenticated encrypted records. Decisions
  and consumption serialize in SQLite; restart, concurrent consumption, current
  approver credential/scope checks, corruption and backup/restore are tested.
- CLI `keys rotate --store audit` publishes an atomic retained-key keyring while
  preserving ciphertext, archives and hash-chain checkpoints. It runs under the
  offline state lock and records rotation under the new primary key.
- Production network connectors require a trusted backend/account inventory,
  matching origin/domain and authorized tenant. Missing-host alias admission is
  denied. Inventoried aliases share the classification floor.

## Build identities

- Wheel: `dist/deployment/enkstein_guard-0.5.0rc3.dev0-py3-none-any.whl`.
  SHA-256: `cdc2f300823c76830809246e3bc1125a438826c2b86e30cce69efec129375c67`.
- Container: `enkstein-guard:0.5.0rc3.dev0`.
  Image ID: `sha256:2500f5e1d44e2604269245ed5dc90f2e77c0f37159f54c717361657db45cfbed`.
- Package-content digest: `6a85291851f3d5fc27fe6a7dd65d8d13a967ef83e07a886be1fee8b4bf888de8`.
- Reports: `verification/0.5.0rc3.dev0/`. The copied musl lock is
  `requirements-musl-arm64.txt`; the active vendor lock now selects this wheel.
  The prior rc2 lock is preserved as `preserved-rc2-requirements-musl-arm64.txt`.

## Executed validation

| Check | Result |
|---|---|
| macOS installed wheel, Python 3.14 | 379 passed, 3 Linux-only skipped, 0 failures/errors; 382 executed |
| Linux extracted wheel, Python 3.12.3, dedicated Colima VM, administrator namespace run | 375 passed, 7 macOS-only skipped, 0 failures/errors; 382 executed |
| Optional installed-wheel SDK tests, Python 3.11 | 4 passed; AGT/NeMo/LangGraph real, Cisco boundary mocked |
| Installed-wheel attack suite | 31 prevented in scenario, 4 benign allowed, 7 confirmed gaps; 42 executed; expected exit 2 |
| Packaged framework mapping | Matches the executed attack outcomes and required passing Linux component tests; no full-category acceptance |
| New image production-profile checks | 38/38 passed; installed image package matches the new wheel |
| New image production disk-full recovery | 20/20 passed |
| New image OS scan | No findings in the refreshed scanner database; no high/critical findings gate passed |
| New image production capacity | Corrected full repeat passed 5/5; identity verified with all four production reports and scan |
| New image multi-hour soak | 8/8 passed; 86,400 requests, zero non-ok responses, zero duplicates; matching wheel and corrected dependency lock |

Linux VM component tests used system cryptography 41.0.7, not the pinned
deployment dependency set. macOS and container dependency inventories are
recorded separately. The container uses the copied hash-locked musl dependency
set; passing VM component tests does not replace installed-image or locked Linux
release acceptance. The earlier ordinary-user VM run skipped user namespaces;
it is retained separately and was not used to claim namespace enforcement.
The first profile/disk-full reports referenced the prior rc2 lock and are retained
with `-superseded-lock` names. Both checks passed again with the active development
lock. Their recorded dependency locks match the installed image. Adding the
capacity report to `partial-snapshot-check.json` correctly fails: it captured the
old lock before correction. The measured capacity outcomes are retained, but a
new full capacity run after soak is required. This is not full release acceptance.

## Compatibility and limits

Existing state requires explicit `init --adopt-existing` while stopped to add the
approval pair. Old backups lacking that pair must first be restored with their
matching release. Missing/corrupt approval state never auto-regenerates at startup.
Ordinary restart preserves approvals, but rollback to an older valid full-state
snapshot can resurrect them without an independent monotonic checkpoint.

Audit rotation retains old decryption keys, with 32 keys maximum. It does not
retire historical keys. Stop all writers before rotation. Direct SDK callers must
honor the same offline requirement as the CLI.

Inventory is trusted operator input, not automatic alias/account discovery.
One origin maps to one inventory entry; separate SaaS accounts on one hostname
cannot have independent identities in this version. Incorrect account mappings
remain a residual risk; omitted hosts fail closed.

Seven known attack gaps, distributed workflow/budget state, wider deployment
platforms, streaming/multimodal support and other original requirements remain
open in [the original requirements register](../original-requirements-roadmap.md).
Live credentials, hosted CI repository, publisher identity and independent human
review remain external inputs. No release was published and no original
upstream application files were changed by this batch.

The [independent-review delta](../security/review-delta-0.5.0rc3.dev0.md) identifies
the changed boundaries, test files, review probes and residual risks. It is a
review request, not an independent assessment result.

The restored `enkstein-guard-completion-loop` heartbeat checks every 30 minutes.
It must keep the package frozen during the soak, repeat capacity with correct
identity afterward, verify the combined snapshot and then continue bounded
original-backlog work. It reports meaningful changes only. The dedicated VM
remains running for these tests; the default Colima profile was not started.

## November 5 verification closure

`verification/0.5.0rc3.dev0/final-snapshot-check.json` passes with explicit wheel, image, dependency lock and revision inputs for production profile, disk-full, corrected capacity and soak, plus the image scan. The wrong-lock run remains superseded history. This closes that validation repeat, not the remaining original product requirements or external release gates. Source development continues separately as 0.5.0rc3.dev1.
