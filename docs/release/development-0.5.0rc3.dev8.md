# Development validation — 0.5.0rc3.dev8

Unreleased candidate; scoped local validation COMPLETE. Installed-package,
production structure, scan, fullcapacity5/5, standard3hsoak8/8 and separate
AI-enabled3hendurance8/8 passed. Driver final snapshot and root explicit recheck
passed all6required production reports plus scan and actual saved configurations. No full product,
production, independent human review, OWASP or ATLAS acceptance is declared.

## Candidate identity

- Wheel SHA256: `2cc2b96f44723bd2b42f5821c79f7d2bcb8e5ee4847083a33fb0a13e683f46d7`.
- Package SHA256: `f518fa74972848895e851ac3e0b04cb7e6709dec28df792a0871299324a7ecc0`.
- Image: `enkstein-guard:0.5.0rc3.dev8`, Linux ARM64.
- Image ID: `sha256:997652245916cbb2a1a8e15f11dbf90654ed304195b561b84b742034f8540347`.
- Exact189input snapshot, both locks, image probe and frozen-candidate.json
  preserved under verification/0.5.0rc3.dev8. Image package matches wheel and
  the image's dependencies match the exact musl lock (build pip absent).

All candidate inputs remain frozen. Earlier dev7 closure/artifacts and every
failed attempt remain preserved and do not validate changed dev8 inputs.

## Changes and review

Root integrated20selectedfiles from three independent executor slices, then
regenerated the two packaged framework mappings before building. IdentityStore
supports offline retained HMAC signing-key rotation/resume; the CLI adds
`keys rotate --store identities`. Exact credential digests, generations,
revocations, timestamps and serial survive reauthentication. Identity JSON is
authenticated, not encrypted. Private paths, stale-handle checks and stable locks
protect writes. Durable key publication precedes the atomic signed-envelope
rewrite; retained keys make post-publication resume possible without ring growth.

Root review corrected legacy raw hex whitespace compatibility and descriptor
cleanup. CLI audit preflight/postcheck and stopped-service lock remain mandatory.
Paired backup verification authenticates identity data, including before restore
copies files. Retained signing keys remain trusted and could forge records if
compromised; no retirement, erasure, rollback resistance or online rotation claim.

The new separate AI endurance harness defaults to plan-only and needs --run.
Its fixed full profile is4actors across2tenants,64retainedvotes/actor,256ordinary
warmup requests,10800seconds at2rps/actor (86400 measured), with no retries.
It requires complete resource/retention telemetry, at least181samples spanning
three hours, exact inspector/business counts and distinct credential sets,
archive verification and exact candidate/configuration/revision/target binding.
Timeouts and missing telemetry fail closed. A shortened run is explicitly smoke
only. Synthetic counters do not prove per-marker duplicate execution; standard
P04 replay evidence is separate. No real-model robustness is established.

The reproducible vendor metadata tool found67projected optional distributions,
including19local native macOS artifacts. Local metadata/API tests do not prove
Alpine/musl ARM64 availability/install/imports, and vendor factories remain
trusted SDK bootstrap only, not CLI activation. Root review corrected bounded
marker semantics and URL evidence sanitization. All workers completed.

## Executed candidate checks

| Check | Result |
|---|---|
| Installed macOS wheel | 594 passed,3 Linux-only skips;597 executed |
| Installed native Linux wheel | 590 passed,7 macOS-only skips;597 executed; exact locked deps |
| Optional SDKs | 8 passed,0 skips; Cisco remote mocked |
| Attack scenarios | 42 prevented in scenario,7 benign,7 confirmed gaps;56 executed;0 unexpected failures/skips |
| Packaged mapping2.3 | Matches installed reports;20OWASP rows/17selectedATLAS;0 full-category acceptance |
| Production boundary | 38/38 passed |
| Disk-full recovery | 20/20 passed |
| Synthetic AI production wiring | 40/40 passed |
| AI endurance short smoke | 256/256 warmup,240/240 measured over30seconds;0errors;p99 ceiling150ms; full_acceptance_passed=false |
| Refreshed exact-image scan | No findings at2026-11-07T12:33:18Z; no unfixed ignored; networkless scan after publicDBrefresh |
| Explicit preflight snapshot | Passed3productionreports+scan, exact wheel/image/locks/revisions and saved configurations |
| Full capacity | 5/5 passed;12,000 sustained requests,zero non-ok/duplicates,p99 68.53ms;forced restart3.8s,55lost responses resubmitted without duplicate execution |
| Capacity identity snapshot | Driver explicit4report+scan snapshot and root verdict/config/identity review passed |
| Standard three-hour soak | 8/8 passed;86400successful,zero non-ok/duplicates/retention failures,p99 65.73ms; exact5report snapshot/root review passed |
| Separate AI three-hour endurance | 8/8 passed;256warmup+86400measured successful,0errors,4actors/64votes each,182samples,p95 ceiling169ms,p99 ceiling280ms |
| Final snapshot/root recheck | Both passed6requiredreports+scan, exact wheel/image/package/locks/revisions and actual savedconfig hashes |

Root verified all4installed reports and every38/20/40structural verdict, actual
saved config hashes, image/wheel/package/revision/dependency identities, smoke
classification and scan binding. structural-root-review.json and
preflight-snapshot-root.json preserve review. Smoke evidence has its own
ai-endurance-smoke directory. Earlier597source/8optional bootstrap checks and
nativeLinux source results are preserved separately; they are not installed
candidate evidence. A pre-image metadata helper AttributeError is recorded in
bootstrap-driver-incidents.json; it changed no product input and counted no test.

## Scoped local closure

The detached driver completed at2026-11-07T23:51:44Z. Root independently reviewed
all8AI targets, all4actors completing21600requests each,256successfulwarmup,
86400successfulmeasured,0errors,182complete resource samples, bounded/full256
history and exact inspector/business phase counts with separate credentials.
Audit/outcome archives verified; retention failures0. GuardRSSmax43.664MiB,
egress37.465MiB,GuardFDmax16,threads10,active state54256958bytes.
The p99 is a conservative1ms histogram ceiling280ms; maxwindowp99430.188ms.
These are synthetic local observations with counter-fsync overhead, not SLAs.

Driver final6report+scan snapshot and root explicit recheck passed exact
candidate/dependency/revision binding and actual saved configs. Artifacts:
closure.json,ai-endurance-root-review.json,final-snapshot-recheck.json. Full
AI progress was copied into evidence. Both driver and phase exited; no owned
container remained. GlobalDockercontextdefault; dedicatedVMenkstein-rc2 stopped
successfully2026-11-08T00:02:53Z. Defaultprofile/unrelatedresources untouched;
old interrupted-run evidence volumes remain retained. Do not rerun completed
acceptance. No full production/product acceptance follows this local milestone.

The standard capacity/soak has optional AI assessment DISABLED. The completed
separate AI-enabled full run establishes only its4actor/64vote/8rps profile.
Larger-scale/full-storage histories, real-model robustness, seven attack gaps,
wider platforms/integrations, vendor target deployability/CLIactivation and
external repository/publisher/credentials/independent-human-review gates remain
open under the original requirements roadmap.

## Additional finite history observations — latency guardrail FAILED

A separate8actor/256votes-each profile filled2048records and completed2048warmup
plus960measured requests successfully. It FAILED predeclared latency guardrails:
p9588876.17ms,p9991566.31ms (limit2000ms),queuep9987089.92ms,RPCp995912.38ms,
91.066sdrain after60seconds offered load. Identity/counters/resources and retained
history checks passed. The planned16actor profile was withheld. Failed evidence
and plans are preserved; no thresholds relaxed and no failed run calledaccepted.

This new performance limitation qualifies the product scope. The completed
4actor/64vote/8rps three-hour result remains valid only for that configuration.
No larger-scale or full-storage-limit claim is made. DedicatedVM stopped after
owned resources completed; an isolatedMac synthetic component diagnostic is
running to attribute bottleneck before any new-version optimization. Main dev8
source, wheel, image, locks and prior acceptance artifacts remain unchanged.
