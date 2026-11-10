# Development validation — 0.5.0rc3.dev10 integrated source

Root selected a scalar SQLite row-count/field-size preflight optimization after
frozen dev9 passed the same eight-actor finite latency guardrails (p99189.10ms)
but failed at sixteen actors/4096rows (p994092.84ms). Every warmup/measured
request completed successfully; latency failed the unchanged1000/2000ms gates.
Fullcapacity and both three-hour profiles were never launched for dev9.

The selected integrated implementation preserves full-store ciphertext reading/authentication,
exact-row/keyepoch cache boundaries, identity/path/key/TTL/actor/global checks,
and rotation semantics. No thresholds, schema, key format or configuration are
changed. Workers implement and independently test only assigned staged files.
No staged improvement, installed candidate, deployment or production acceptance
is claimed. Root review, combined regressions, selected integration, a fresh
wheel/image/locks/snapshot and all exact-candidate validation remain required.
Seven confirmed attack gaps and the broader original requirements stay open.


Root reviewed the exact SQLdiff and independent corruption tests and selected
8files for newdev10 integration. Source633tests630passed/3platformskips and
optionalSDK8passed,Cisco mocked; sourceattacks56:42prevented/7benign/7gaps.
Profilerworker stopped atusage limit;root reviewed preservedpartialscript and
completed the comparison. Matched4096row/32op Maccomponent singlethread
0.2517→0.2133s and16thread0.1950→0.1621s;fullciphertextrows131072unchanged,
returnedlengthmetadata rows131072→32. This is component evidence only. The
first multithreadprofiling API failure and one sourceattack interpreterimport
failure are preserved separately; corrected runs completed. Main source is
nowdev10; no newwheel/image/installed/deployment acceptance yet.


## Build rejected before installed acceptance

Frameworkmapping prerequisite failed because root selected an interpreter
without PyYAML, but the build proceeded. Preserve the wheel,image,bothlocks
and source snapshot; rejected-build-identity.json records exact identities.
No installed/production run started. Root corrected the order and advanced
to dev11 before changed inputs/newartifacts. This dev10 build is not accepted.
