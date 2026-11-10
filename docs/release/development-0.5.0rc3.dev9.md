# Development validation — 0.5.0rc3.dev9

Root integrated11selectedreviewedfiles from staging/history-scaling-rc3.dev9.
New immutable wheel/image built and frozen; installed and structural checks pass.
Finite larger-history validation ended with a16actor latency failure. Not released or accepted. Main dev8 artifacts and scoped4actor/64vote3h validation
remain preserved and unchanged. Separate8actor/256vote dev8 finiteprofile
FAILED latency guardrail (p9991566.31ms);16actor profile withheld.

Root Mac installed-wheel component diagnostic attributed3.827of3.861seconds
for24recent+8record operations at2048rows to _records (65536recorddecodes).
This diagnostic used bulk-seeded isolated synthetic data and is not deployment
acceptance or exact Linux/end-to-end attribution.

Root design preserves whole-store current-row reading,integrity/schema/selector,
size/count/peractorcapacity,identity/options/privatepath/keyepoch and freshTTL
validation. A bounded4096entry/8MiB-accounted immutable decode cache may reuse
previous proofs only for an exactcompleteSQLrow+keyepoch match. No schema,
key-format/config migration,query narrowing,unverifiedinsert shortcuts or weaker
guardrails. Three disjoint workers completed cache,independent security tests,
and a repeatable plan-first component profiler. Root reviewed and integrated the selected files; all workers are completed.

Root reviewed cache,blackbox security tests and profiling tool.77combined focused
checks passed. Matched32operation/2048row Mac component diagnostic fell from
3.861s to0.121s (32x observed),while preserving32whole-store scans; recorddecode
calls fell65536to7. This is staged-source/component evidence only,not installed
Linux/end-to-end acceptance. Fullsource regressions619passed/3platformskips out622; optionalSDK8passed.
The component diagnostic alone does not establish deployment performance.
Fresh installed/structural/scan results are recorded below; capacity,standard3h
and separateAI3h evidence remain required. The failed8x256 profile is repeated
with the SAMEguardrails; do not count oldversion results,skips or knownattackgaps
as passes. Broader requirements remain open.

## Frozen candidate identity

Wheel SHA256: `d867b4b1172f8a43132b30494a500e823b11ba613f814b69ca20c091aee47e58`.
Package SHA256: `edd9e318907b5a19048a8436ebf8cea9a242bb8764650869a4ba496542a1b22f`.
Image `enkstein-guard:0.5.0rc3.dev9`, ID
`sha256:053e4a838f8fdbf130c23e25220656f1212c52a0f11665d3c502d312b9a905f5`.
Exact193input snapshot and both locks preserved underverification/0.5.0rc3.dev9.
Image package matches wheel; exactmusldeps match with buildpip absent. Inputs
are frozen. No code/test/tool/deployment/definition/lock/wheel/tag edits or
competing loads during validation. Source diagnostics remain separately labeled.

## Installed and structural checks — passed

Mac installedwheel619passed/3Linux-onlyskips; nativeLinux615passed/7Mac-onlyskips
out622each; optionalSDK8passed/0skips,Cisco remote mocked. Attacks56:42prevented,
7benign,7confirmedgaps,zero unexpectedfailures/skips. Root verified all4report
wheel/package/revision identities and exactLinuxdependencylock. Packaged mapping
2.3 --check matches20OWASProws/17selectedATLAS; no fullcategory acceptance.

Structural validation completed38boundary/20diskfull/40syntheticAI checks plus
short30sAI smoke, allpassed. Refreshed exactimage scan has no findings; root
review and explicit3report+scan preflight identity check passed. Failed8x256
profile repeat passed the unchanged latency guardrails:2048successfulwarmup,
960successfulmeasured,0errors,p95151.13ms,p99189.10ms,0drain,historyfull2048.
GuardRSS47.117MiB,egress38.156MiB. Exactwheel/image/dependency/revision and actual
savedconfiguration bindings passed,including identical raw8actorconfig hash to
the failed dev8 profile. This is finite60s synthetic local evidence,not a
productionSLO,realmodel evaluation or multi-hour result. The conditional16actor/
4096record profile completed all4096warmup+1920measured successfully,0errors,
fullhistory,correctbindings/counters/credentials and RSS57.547/39.988MiB, but
FAILED unchangedlatency gates:p953939.05ms,p994092.84ms,3.443sdrain. Thedriver
stopped;fullacceptance is WITHHELD and has never launched. All evidence is
preserved. Further implementation is isolated in staging/history-scan-rc3.dev10
with rootreview/promotion required. Inputs remain frozen. No larger-scale or
newcandidate endurance acceptance is claimed.
