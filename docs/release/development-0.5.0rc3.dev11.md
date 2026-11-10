# Development validation — 0.5.0rc3.dev11 frozen

Unreleased candidate; no production/full-product acceptance. Root integrated the
reviewed scalar SQLite preflight optimization from staging/history-scan-rc3.dev10.
The previous dev9 finite8x256 profile passed unchanged latency gates,p99189.10ms,
while16x256 failedp953939.05ms/p994092.84ms despite1920successfulmeasured and
full4096history. That failure and all oldartifacts remain preserved. Fullcapacity
and both three-hour profiles were never launched for dev9.

## Change and root review

COUNT(*)/MAX(CASE) now returns one count/invalid-size scalar before the unchanged
fullsixcolumn ciphertext fetch inside the existing transaction. Explicit NULL,
shape,type,size/globalcount checks preserve fail-closed behavior. Whole-store
authentication/exactrow+keyepoch cache,bounds,identity/path/key/TTL/peractor and
rotation/stalehandle checks remain. No querynarrowing,skippedvalidation,largercache,
weakerthresholds,schema/config/keyformat change or presumed-valid insertion.
Root reviewed SQLdiff and independent blackbox nullabletable/foreign/expired/
overcount/oversize/warmcache-corruption tests. Two workers completed/froze their
implementation and security slices. Profilerworker stopped at a usage limit;
root reclaimed the stopped packet,reviewed/preserved its partialscript and
finished the diagnostic. No claim that a limited worker continued.

Stagedsource633:630pass/3platformskips;optional8pass,Cisco mocked. Sourceattacks
56:42prevented/7benign/7confirmedgaps. NativeLinuxsourcebootstrap fordev11:626pass/
7Mac-onlyskips. Matched4096row/32op Maccomponent:singlethread0.2517→0.2133s,
16thread0.1950→0.1621s. Both fetch131072ciphertextrows;returnedlengthmetadata
rows131072→32. Component only,not deployedLinuxcapacity/SLO/endurance. The first
multithreadprofilingAPI failure and one sourceattack interpreterimportfailure
are preserved separately; corrected runs completed.

## Preserved build-order failure

Root selected an interpreter without PyYAML for mappinggeneration,which failed,
but the dev10 build proceeded. That unaccepted wheel,image,locks and source
snapshot are preserved with rejected-build-identity.json; no installed or
production checks started. Freshdev11 regenerated and verified mapping BEFORE
packaging using the existing YAML-enabled environment. No oldartifact overwritten.

## Frozen identity

Wheel SHA256 `f03527ee20b19aaa9589b100c77f19edd98490c3fde4c07471c5b6e6dabaa923`.
Package SHA256 `667f7ae5620e93d6c05630014e863edaa6261f9d170ee28ba4ae4617b8c15380`.
Image `enkstein-guard:0.5.0rc3.dev11`, ID
`sha256:3c1686b52fe787d8ab2cf39ab7d245cd8dc418fe13618e5c669a80678d993e44`.
Exact195input snapshot,bothlocks and supplementaloptionalrequirements preserved
underverification/0.5.0rc3.dev11. Imagepackage matcheswheel;exactmusllock matches
withbuildpip absent. Source/tests/tools/deployment/definitions/locks/wheel/tag
are frozen. No edits/retags/competingloads during validation.

## Installed candidate checks — passed

Mac630passed/3Linux-onlyskips;nativeLinux626passed/7Mac-onlyskips out633each.
OptionalSDK8passed/0skips,Cisco mocked. Attacks56:42prevented/7benign/7confirmed
gaps,zero unexpectedfailure/error/skip. Root verified all4exactwheel/package/
revision reports and exactLinuxdependencylock. Mapping2.3 --check matches20OWASP
rows/17selectedATLAS. No skipped/gap is a pass; no fullcategoryacceptance.

## Active and remaining validation

Structural38boundary/20diskfull/40syntheticAI plus separate30sAI smoke passed.
Smoke256warm+240measured is explicitly notfullacceptance. Refreshed exactimage
scan has0findings at2026-11-08T03:52:41.131518+00:00;unfixednotignored.
Root everyverdict/actualsavedconfig/identity review and explicit3report+scan
preflight passed. Optionalmetadata identity review passed sameSDKroots/versions
and unchangeddependencyinventory excludingGuard vsdev9;this is macOSPython3.11
metadata/mocked SDKs,not hashlockedmuslclosure/livevendor/CLIactivation.

Both finiteprofiles passed unchanged1000ms p95/2000ms p99 and memory gates:

|Actors / votes each|Warmup / measured successful|p95 / p99 ms|Guard / egress peak RSS MiB|
|---|---|---|---|
|8 /256|2048 /960|142.21 /194.23|48.871 /38.000|
|16 /256|4096 /1920|793.67 /977.66|56.016 /40.016|

Zero requesterrors/drain,full2048/4096history before/after,exactcounter/credential
separation and identity/savedconfig checks passed. 8actorrawconfig equals failed
dev8;16actorrawconfig equals faileddev9(p994092.84ms). Root independentstrong
recheck passed; larger-history-root-review.json preserves exactreporthashes.
These are60s local synthetic finiteprofiles,not productionSLOs,realmodelrobustness
or16actor endurance. They do not erase priorfailures or broader requirements.

Fullcapacity→standard10800ssoak→separateAI10800sendurance driver55839 started
2026-11-08T04:01:13Z. Full capacity and standardsoak completed; separateAIendurance is active
since07:19:25Z (child19048). Its prerequisites,exclusive
lock and before/after frozenidentity checks passed atlaunch. Root finalverdict/
configuration/identity review and explicit6report+scan recheck remain required.
Standard load hasAIoff; separateAIendurance uses4actors/64votes each. No fresh
three-hour/localclosure or fullproduct/production acceptance is claimed yet.
Sevenattackgaps,broaderoriginalrequirements,realmodelrobustness,externalrelease
gates and independenthumanreview remain open.


## Full capacity — root verified

All5targets passed. P01:12000successful sustained requests,0non-ok/duplicate
markers,p5012.57ms/p9527.39ms/p9960.10ms,GuardRSS40.7MiB/egress37.3MiB.
Saturation4876ok with explicitratelimits and equalperagent1219;fairnesslight
100%ok,p9528.19ms. Forcedrestart3.9s,all55lostresponses resubmitted
(52ok/3outcome_unknown_no_replay),0duplicateexecution. Forbiddenproviderfields
denied with0upstreamdispatch. Allphaseparticipants exited0 withcomplete
summaries. Root reviewed everytarget,measurement,actualsavedconfiguration,
wheel/image/package/dependency/revision/definition and explicit4report+scan
snapshot. capacity-root-review.json and capacity-snapshot-root.json preserve
proof. Standard capacity/soak have optionalAIoff; these results do not measure
AIenabledcapacity. Standard3hsoak passed and rootreview is recorded below. SeparateAI3h
and final6report identity/rootreview remain pending. No fullproduct/production
acceptance or closure of the sevenattackgaps is claimed.


## Standard three-hour soak — root verified

Full10800-second profile passed8/8:86400successful,0non-ok/duplicateexecution/
retentionfailures,p5014.06ms/p9528.34ms/p9973.41ms,maxwindowp99252.73ms.
GuardRSS41.9MiB(firsthour41.2,last41.9),egress36.8MiB,FDmax14,threads5;active
state54.47MB,archive223.10MB/2582.2bytespertrackedrequest. All4agents exited0
with21600calls each;720windows. Scheduledretention and200dedup/40expiredID
probes passed. Auditwitharchives and outcome57748archived+28652active records
verified. Externalmonotoniccheckpoint matching was not part of this local run.

Root reviewed everyverdict and numericmeasurement,fullparticipation,exact
wheel/image/package/dependencies/revision/targetdefinitions/actualsavedconfig.
Explicit5requiredreport+scan rootrecheck passed;soak-root-review.json and
standard-soak-snapshot-root.json preserve proof. This profile has optionalAIoff.
SeparateAI10800-second endurance started07:19:25UTC and remainsactive/unaccepted;
its fullverdicts and final6report+scan rootreview remain required. No elapsed
time establishes completion. Broaderrequirements,7attackgaps,realmodelrobustness,
independenthumanreview and externalreleasegates remain open.


## Scoped local closure — November 8, 2026

The full synthetic AI-enabled10800-second endurance passed8/8:256successful
warmup and86400successfulmeasured,0errors,4actors/2tenants/64votes each.
p95ceiling51ms,p99ceiling115ms,maxwindowp99455.059ms;182complete samples.
GuardRSS42.219MiB,egress37.590MiB,FD14,threads11,active state54194922bytes.
History stayedfull/bounded256. Exactinspector/business counts,2+2disjoint
credentialhash sets,retention0failures,auditwitharchives and outcome57748archived
+28908active records verified. Syntheticcounters do not prove per-marker
duplicateexecution; standardP04 is separate no-replay evidence.

Driver completed10:20:21UTC. Root reviewed everyverdict,actualcounts/histograms,
configuration,targets and exactwheel/image/package/dependency/revision binding;
all195frozeninputs unchanged. A fresh exactimageprobe matches the wheel and
musllock. Finaldriver snapshot AND independentroot explicitrecheck pass all6
requiredproductionreports+scan,bothlocks/all5revisiondigests. AIprogress copied.
ai-endurance-root-review.json,final-snapshot-recheck.json andclosure.json retain
proof. No requiredlocal acceptancephase remains; do not reruncompleteddrivers.

Owned runningcontainers0 and allvalidationprocesses exited. DedicatedColima
enkstein-rc2 stoppedexit0 at10:44:10UTC; globalDockercontextdefault verified.
Priorimages/wheels/locks/reports/failures/old evidencevolumes remain preserved.
This closes the singlehostsynthetic localprofiles only,not production/fullproduct
release,realmodelrobustness,16actorendurance or universalOWASP/ATLAS protection.
Sevenattackgaps,broaderoriginalrequirements,publisheridentity/keycustody,exact
separaterepository,nonproductioncredentials and independenthumanreview stayopen.
