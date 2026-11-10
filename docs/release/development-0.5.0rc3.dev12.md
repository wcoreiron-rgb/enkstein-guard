# Development validation — 0.5.0rc3.dev12

Scoped single-host local validation is complete. This is an unreleased candidate,
not production/full-product acceptance or full OWASP/ATLAS protection. The broader
original requirements and seven confirmed attack gaps remain open.

## Implemented change

The CLI configures optional local AGT5.0.0 policy engines with exact trusted
tenant/principal/agent/route bindings and bounded typed JSON conditions. These
required controls narrow existing grants; they cannot choose endpoints or
credentials, rewrite payloads or override deterministic/privacy/authorization
denials. Missing/incompatible configured SDKs reject startup; default configs
do not import the SDK. Root also corrected mutable normalized-configuration
aliases affecting grants, approver tenant authority and declared-context privacy.

Only23reviewed files were selected from the completed independent staged packets.
All original staged checks and failed probes/results are preserved. The pinned
pureAGT wheel came from verified official commit86db4607dcb67e5dbe48b885bc535f77be5e244d;
two fixed-epoch builds matched, and final installedSDK35files match that wheel.

## Immutable identities

WheelSHA25669305575c243154de96d9e712b0d4c83c5f4c17cffdb3debb5d7374a05620f99.
GuardpackageSHA2566d51bf34034463fffd8a65eb0cb35809220c0441ad22d59bf8c3192b23218352.
Imageenkstein-guard:0.5.0rc3.dev12 ID
sha256:e2eaa5b2dede859a6ca4367e8444232f546b25763b8f8df3c44a62b962ab34e9.
Exact206input snapshot,both6pinlocks,supplementalrequirements and all5revision
digests remain unchanged. All prior artifacts/failedruns were preserved.

## Executed verification

InstalledMac663passed/3Linux-onlyskips; nativeLinux659passed/7Mac-onlyskips out666.
OptionalSDK21passed/0skips; Cisco mocked. The first optional runner lacked a core
test utility path; its14pass/1importerror result is preserved. Corrected-I
invocation adds onlytests utilitypath, never src/PYTHONPATH, and all21passed.
Installed reports match exactwheel/package/revision; mapping--check passes.
Attack56:42prevented/7benign/7confirmedgaps,0unexpectedfailure/error/skip.

Sequential physicalboundary38/38,diskfull20/20,syntheticAI40/40 and AGT56/56
passed, with everyverdict/actualconfiguration/identity reviewed. AGTphysical
proof is22requests across2tenants/2engines:2allowed targetcalls,20denied.
The recordedexactimage scan at2026-11-08T14:23:29Z had0findings,unfixednotignored;
raw/provenance,orderedfilesystemlayers/runtimeconfig and packageinventory bound.
Short30sAIsmoke passed onlysmoke; fullacceptance remainedfalse. Samefinite8/16
actorhistoryprofiles passed unchangedgates,p99155.09/903.37ms,all960/1920measured
successful,0errors/drain. These are60sprofiles,not16actorendurance.

Fullcapacity passed5/5:12000sustainedsuccessful,0nonok/duplicateexecution,
p9968.37ms;restart3.8s,all56lostresponses resubmitted,0duplicateexecution.
Standard10800ssoak passed8/8:86400successful,0nonok/duplicateexecution/retention
failures,p9968.06ms,720windows. Separate syntheticAI10800s passed8/8:256warmup
plus86400successfulmeasured,0errors,actual10802.65s,4actors/2tenants/64votes each,
182samples,p95ceiling59ms/p99ceiling126ms. Boundedhistory/counters/credential
separation/audit/archives/retention verified. AIcounters do not prove per-marker
duplicates; standardP04 is separate no-replay proof.

## Root closure and limits

The controller completed2026-11-08T20:57:21Z. Root subsequently reviewed every
loadverdict, actualparticipation/counts/histograms/counters/configurations and
identities. Freshimage+SDKbyteprobes and independentexplicit7productionreports
plus scan,bothlocks/all5revisiondigests recheck pass. closure.json and final
rootreviews/recheck retain proof. No acceptanceprocess remains. DedicatedVM is
stopped with0ownedrunningcontainers beforestop; globalDockercontextdefault.
The earlier stale report/checkpoint are preserved separately.

Standardlongprofiles have optionalAI OFF; localAGT rules are OFF in standard and
AIhistorylongprofiles. The AGTproof is shortphysicalactivation, not AGTcapacity/
endurance. These are syntheticsinglehostprofiles, not real-modelrobustness,
providerSLA,fullstorage-limit or universalframeworkprotection. Sevenattackgaps,
broaderplatform/integrationrequirements,realnonproductionworkflows,HA/distributed
state,streaming/multimodal,publication/signing/repository setup and independent
humanreview remain open. Nothing was published.
