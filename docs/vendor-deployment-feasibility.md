# Vendor SDK deployment dependency feasibility

## Decision boundary

The currently installed optional SDK environment is **not evidence that the
selected vendor dependencies are deployable in the production core image**.
The installed root metadata permits Python 3.12, but the production profile is
Alpine Linux/musl on ARM64 while the inspected environment is macOS ARM64 on
CPython 3.11.14. Nineteen dependencies in the selected-adapter closure are
installed as native macOS wheels. No Linux/musl ARM64 package resolution,
download, build, install, import, or runtime test was performed.

This document complements, and does not repeat, the invocation contract in
[`reused-engine-capabilities.md`](reused-engine-capabilities.md). Package
installation still does not activate a vendor control. In particular, the
supported CLI does not currently wire vendor activation.

## Evidence and method

The reproducible evidence is
[`verification/vendor-dependency-inventory/inventory.json`](../verification/0.5.0rc3.dev8/vendor-dependency-inventory/inventory.json).
The pre-correction review snapshot is retained as
`verification/vendor-dependency-inventory/inventory.superseded.json`; it is
superseded and must not be used for deployment conclusions.
It was produced in the isolated development stage from the actual `.venv-engines`
interpreter. It describes installed SDK metadata, not an installed dev8 candidate.
The recorded staging invocation was:

```text
<guard-checkout>/.venv-engines/bin/python \
  tools/inspect_vendor_dependencies.py \
  --output verification/vendor-dependency-inventory/inventory.json \
  --strict-roots
```

The inventory uses `importlib.metadata` plus a bounded stdlib PEP 508
requirement/marker parser. It does not import
AGT, NeMo, Cisco, or any other SDK module. It records installed versions,
`Requires-Python`, every `Requires-Dist` expression and marker, active transitive
closures, license metadata, sanitized public origins, `direct_url.json`, and
installed `WHEEL` tags. Unsupported marker expressions are recorded explicitly
and are never treated as active or satisfied. PEP 440 version satisfaction uses
`packaging` only when it is already installed in the inspected environment; the
tool imports and runs without it and otherwise records version satisfaction as
unknown. URL user information, queries, fragments, local paths,
and non-public origins are not retained. The evidence records the exact tool
arguments and runtime, and states that no network, resolver, or installer ran.
This redaction also covers URLs embedded in raw `Requires-Dist` records; direct
URL requirements are never treated as installed-version satisfaction evidence.

Missing optional SDKs are normal in the core environment: discovery still
writes a complete missing-root inventory and exits successfully by default.
`--strict-roots` was used for this optional-environment evidence so an absent or
wrong-version expected root would make that verification invocation nonzero.

The deployment comparison is the supplied production profile: CPython 3.12 on
Alpine Linux/musl ARM64, with only Guard's core
`cryptography>=50.0.2,<51` dependency present. Target-marker projection changes
the installed metadata environment to Linux/aarch64/Python 3.12; it is not a
target package availability or installation test.

## Installed root facts

| Distribution | Role and installed evidence | Python and wheel metadata | License metadata | Deployment interpretation |
|---|---|---|---|---|
| `agent-governance-toolkit-control-plane==5.0.0` | Selected AGT adapter distribution. Installed `direct_url.json` identifies the GitHub archive for immutable commit `86db4607dcb67e5dbe48b885bc535f77be5e244d`, the control-plane subdirectory, and SHA-256 `d188680c60a6d6be25799fa8b0236e869c45c0a978650b9aabba254bd646492c`. | `>=3.8`; installed root tag `py3-none-any`. Its nine declared dependencies are all gated behind `dev`, `hf`, or `sql` extras, so the base active closure contains only this distribution. | `MIT` and `LICENSE` are present in installed metadata. | Metadata admits Python 3.12. The installed pure wheel was built from the pinned source archive; target source-build/install success and target artifact availability remain untested. |
| `agent_governance_toolkit==4.1.0` | Distinct umbrella distribution retained for comparison only. It is not the selected control-plane adapter distribution and is not included in the selected-adapter deployment projection. Its active installed closure has eight packages. | `>=3.9`; installed root tag `py3-none-any`. Its closure includes native `pydantic-core` and `pyyaml` macOS wheels. | `MIT` and `LICENSE` are present in installed metadata. | Metadata admits Python 3.12, but this does not make the umbrella interchangeable with or required by the selected control-plane package. |
| `nemoguardrails==0.24.1` | Selected NeMo adapter distribution. Its active installed closure has 64 packages. | `>=3.10,<3.14`; installed root tag `py3-none-any`. The closure contains 19 native-wheel distributions in this environment. | `Apache-2.0` expression and three license-file entries are present. | The root range admits Python 3.12. Installed macOS artifacts cannot establish Linux/musl ARM64 availability or behavior. |
| `cisco-aidefense-sdk==2.2.0` | Selected Cisco adapter distribution. Its active installed closure has 20 packages. | `>=3.9,<4.0`; installed root tag `py3-none-any`. Seven closure dependencies have native macOS tags. | No license expression, legacy license value, license classifier, or license-file entry is present in the installed distribution metadata. | The root range admits Python 3.12. License status requires a separate primary-source review. Package feasibility does not establish Cisco service, credential, tenant, or live inspection availability. |

All four exact root versions were present exactly once. The installed union had
no active missing dependencies and no normalized-name duplicate ambiguity.
Public origin and license fields above report only what the installed metadata
contains; missing fields are unknown, not negative vendor claims.

## Target projection and factual blockers

The Linux/aarch64/Python 3.12 marker projection for the three selected adapter
roots contains 67 installed distribution records and 561 declared dependency
edges (including inactive extras/markers retained for audit). None of the 67 is
part of the stated core dependency set, so the current core image would need all
67 selected-adapter distributions or reviewed replacements before these SDKs
could be installed as represented. The current core image is therefore not
vendor-SDK deployment-ready as-is.

The bounded evaluator left no marker unresolved in this installed metadata.
For target-active edges, the local environment has no missing distribution and
no installed version that fails its declared constraint. This is internal
closure consistency only; it does not resolve or obtain target artifacts.

No installed selected-closure version has a `Requires-Python` field that
explicitly excludes 3.12. `flatbuffers==25.12.19` and
`typing-inspect==0.9.0` declare no `Requires-Python`, so their Python 3.12
compatibility is not established by metadata. A compatible root range also does
not prove that every dependency has an obtainable target artifact.

The following 19 selected-closure distributions have native installed wheel
tags: `aiohttp`, `charset-normalizer`, `frozenlist`, `hf-xet`, `markupsafe`,
`mmh3`, `multidict`, `numpy`, `onnxruntime`, `pillow`, `propcache`, `protobuf`,
`py-rust-stemmers`, `pydantic-core`, `pyyaml`, `rpds-py`, `tokenizers`,
`wcwidth`, and `yarl`. Their exact evidence tags are macOS ARM64 or macOS
universal2 tags (some use CPython ABI3). Those installed artifacts are not
Linux/musl ARM64 wheels and cannot be copied into the target as compatibility
evidence. This is an artifact blocker for reusing the local environment, not a
claim that a musllinux wheel or source build does not exist.

Optional installed-wheel contract tests remain useful API behavior evidence,
but they ran on the optional macOS environment. They do not prove target image
resolution, native compilation, shared-library availability, importability, or
runtime behavior. The inventory likewise does not establish service-backed
Cisco operation or CLI vendor activation.

## Remaining target probes

Promotion needs separate, reviewed target evidence:

1. Resolve the selected root versions for CPython 3.12, Linux/musl, ARM64 from
   an approved package source without relaxing pins; record artifact filenames,
   hashes, source fallbacks, and licenses. Availability was not queried here.
2. Confirm whether each of the 19 native dependencies has an appropriate target
   wheel or a reproducible source-build path and required Alpine build/runtime
   libraries. A manylinux/glibc artifact alone is not musl evidence.
3. Build and install the selected closure in the actual target image, then run
   focused import and adapter contract tests there. The present work did not run
   a VM, Docker, or target container.
4. Re-fetch or otherwise supply the AGT control-plane archive through the
   approved build channel, verify the recorded SHA-256 and commit/subdirectory,
   and prove its target build. The local source-built pure wheel is not that
   proof.
5. Complete a primary-source license review, especially for Cisco where the
   installed metadata has no license fields, and review the recorded transitive
   license metadata rather than treating it as legal approval.

Until those probes pass, the exact status is: installed metadata/API evidence
exists on macOS Python 3.11; target Python ranges show no explicit root conflict;
the core image lacks the optional closure; and target Alpine/musl ARM64 artifact
availability and runtime viability are untested.
