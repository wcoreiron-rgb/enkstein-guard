# Third-party notices and provenance

Enkstein Guard is distributed under the MIT license in LICENSE. The original
Enkstein contributor copyright notice and policy-module attribution are retained.
The initial scanner import is recorded in docs/source-provenance.json, including
the public upstream repository, revision and imported file hashes. That record
describes the original import, not the current modified scanner hash.

This repository contains Guard source and compatibility adapters. It does not
redistribute optional vendor SDK implementations, vendor wheels, model weights,
container images or private operator policy packs. Installing dependencies
retrieves separate distributions subject to their own licenses and notices.

The locally validated dependency/compatibility points include:

| Distribution | Version | License recorded in installed distribution |
|---|---|---|
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| cffi | 2.1.1 | MIT-0 |
| pycparser | 3.11 | BSD-3-Clause |
| Microsoft agent-governance-toolkit-control-plane | 5.0.0, pinned upstream revision | MIT |
| NVIDIA nemoguardrails | 0.24.1 | Apache-2.0 |
| Cisco cisco-aidefense-sdk | 2.2.0 | Apache-2.0, from its distribution LICENSE |
| langgraph | 1.2.16 | MIT |

Transitive dependencies and any external services have additional terms; this
table does not relicense them. Optional requirements and the reused-engine
capability guide record exact pins and supported surfaces. Engine names and
trademarks identify compatibility only; no vendor endorsement is asserted.
