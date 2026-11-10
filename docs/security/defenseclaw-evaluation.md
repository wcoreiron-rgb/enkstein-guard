# DefenseClaw evaluation against a concrete missing capability

Date: 2026-10-28. Evaluated against the open gap **"a correctly pinned
malicious component is not classified"** (LLM04/ASI04). Hash pinning and the
declared-capability check are Guard's only component controls.

## Candidates

| | DefenseClaw (`cisco-ai-defense/defenseclaw`) | Skill Scanner (`cisco-ai-skill-scanner`) |
|---|---|---|
| What it is | Security governance platform: Python operator CLI, Go gateway, connector hooks, policy, scanners, observability exporters | Scanner for agent skills: YAML/YARA signatures, bytecode, shell-pipeline taint, AST behavioural dataflow; optional LLM, VirusTotal and AI Defense analyzers |
| License | Apache-2.0 (Cisco, 2026) | Apache-2.0 (Cisco, 2026) |
| Runtime | Python ≥3.10,<3.14, Go 1.26, Node.js 24 components; installer script | Python ≥3.11,<3.15 (2.3.2); 102 installed distributions incl. `yara-x` |
| Service dependencies | Its own gateway and policy plane | None for the offline analyzers; API keys and network for LLM/VirusTotal/AI Defense (possible paid usage) |
| Overlap with Guard | Gateway, policy, audit and connector hooks duplicate Guard's executor | Behavioural analysis overlaps Guard's capability check but goes further (dataflow) |

## Executed comparison

Five synthetic fixtures (`tests_adversarial/data/component-fixtures/`), offline
analyzers only (`--use-behavioral`), compared with Guard's capability check
using minimal declarations. Evidence:
`verification/cli-v1/component-scanner-evaluation.json`.

| Fixture | Skill Scanner 2.3.2 | Guard capability check |
|---|---|---|
| benign | safe (INFO only) | nothing detected |
| raw socket exfiltration | CRITICAL data exfiltration | `network` (denied unless declared) |
| declared network, forwards payload and environment to a second host | CRITICAL data exfiltration | `network`, `environment` (denied only because `environment` was undeclared) |
| `__import__(base64(...))` obfuscated socket | **not flagged** (INFO only) | `dynamic_code` (denied unless declared) |
| returns environment secrets in output | **not flagged** | `environment` (denied unless declared) |

The tools are complementary: the scanner catches misuse of a declared
capability that Guard's check cannot see; Guard's conservative capability
inventory catches obfuscation and environment access the scanner missed.
Neither is malware classification; five fixtures are not a detection rate.

## Decision

- **DefenseClaw platform: not adopted.** Its gateway and policy plane would add
  a second authoritative executor on the same boundary, a Go/Node toolchain and
  a separate installation lifecycle, which conflicts with the single-executor
  design and the CLI-only v1 scope.
- **Skill Scanner: recommended as an optional, offline pre-admission step**
  run by the operator in the release pipeline for Python tool components before
  their hash is pinned, with results stored beside the pin. Not a Guard runtime
  dependency (dependency footprint, musl wheel availability for `yara-x` not
  validated, optional analyzers need credentials). Not executed in Guard's
  request path.
- The LLM04/ASI04 gap stays **open**: a pinned component that misuses capabilities
  it legitimately declares, and is not caught by an external scanner, still runs.
  Runtime containment (network-less Guard, egress allowlist, read-only
  containers) remains the enforcing control.

Sources: https://github.com/cisco-ai-defense/defenseclaw (README, LICENSE),
https://github.com/cisco-ai-defense/skill-scanner (README), PyPI
`cisco-ai-skill-scanner` 2.3.2 metadata.
