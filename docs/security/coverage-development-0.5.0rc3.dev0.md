# OWASP development coverage — 0.5.0rc3.dev0

Generated from the packaged pinned-framework mapping and executed local attack outcomes.
All rows remain scoped evidence; no category is fully accepted. Scenario counts overlap across categories.

| Requirement | Prevented scenarios | Benign allowed | Confirmed gaps | Full category accepted |
|---|---:|---:|---:|---|
| LLM01:2026 — Prompt Injection | 2 | 1 | 0 | No |
| LLM02:2026 — Sensitive Information Disclosure | 9 | 1 | 0 | No |
| LLM03:2026 — Excessive Agency | 1 | 1 | 0 | No |
| LLM04:2026 — Supply Chain | 2 | 0 | 1 | No |
| LLM05:2026 — Data and Model Poisoning | 0 | 0 | 1 | No |
| LLM06:2026 — Unbounded Consumption | 3 | 0 | 1 | No |
| LLM07:2026 — Misinformation | 1 | 0 | 1 | No |
| LLM08:2026 — Hidden Context Exposure | 2 | 0 | 2 | No |
| LLM09:2026 — Vector and Embedding Weaknesses | 2 | 0 | 1 | No |
| LLM10:2026 — Improper Output Handling | 2 | 0 | 0 | No |
| ASI01:2026 — Agent Goal Hijack | 2 | 1 | 0 | No |
| ASI02:2026 — Tool Misuse | 2 | 1 | 0 | No |
| ASI03:2026 — Identity and Privilege Abuse | 6 | 0 | 0 | No |
| ASI04:2026 — Agentic Supply Chain Vulnerabilities | 2 | 0 | 1 | No |
| ASI05:2026 — Unexpected Code Execution | 2 | 0 | 0 | No |
| ASI06:2026 — Memory and Context Poisoning | 2 | 0 | 0 | No |
| ASI07:2026 — Insecure Inter-Agent Communication | 5 | 1 | 0 | No |
| ASI08:2026 — Cascading Failures | 3 | 0 | 1 | No |
| ASI09:2026 — Human-Agent Trust Exploitation | 2 | 0 | 0 | No |
| ASI10:2026 — Rogue Agents | 2 | 0 | 0 | No |

Whole suite: 42 distinct scenarios — 31 prevented in scenario, 4 benign allowed, 7 confirmed gaps.
The inventory control prevents the tested omitted-host configuration; operator account/alias truth remains an assumption.
The existing suite does not establish general model robustness, semantic grounding, model/training integrity or universal framework protection.

See [development validation](../release/development-0.5.0rc3.dev0.md), [original requirements](../original-requirements-roadmap.md), and the raw versioned reports under `verification/0.5.0rc3.dev0/`.
