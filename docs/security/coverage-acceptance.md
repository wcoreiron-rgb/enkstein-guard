# Coverage acceptance matrix

> Historical planning matrix, superseded. The executed, versioned mapping for
> 0.5.0rc1 is `src/enkstein_guard/coverage.json` (with `atlas-evidence.json`);
> status is in [cli-production-readiness.md](../cli-production-readiness.md).

Planning evidence only. No category is validated by this package yet. Names/IDs reference OWASP 2026; see the packaged manifest for source/version caveats. The previous 2025 checklist remains historical only.

| Requirement | Control responsibility | Acceptance scenario (planned) | Status |
|---|---|---|---|
| LLM01:2026 Prompt Injection | authorization, trust boundaries | AC-LLM-01: indirect content cannot expand tool permissions | planned |
| LLM02:2026 Sensitive Information Disclosure | vault, DLP | AC-LLM-02: secrets absent from model capture and unauthorized sinks | planned |
| LLM03:2026 Excessive Agency | authorization, scoped credentials | AC-LLM-03: unauthorized tool and destination denied | planned |
| LLM04:2026 Supply Chain | admission, integrity | AC-LLM-04: unapproved tool or dependency denied before loading | planned |
| LLM05:2026 Data and Model Poisoning | provenance, memory | AC-LLM-05: poisoned source quarantined and rollback works | planned |
| LLM06:2026 Unbounded Consumption | shared budgets | AC-LLM-06: delegation cannot evade aggregate limits | planned |
| LLM07:2026 Misinformation | grounding, review | AC-LLM-07: unsupported citation flagged and high-risk action held | planned |
| LLM08:2026 Hidden Context Exposure | context minimization, output inspection | AC-LLM-08: hidden context extraction blocked in declared scenarios | planned |
| LLM09:2026 Vector and Embedding Weaknesses | retrieval ACL | AC-LLM-09: cross-tenant document retrieval denied | planned |
| LLM10:2026 Improper Output Handling | sink validation, isolation | AC-LLM-10: generated SQL/shell cannot cause unauthorized side effect | planned |
| ASI01:2026 Agent Goal Hijack | task authority | AC-ASI-01: retrieved instructions cannot redefine authorized task | planned |
| ASI02:2026 Tool Misuse | tool policy | AC-ASI-02: allowed tool used against forbidden resource denied | planned |
| ASI03:2026 Identity and Privilege Abuse | identity, delegation | AC-ASI-03: forged identity and delegated privilege escalation denied | planned |
| ASI04:2026 Agentic Supply Chain Vulnerabilities | admission | AC-ASI-04: malicious MCP/skill blocked before use | planned |
| ASI05:2026 Unexpected Code Execution | isolation | AC-ASI-05: forbidden process/filesystem/network access denied | planned |
| ASI06:2026 Memory and Context Poisoning | memory policy | AC-ASI-06: unauthorized write denied and provenance retained | planned |
| ASI07:2026 Insecure Inter-Agent Communication | message security | AC-ASI-07: forgery, replay and unauthorized disclosure denied | planned |
| ASI08:2026 Cascading Failures | budgets, cancellation | AC-ASI-08: descendant failures cannot exhaust unbounded resources | planned |
| ASI09:2026 Human-Agent Trust Exploitation | bound approvals | AC-ASI-09: substituted and replayed approval rejected | planned |
| ASI10:2026 Rogue Agents | containment | AC-ASI-10: independent termination and credential revocation observed | planned |

MITRE ATLAS technique selection is pending. No ATLAS coverage percentage is reported.

The manifest is `src/enkstein_guard/coverage.json`; acceptance IDs identify future tests, not tests already executed. Every release evidence record must include source revision, configuration, deployment scope, observed side effects, audit correlation and residual risk.

Official sources: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ and https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/.
