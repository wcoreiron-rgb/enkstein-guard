# One Enkstein Guard product — completion plan

The product is one reusable security enforcement layer for AI-enabled apps and
agentic solutions. Developers install or deploy Guard, configure trusted routes
and identities, and integrate their application through its SDK/service. The
same policy authority governs supported model, data, tool, delegation and action
paths. Operators use one CLI. Optional inspection engines sit behind this
integration and do not require developers to assemble separate security products.

The target is broad; the current evidence is narrower. Dev12 remains the
preserved, unreleased, locally validated baseline. The original requirements
register and confirmed attack gaps remain open.

## Delivery sequence and evidence

| Work | Concrete acceptance | Current position |
|---|---|---|
| Unified developer integration | One documented client for configured routes; authenticated service connection; detached exact request intent; explicit denied, approval, completed and uncertain outcomes; no automatic uncertain retries; executed local integration and security tests | Dev13 isolated source implemented/root reviewed: 722 passed, 3 Linux-only checks skipped; installed/deployment acceptance remains open |
| Complete CLI configuration | Configure supported identities, vault, policies, routes and optional engines through the same operator workflow; reject incompatible or ambiguous configuration; demonstrate safe failure and rollback | Existing CLI/configuration capabilities; broader engine and installation experience open |
| Supported mediation boundaries | Declare each supported framework/host/connector and every protected execution path; test direct-call and egress bypass attempts, agent delegation, tenant isolation and permissions | Configured service/runtime/SDK and selected LangGraph paths; broader adapters and remote messaging open |
| Applicable threat coverage | Maintain versioned OWASP LLM/Agentic and selected ATLAS mappings; execute legitimate and adversarial cases; remediate applicable confirmed gaps and record residual risk | Seven confirmed gap scenarios remain; no full-category acceptance |
| Privacy and secrets | Evaluate undeclared and paraphrased confidential context, retrieval, credential exposure and key lifecycle; extend protection to declared streaming/multimodal support | Scoped text/JSON controls exist; wider detection and lifecycle remain open |
| Supported deployments | Reproducible installation, least-privilege isolation, upgrade/recovery and escape tests for each declared platform/cloud; publish an evidence-based support matrix | Linux ARM64 local evidence and macOS component tests; broader platforms/distributed state open |
| Real workflows and operations | Authorized nonproduction business/model/provider integrations, useful vendor engines and realistic recovery/performance tests with exact artifacts/configurations | Synthetic/local proof exists; real-model robustness, wider engines, live workflows and AGT endurance remain open |
| Release readiness | Separate repository/CI, publisher/key custody, signing, independent human review, remediations and explicitly authorized publication | External inputs and further implementation required |

Each changed candidate receives a new version, immutable inputs and fresh
installed-wheel/deployment evidence. Source tests do not inherit dev12's load or
security acceptance. A new SDK alone does not intercept arbitrary processes;
supported applications must route protected work through the enforced boundary.

## Fixed security architecture

Trusted configuration chooses endpoints, identities, grants and credentials.
Deterministic checks remain authoritative. AI may narrow permission or require
an explicitly permitted approval bound to the exact request. It cannot widen
grants, override tenant/clearance/privacy denial or rewrite executed payloads.
Trusted broker context stays local and unchanged; models see redacted inspection
copies. Privacy, history and internal boundary failures deny. Recovery preserves
request identity and reports uncertainty without blindly repeating side effects.

This plan sequences the original purpose; it does not replace or close the
[original requirements register](original-requirements-roadmap.md). The product purpose and open requirements define acceptance.
