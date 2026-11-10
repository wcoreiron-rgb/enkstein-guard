# Product requirements and remaining work

Enkstein Guard targets one reusable CLI-first security layer for supported
AI-enabled applications and agents. Model, data, tool, delegation and action
paths share trusted identities, privacy, policy, approval and recovery controls.
Local PCs and cloud runtimes are targets; platform support is evidence-specific.

The public development preview is based on dev12, whose scoped local validation
is recorded in [the development report](release/development-0.5.0rc3.dev12.md).
This is not full product, production, OWASP or ATLAS acceptance. A newer
application-client source stage exists separately and is not included in this
preview. Development-agent choices are not product dependencies.

## Remaining original scope — do not silently defer as completed

| Requirement | Existing position | Remaining |
|---|---|---|
| Single CLI installation/deployment | Local package and Linux deployment | Reproducible supported installers, distribution and publisher identity |
| Local PC and cloud coverage | Linux ARM64 tested; macOS component tests | Linux AMD64, Windows and cloud-specific isolation/escape acceptance; supported deployment matrix |
| Human/agent/orchestration integration | CLI, service, SDK and LangGraph paths | Additional supported integrations; authenticated remote messaging; explicit interception boundaries |
| Broad traffic/action mediation | Configured runtime plus independent egress proxy | Framework/host adapters and deployment bypass testing; no claim pip alone intercepts all processes |
| Private AI vault | Text/JSON pattern and declared-data protection | Additional detection evaluation, paraphrase/undeclared-context controls, streaming/multimodal paths, other store key lifecycles; model tokenization defaults implemented in rc3.dev1 |
| Tenant and agent isolation | Supported peer-bound single host; unreleased durable local approvals | Multi-host identity/state and deployment-specific controls; explicit single-host SDK budget/workflow recovery implemented in rc3.dev1 |
| Harmful-action prevention/business continuity | Policies, tasks, approvals, quotas, recovery and measured capacity | Real nonproduction business workflows and downstream authorization; expanded endurance evidence |
| OWASP LLM + Agentic Top 10 | Scoped control/scenario mappings | Close applicable gaps and expand adversarial/benign acceptance; no full-category claims yet |
| MITRE ATLAS | Selected mappings | Versioned applicable-technique inventory and executed outcomes/residual risk; no universal prevention claim |
| Microsoft AGT reuse | Selected policy adapter | Supported capability inventory, configuration, version compatibility and additional useful subsystems |
| NVIDIA NeMo reuse | Selected input/output inspection | Relevant retrieval/dialog/execution rails and operator configuration acceptance |
| Cisco inspection | SDK adapter | Live nonproduction acceptance and CLI-supported activation |
| DefenseClaw | Evaluated; not adopted | Implement needed missing controls through supported reuse rather than treating evaluation as integration |
| Live ServiceNow/Hatz/VirusTotal workflow | Synthetic/local acceptance | Authorized nonproduction connectors and end-to-end security operations scenario |
| Release process | Local unsigned rc2 provenance | Separate repository, hosted CI, trusted signing and publication when explicitly authorized |
| Independent security review | AI-assisted reviews only | External human review; remediation and revalidation |

## Known attack limitations still open

Pinned malicious capabilities, poisoned model/training data, semantic grounding,
undeclared confidential context, paraphrased declared context, generic retrieval
connectors and legacy unbound IPC remain confirmed gaps in the current 56-scenario
suite (seven gap scenarios). Production inventory admission prevents the tested
missing-host alias configuration in development source; it does not discover
aliases or prove an operator's account mapping. Remaining gaps require a supported control
and executed acceptance, or an explicit user-approved change in product scope.

Trusted inventory cannot discover or prove that two arbitrary remote hosts do
not share storage. Its acceptance must state that operator inventory completeness
is an assumption, not automatic DNS alias discovery.

Durable approval consumption is atomic against concurrent requests and ordinary
restart. Restoring an older valid database snapshot may resurrect approvals;
there is no independent monotonic checkpoint. Old backups lacking the new store
must be restored with their matching release before explicit adoption. Audit
rotation retains old decryption keys (maximum 32 total); key retirement requires
a separate migration. These limits remain part of acceptance.
