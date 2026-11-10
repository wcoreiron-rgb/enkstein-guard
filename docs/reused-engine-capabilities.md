# Reused engine capability contract

This inventory records the narrow Microsoft Agent Governance Toolkit (AGT),
NVIDIA NeMo Guardrails, and Cisco AI Defense SDK surfaces that Enkstein Guard
actually invokes. It is an implementation and test boundary, not a statement
that installing a vendor package enables every vendor capability. None of these
adapters is enabled merely by package installation.

## Verified environment and evidence

The optional-engine environment inspected on 2026-11-07 uses CPython 3.11.14.
Version evidence comes from installed distribution metadata and the invoked
module source under `.venv-engines/lib/python3.11/site-packages`; Guard behavior
comes from `src/enkstein_guard/engines.py`, `private_ai.py`, and `runtime.py`.

| Provider | Exact installed distribution and invoked module | Installed/public primary-source anchor |
|---|---|---|
| Microsoft AGT | `agent-governance-toolkit-control-plane==5.0.0`; `agent_control_plane.policy_engine.PolicyEngine` | Installed `METADATA` identifies the [Microsoft repository](https://github.com/microsoft/agent-governance-toolkit). Installed `direct_url.json` pins archive commit [`86db4607dcb67e5dbe48b885bc535f77be5e244d`](https://github.com/microsoft/agent-governance-toolkit/tree/86db4607dcb67e5dbe48b885bc535f77be5e244d) and subdirectory `agent-governance-python/agent-os/modules/control-plane`. The separately installed `agent-governance-toolkit==4.1.0` umbrella distribution is not imported or invoked by this adapter. |
| NVIDIA NeMo Guardrails | `nemoguardrails==0.24.1`; `nemoguardrails.LLMRails` and `nemoguardrails.rails.llm.options.{RailType,RailsResult,RailStatus}` | Installed `METADATA` identifies NVIDIA's [repository](https://github.com/NVIDIA-NeMo/Guardrails) and [documentation](https://docs.nvidia.com/nemo/guardrails/); installed `llmrails.py` defines the exercised `check_async` contract and installed `options.py` defines the input/output rail and result enums. The distribution declares Python `>=3.10,<3.14`. |
| Cisco AI Defense | `cisco-aidefense-sdk==2.2.0`; `aidefense.runtime.AsyncChatInspectionClient` and `aidefense.runtime.models.{InspectResponse,Action}` | Installed `METADATA` names the SDK and links its own description to Cisco's [official SDK repository](https://github.com/cisco-ai-defense/ai-defense-python-sdk); installed `chat_inspect.py` and `models.py` define the exercised serialization and verdict fields. The remote inspection call is mocked in tests. |

The exact versions above are the tested compatibility points, not open-ended
compatibility ranges. Core Guard does not bundle these optional distributions.
If a required configured engine is absent, trusted bootstrap cannot construct
its real engine/client and must not register the route as usable. The optional
tests skip that engine with an explicit missing-distribution reason; they do not
turn absence into a passing integration claim.

AGT now has one narrow optional CLI product integration: trusted
`policy_engines` configuration can construct the tested local control-plane
`PolicyEngine` and register `agt.<name>` as a required route control. NeMo and
Cisco remain trusted SDK-bootstrap adapters only and are not activated by CLI
configuration. The CLI `security_engines` setting continues to select Guard's
separate brokered `ChatSecurityAnalyzer` path; it does not activate AGT or NeMo.

## Supported invocation and enforcement inventory

| Engine | Capability Guard actually invokes | Where its decision enters enforcement | Required operator configuration | Failure and unavailable behavior | Explicitly not integrated or verified |
|---|---|---|---|---|---|
| AGT control plane | `PolicyEngine.is_shadow_mode(role)` followed by synchronous `PolicyEngine.check_violation(role, operation.route, operation.payload())` in a worker thread. `None` allows; a string violation denies. CLI policy roles are exact deterministic JSON tuples of trusted `tenant_id`, `principal_id`, and `agent_id`; conditions address `args.<prepared-payload-field>`. | A configured route automatically requires `agt.<name>`. `GuardRuntime` evaluates it after payload preparation/tokenization and before dispatch. A local exact-type payload/identity/route check runs before the vendor verdict, and the vendor verdict may deny only. Route authentication, grant, tenant, clearance, deterministic controls, approval, audit, and dispatch remain Guard responsibilities. | Configure strict JSON `policy_engines` bindings only for agents that already hold the same-tenant route, and select that engine on the route. Trusted startup requires exactly `agent-governance-toolkit-control-plane==5.0.0`, constructs exact route constraints and conditional permissions, checks the frozen structure, and rejects shadow mode. `config validate` needs no SDK. | Missing/wrong-version/incompatible SDK or build failure rejects service start; it never silently drops a configured required control. Unbound identity/route, missing/wrong-type/nonscalar payload leaves, condition mismatch, shadow mode, SDK exception, invalid verdict, and timeout all deny before dispatch. A timeout does not forcibly stop the underlying synchronous worker thread. | No AGT umbrella-package feature, `AgentControlPlane.execute`, arbitrary policy YAML/Python/plugin loading, custom roles, role overrides, signals/VFS/kernel layer, quota/risk subsystem, framework auto-instrumentation, endpoint, credential, or network subsystem is activated. No musl image, live vendor service, or production deployment acceptance is established. |
| NeMo Guardrails | `LLMRails.check_async(messages, rail_types=[RailType(stage)])` for an explicit `input` or `output` stage. Guard sends the complete tokenized `operation.payload_json` as one `user` message for input or one `assistant` message for output. Only `passed` allows; `blocked` and `modified` deny. | A configured input adapter can be a required `GuardRuntime`/`PrivateAI` input control after tokenization and before the model. A configured output adapter runs after the model response is tokenized and before a private reply receipt is released. | Build `RailsConfig`/`LLMRails` with a non-empty flow list for every selected stage, register all local actions and any model dependencies those flows require, wrap each stage separately with `nemo_control`, and register it under the matching required-control name (normally `nemo`). Deterministic tests use local actions and no provider. | Adapter construction rejects an unknown stage, a non-async `check_async`, or no flows for the selected stage. Unknown result status rejects. SDK/action/model exceptions propagate; required Guard controls convert them to an error denial and do not dispatch the model or release output. `modified` denies because Guard has no reviewed rewrite-application contract. | Dialog, retrieval, tool-input, tool-output, topical, execution, server, evaluation, and vendor detector/model integrations are not wired by this adapter. No external LLM or comprehensive detector set was tested. Guard does not consume rewritten NeMo content. |
| Cisco AI Defense SDK | `AsyncChatInspectionClient.inspect_prompt(prompt=payload_json, request_id=operation_id)` or `inspect_response(response=payload_json, request_id=operation_id)`. Guard accepts only a boolean `is_safe` plus action `Allow`/`Block`; allow requires both `is_safe is True` and `Allow`. | The adapter returns a normal Guard control result and is enforceable only when trusted bootstrap registers it as a required input/output control. The optional test exercises real SDK message serialization and result models while replacing the client's `_inspect` remote boundary. | Construct an async SDK client with operator-managed service credentials and client configuration, select the stage, then register the adapter as a required control. Guard does not currently expose supported CLI activation or policy/profile arguments for this adapter. | Invalid stage/client/result rejects. SDK transport/auth/service errors propagate; if registered as required, Guard converts the error/timeout to a denial before the next protected boundary (model dispatch for input, response release for output). Conflicting `is_safe`/action values do not allow. | No live Cisco request, credential, tenant, policy/profile, endpoint acceptance, paid-service availability, management API, auto-patching, HTTP/MCP inspection, model scanning, or DefenseClaw integration was verified. The adapter is mocked-service status, not a live Cisco service integration. |

## Security interpretation

These engines are optional controls within Guard's policy aggregation boundary;
they are not blanket mandatory security dependencies. Selecting an AGT policy
engine makes its `agt.<name>` control mandatory for that route. Failure denies
the operation, while a default configuration with no policy engine loads no AGT
SDK and claims no AGT coverage.

Vendor/framework integration does **not** establish acceptance of any OWASP LLM,
OWASP Agentic, MITRE ATLAS, or other threat category. Category evidence remains
scenario-specific in Guard's separate coverage and verification artifacts.

The focused contract tests in
`tests_optional/test_reused_engine_contracts.py` additionally exercise real AGT
ABAC identity/payload binding, AGT shadow-mode rejection, NeMo's typed
`modified` result and explicit stage/message boundary, and required-control
failure before a local fake model. Socket creation is disabled around engine
execution; the tests use synthetic data and no business or provider API.
