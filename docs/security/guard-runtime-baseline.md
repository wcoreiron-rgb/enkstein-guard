# Enkstein Guard runtime baseline

Assessment date: 2026-10-19. Baseline HEAD: `bad013544afde738e9eab0c8c9282028fd28ab3d`.
The checkout has pre-existing uncommitted changes. This is a source inventory of
the working tree, not a certification or a complete attack assessment.

## Implemented foundations

| Component | Source / symbols | Evidence and limits |
|---|---|---|
| Coding-agent interception | `plugins/enkstein-guard/hooks/enkstein_guard.py`: `_evaluate`, `_handle_prompt`, `main` | Local decisions plus optional backend; not a mandatory OS boundary. |
| Local detection and packs | `plugins/enkstein-guard/hooks/policy.py`: `scan_content`, `scan_command`, `scan_prompt`, `scan_with_packs`, `redact` | Pattern/structural checks, scoped packs, masking. Imported scanning truncates at 65,536 characters. Private content not inspected. |
| Central evaluation | `backend/app/api/routes/trust_fabric.py`: `evaluate_guard_action` | Authenticated endpoint accepts classifications/digests; cannot independently inspect original content from hashes. |
| Enforcement | `backend/app/trust_fabric/enforcement.py`: `enforce` | Ring branch and catalog branch are alternatives. Full catalog flag does not guarantee catalog participation for ring-classified requests. |
| Catalog | `backend/app/services/policy_engine.py`: `evaluate_policy_catalog` | Reports traversal counts; first matching policy determines result; unmatched requests default allow. Counts do not prove protection. |
| AGT | `backend/app/trust_fabric/agt_bridge.py`; `backend/app/fabric/providers/agt/adapter.py` | Optional scanning and adapter functions; capability activation and upstream compatibility require separate verification. |
| Connector secret storage | `backend/app/services/secrets_manager.py`: `store_credential`, `get_credential` | Existing encrypted credential foundation with tenant checks. File has pre-existing modifications; do not replace. Not proof of pre-model tokenization. |
| Credential requests / approvals | `backend/app/api/routes/exec_channels.py`; `backend/app/models/exec_channels.py` | Existing request, credential broker, approval and execution concepts. Exact-action binding and credential delivery require tracing before reuse. |
| Orchestration | `backend/app/core/swarm/orchestrator.py` | Bounded parallelism and cancellation checks; shared descendant budgets and independent termination not established. |
| Memory | `backend/app/services/memory_runtime.py` | Tenant-aware approved observation retrieval and memory proposals; general poisoning prevention not established. |

## Confirmed design gaps

1. Hook backend outages retain local decisions; unexpected hook exceptions allow.
2. Ring/catalog policy composition needs a deliberate contract, without silently
   changing legacy first-match behavior for existing callers.
3. `send_secure_message` signs Base64-encoded JSON but labels it encrypted.
   That function does not provide payload confidentiality.
4. Tool approval in the hook denies and asks for human confirmation. This does
   not establish a single-use approval bound to an immutable operation.
5. No general encrypted privacy-token vault or complete model interception was
   established by this inventory. Existing connector secret storage must be reused
   where suitable rather than mistaken for absent functionality.
6. Stateful sensitivity propagation, non-bypassable tool access, and all-framework
   protection remain unverified.

## Verification boundary

Focused baseline suites: `backend/tests/test_enkstein_guard_hook.py` and
`backend/tests/test_guard_policy_catalog.py`. Executed with the existing backend
virtual environment: **134 passed, 5 warnings in 6.35 seconds**. Warnings concern
dependency deprecations and Pydantic protected namespaces. This result validates
these suites only, not broad attack prevention or framework compatibility.
The 270-policy test uses synthetic policies, not the private production catalog.
No private secret directories, keys, existing migrations, or production data were
read as part of this inventory.

Next: [runtime architecture and acceptance plan](../rfcs/guard-unified-runtime.md).
