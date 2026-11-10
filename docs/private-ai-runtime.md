# Private AI runtime

Version 0.2.0.dev0 adds a local encrypted vault, private JSON model pipeline,
credential broker, fixed-endpoint HTTPS transport and optional engine adapters.
Upstream application source checkouts are not runtime dependencies.

## Use locally

Install `python -m pip install .` and run `python examples/private_runtime.py`.
The example uses a temporary vault and fake model/sink; no external API is called.
For persistent storage:

```sh
enkstein-guard vault init --directory .local-vault
enkstein-guard vault status --directory .local-vault
enkstein-guard vault rotate --directory .local-vault
enkstein-guard vault purge --directory .local-vault
```

Use `--key-file` for an independently protected key path. The default separates
data and keys into subdirectories, but both are accessible to the same OS user.
This protects database-only disclosure, not compromise of that user or process.
POSIX owner/mode checks are enforced; Windows ACL integration is not validated.

Initialization is explicit and exclusive. An unreadable database or missing key
never causes silent reinitialization. Back up both database and keyring securely;
losing the keyring makes records unrecoverable. Do not put keys in source control.

CredentialBroker.register stores encrypted credential bindings. After restart,
use CredentialBroker.load with the same name, tenant and principal to restore the
binding without re-entering the original secret. Credential expiry still applies;
reload is not an automatic refresh or extension of delegated authority.
Rotation retains old keys for interruption recovery, re-encrypts records in a
transaction, and requires an exclusive maintenance window. Old-key retirement
and cloud KMS/keychain providers are not shipped. Purge expired records on an
operator-defined schedule. Deletion is not guaranteed forensic disk erasure.

## Request flow

1. Host bootstrap fixes identity, tenant, model destination, routes, credentials,
   required inspectors and restoration sinks.
2. Guard authenticates and checks route/tenant grants, then snapshots JSON.
3. Local tokenization replaces detected values with random scoped references.
   Sensitive field names and text patterns are configurable. No external detector
   receives pre-tokenization content in the PrivateAI path.
4. Required input engines inspect tokenized content. Denial, malformed results,
   unavailable modules and timeouts block the model call.
5. Model receives only the transformed operation. If BrokeredChatProvider is used,
   its API key is resolved directly into the configured HTTPS Authorization header.
6. Provider output is locally tokenized and inspected before release. Output
   controls use a distinct operation ID so input verdicts cannot authorize output.
7. Caller receives a tokenized PrivateReply and an opaque receipt. Originals are
   never automatically restored into model context.
8. `restore_to` checks the caller's sink route and original principal/tenant,
   validates expiry and destination, atomically consumes references, and invokes
   the configured sink. Concurrent receipt replay cannot invoke it twice.

Restoration ignores caller mutations to PrivateReply.content and uses the saved
sanitized result. Receipts are in memory and do not survive process restart;
encrypted vault records do. Sink failures have unknown external outcomes; consumed
references/receipts are not automatically retried. Audit availability gates
execution; model/sink exceptions do not expose raw upstream error bodies.

## Supported content and limits

Text/JSON only, up to 1 MiB. Detection includes supported credential formats,
private key blocks, email, phone/SSN patterns, Luhn-valid payment-card candidates,
and configured sensitive fields. Free-text names and arbitrary business secrets
cannot be discovered reliably from patterns; mark their fields explicitly.
Numeric sensitive fields are rejected rather than silently changing data types.
Conservative field detection may need schema-specific tuning for tool definitions.
This is not medical/legal/entity-classification completeness or full DLP.
Restored expansion is also bounded to 1 MiB. Pending/in-flight replies share a
configurable per-runtime cap (128 by default); this is not a distributed budget.

Streaming, binary attachments and recognized image/audio/file parts are rejected.
There is no automatic retry/fallback to an unprotected provider. URL-loaded data,
custom provider protocols, direct SDK calls and traffic outside the registered
runtime are not protected. Use host/network isolation to prevent direct bypass.

## Model-provider integration

`BrokeredChatProvider` supports fixed HTTPS `/chat/completions` endpoints with an
explicit host allowlist, configured model and vault-brokered credential. Set
PrivateAI.model_destination to provider.destination and model_resource to its
model; pass provider.call as the transport. Register the broker credential for
the same tenant, principal, route `model`, and destination. Caller model overrides,
redirects, environment proxies, streaming and oversized responses are rejected.
TLS verification uses the standard trust store. Endpoint choice is trusted host
configuration; destination allowlisting is not DNS pinning or a cloud firewall.
HTTP tests use an injected fake opener; no live model API was called.

## Engine integration

`engines.py` adapts selected upstream APIs, not every toolkit feature:

| Adapter | Contract | Status boundary |
|---|---|---|
| Local | Existing pattern scanner over tokenized text | Default offline engine |
| AGT | Frozen control-plane PolicyEngine.check_violation | Tenant-aware role mapping; shadow mode rejected |
| NeMo | Configured LLMRails.check_async with explicit input/output rail | Missing rails rejected; modified results block until rewriting is implemented |
| Cisco SDK | AsyncChatInspectionClient.inspect_prompt/inspect_response | Requires configured service; explicit Block dominates, unknown verdicts reject |
| DefenseClaw | No new runtime adapter in this increment | Admission/gateway reuse belongs to supply-chain/execution milestone |

No optional engine activates merely because its package is installed. Missing
required engines block. Upstream dependency compatibility and actual SDK smoke
results are recorded separately in verification; mocked adapter tests are not
live service validation. No Cisco credentials or paid inspection service are
available in this project. Do not advertise that service as enabled.

Verified optional environment uses Python 3.11, NeMo 0.24.1, Cisco SDK 2.2.0,
and AGT control plane pinned at `86db4607dcb67e5dbe48b885bc535f77be5e244d`.
The umbrella `agent-governance-toolkit` 4.1.0 does not install that control plane;
the separately published `agent-control-plane` 1.2.0 lacks freeze() and is rejected.
Install `requirements-engines.txt` to reproduce the selected APIs. NeMo excludes
Python 3.14; use Python 3.11 for the combined engine profile. Actual AGT allow/deny
and NeMo input/output rails run offline. Cisco's actual SDK serialization and
verdict handling are tested with its inspection boundary mocked, not a live service.

Async timeouts are cooperative; Python cannot forcibly stop blocking callbacks
or HTTP worker threads. Production deployments need isolated workers and an
independent gateway. Vault contents may exist transiently in local process memory;
Python cannot promise zeroization. No whole-host or complete OWASP/ATLAS claim.
