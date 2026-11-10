# Private AI runtime delivery

Version: 0.2.0.dev0. Scope: local text/JSON runtime and selected engine APIs.

| Deliverable | Implemented and exercised | Boundary |
|---|---|---|
| Encrypted vault | Authenticated encryption, scope/expiry binding, rotation, tamper checks, purge/revoke, restart | Local keyring; no cloud KMS or old-key retirement |
| Pre-model privacy | Pattern and explicit-field replacement before inspectors and model | Heuristic discovery, text/JSON only; no streaming or binary content |
| Controlled restoration | Fixed authorized sink, principal/tenant checks, single-use receipt/tokens, expansion bounds | Receipts are process-local; sink result is not automatically model context |
| Credential broker | Encrypted persistent bindings, tenant/principal/route/destination checks, reload/revoke | Trusted connector must not echo credentials into unprotected paths |
| HTTPS model transport | Fixed host/model, brokered header, redirect/proxy rejection, bounded response | HTTP transport tested with fake opener; no live model account used |
| AGT | Actual pinned frozen policy engine allow/deny | Selected control-plane API only; umbrella package alone is insufficient |
| NeMo | Actual configured input/output rails in the private pipeline with AGT | Deterministic offline rail fixture; no claim of all NeMo detectors |
| Cisco SDK | Actual SDK serialization and strict verdict adapter | Remote inspection boundary mocked; paid service not enabled |

Source and operating guidance: [private runtime](private-ai-runtime.md).
Core and optional SDK test outputs are retained in `verification/`.
`private-runtime-artifact.json` identifies the exact verified wheel and test count.
`optional-environment.txt` records SDK/transitive versions; no source project is
needed at runtime. Selected optional requirements are in `requirements-engines.txt`.

This delivers the local private-runtime milestone. Live Cisco service validation,
production provider integration, independent isolation, cloud key providers and
all-category adversarial coverage remain explicit release gates, not delivered
capabilities. Existing original repositories remain unchanged.

## Verified artifact results

The installed wheel passed **83 core tests** on Python 3.14 and **3 optional SDK
integration tests** on Python 3.11. Both environment dependency checks passed.
Offline installation, private and Foundation examples, CLI diagnostics and copied
source provenance checks passed. AGT/NeMo tests run actual selected SDK code;
Cisco's remote inspection response is mocked. No live model or paid service was
called. Exact wheel SHA-256 is in `verification/private-runtime-artifact.json`.
