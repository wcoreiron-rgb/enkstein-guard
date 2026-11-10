# Data protection: classification, propagation, retrieval and grounding

This describes what 0.5.0rc2 enforces for sensitive data, where the labels come
from, and what it cannot recognize. Evidence references are in the
[readiness register](cli-production-readiness.md).

## Levels and trusted sources

Levels are ordered `public < internal < confidential < restricted`. A value's
level is the highest level assigned by any trusted source:

| Source | Configured by | Example |
|---|---|---|
| Route `produces` | operator | a CRM route returns at least `confidential` |
| Field rules | operator (`sensitivity.field_rules`) | `["customer", "*", "ssn"] → restricted` |
| Detectors | built in | credential, private-key and dashed SSN patterns → `secret_level` (`restricted`); email, phone and Luhn-valid card numbers (in text or sent as JSON numbers) → `detected_level` (`confidential`) |
| Declared context | operator files | system prompts, internal phrases, code names |
| Document records | operator ingestion | each retrieval document carries a label |
| Heuristics | built in | confidentiality markers; **monitor-only by default** |

Agent-supplied labels, sensitivity fields, ACLs or identities are ignored.
Vault references (`[[EGV:…]]`) are opaque and carry no level. Other sensitive
numbers sent as JSON numbers (SSNs or phone numbers without separators,
account numbers) are not recognized; declare them with field rules.

## Propagation

**Service routes (CLI product).** Before dispatch the `sensitivity` control
computes `max(agent taint, payload level)` and denies when it exceeds the
route's `clearance`. After execution the response level is
`max(route produces, retrieved document labels, response classification)`; a
response above the agent's `clearance` is withheld (`response_withheld`) and
otherwise released after the agent's taint is raised and persisted. Taint is
sticky and durable across restarts, so anything an agent writes after seeing
confidential data — including summaries and paraphrases — is treated as
confidential. Operators reset taint (`agent reset-taint`, audited) only after
discarding the agent's state, for example by recycling its container.

**Round trips.** Data written to a backend can be read back by another agent.
In the production profile every route to the same backend must declare
`produces` at least as high as the highest `clearance` of any route to it
(`produces_below_destination_clearance`), so data cannot lose its level by
being written and read back through Guard. The backend is identified as:

- the connector's `data_domain` when declared (shared by every connector and
  tenant that declares it), otherwise
- the tenant's canonical destination: the endpoint host in the egress proxy's
  normalization (lower-case ASCII, no trailing dot, canonical IP literal;
  non-canonical spellings are rejected as `endpoint_host_not_canonical`), or the
  fixture destination compared case-insensitively.

**Scope decision (0.5.0rc2): DNS-level aliases are declared, not discovered.**
Guard cannot know that two different host names reach one service (CNAMEs,
alternate domains, a load balancer serving both). Undeclared, such aliases let
data written through one name be read back through the other at a lower label;
this is a confirmed gap scenario (`test_undeclared_dns_alias_can_lower_label`).
Declare aliases with one `data_domain` (compared case-insensitively). Shared IP
addresses are not treated as aliases, because unrelated services share
addresses behind proxies and CDNs. As a hint only, validation warns
(`connectors_may_alias_one_backend`) when connectors to different host names
under one parent domain do not all declare a `data_domain`.

Guard also cannot see copies made outside its routes; treat systems that other
tools write to as `produces` at their highest level. In production one provider
secret value cannot be stored for two tenants
(`secret_value_shared_across_tenants`), because a shared provider account shares
any provider-side state across them.

**Provider-side destinations.** A model provider can itself fetch or keep data:
image and file URLs, hosted tools, web search and stored completions would send
data to places Guard never authorized. `chat_completions` request bodies are
therefore limited to text chat fields (see the configuration reference); the
rest is refused before dispatch. 0.5.0rc1 refused media parts only on
`tokenize` routes. Provider features that do not need a request field (a model
with built-in browsing, provider retention) depend on the provider and model the
operator chooses for a route's clearance.

**Privacy routes.** `tokenize` replaces detected sensitive values with
agent-scoped vault references before controls and transport, so lower-cleared
destinations (for example an external model) never receive them, and tokenizes
responses. A card number sent as a JSON number in a request is rejected (the
destination's schema would change); in responses it is replaced by a string
reference. `restore` restores references only for the route's destination, only
for the same tenant/principal/agent scope and only before expiry; a mismatch is
rejected before any external call.

**PrivateAI (SDK).** `sensitivity_control` can be an input control (on the
tokenized request); `declared_output_control` and `grounding_control` are
output controls that withhold model output.

**ProtectedOrchestrator (SDK).** With a `classifier`, arguments and tool results
add their level as a workflow label. Labels are workflow-wide and sticky, so
delegated children and handoffs inherit them, and a tool must `accept` every
label to run.

## Declared context

Operators declare confidential text in files. Short entries and canaries match
as whole phrases, including case, punctuation, spacing, zero-width characters,
common Cyrillic/Greek look-alikes, URL encoding, base64 and hex. Longer entries
match when at least two distinct four-word shingles reappear. Fingerprints are
keyed HMACs held in memory.

It does **not** recognize paraphrase, translation, reversal, partial fragments
below the threshold or undeclared facts. Single dictionary words make poor
canaries (false positives).

## Unlabelled data: evaluation

`tools/evaluate_unlabelled_detection.py` runs the versioned synthetic corpus
`tests_adversarial/data/unlabelled-corpus-v1.json` (30 adversarial, 24 benign).
Executed result (`verification/cli-v1/unlabelled-detection-evaluation.json`):

| Detector | TP | FN | FP | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| Heuristics | 15 | 15 | 5 | 19 | 0.75 | 0.50 |
| Declared context | 11 | 19 | 1 | 23 | 0.92 | 0.37 |
| Combined | 24 | 6 | 6 | 18 | 0.80 | 0.80 |

Misses (combined): partial reuse below threshold (A11), paraphrase (A21),
translation (A22), reversal (A23), leetspeak variant (A25), indirect description
(A26). False positives: "confidential computing" (B02), a private IP in a
tutorial (B09), a dictionary-word canary (B10), "do not share passwords" (B18),
"internal notes" (B19), "system prompt concept" (B23). Because of these false
positives heuristics are `monitor` by default. These numbers describe this
corpus only; arbitrary confidential information is not recognized automatically.

## Retrieval authorization

`retrieval_local` documents are stored encrypted with tenant, ACL (principals,
`agent:<id>`, groups, or `*` for the whole tenant) and label. For each request
the authenticated identity from the trusted security context selects documents:
same tenant, ACL match, label at or below the agent's clearance. The local store
filters **before** ranking, so result counts and ordering never depend on
documents the caller may not read. Requests by document ID return unauthorized
and nonexistent IDs identically. Request fields other than `query`/`top_k` or
`document_ids` (for example a forged `tenant`) are rejected before any lookup.

For external backends `RetrievalAuthorizer` reads only `doc_id` (and optionally
content for a digest check) from each candidate; tenant, ACL, label and content
always come from Guard's records. Over-fetching from an external vector store can
still reveal approximate counts to that backend's operator; generic tool
connectors used for retrieval get none of these checks (confirmed gap).

## Grounding

With `grounding` on a route (or `grounding_control` in PrivateAI), responses must
cite documents with `[[cite:ID]]` markers or a `citations` list. Every cited ID
must have been retrieved for the same agent recently (in-memory, 15 minutes,
lost on restart — fail closed) and quoted spans must occur in the cited
document. Fabricated or unretrieved citations withhold the response. Whether the
cited document supports the claim is **not** verified (confirmed gap).

## Training and model poisoning

Scope limitation: Guard has no access to training data or model weights. The
supported controls are model identity pinning in connector configuration,
operator-only retrieval ingestion with content digests, and output controls.
Poisoned answers are not detected (confirmed gap).

## Malicious components

Hash pinning proves a component is the approved bytes; it is not malware
detection. An optional declared-capability static check (`Admission(...,
capabilities=…)`) denies Python components that use undeclared network,
process, dynamic-code, native, filesystem-write or environment capabilities.
A pinned component that misuses capabilities it legitimately declares is not
classified (confirmed gap). See the scanner evaluation in
[DefenseClaw evaluation](security/defenseclaw-evaluation.md).
