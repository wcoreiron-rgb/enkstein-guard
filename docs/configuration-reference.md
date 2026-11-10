# Product configuration reference (schema version 2)

The configuration is strict JSON (≤ 1 MiB, duplicate keys rejected). It holds
identity, permissions and policy only; it must never contain secrets (unknown
fields such as `api_key` are rejected). `enkstein-guard config validate`
reports every error as `{path, code}`. Defaults below apply when a field is
omitted.

## Top level

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | `2` |
| `profile` | yes | `production-linux-peer-bound` or `development` |
| `deployment.guard_uid` | production | UID the service must run as; agents may not share it |
| `paths` | yes | absolute, normalized: `state_directory`, `key_directory` (separate, not nested), `socket`, `admin_socket` (different directories), `archive_directory` |
| `tenants` | yes | `[{id, vault_bytes?}]`; give `vault_bytes` for all or none (sum ≤ half of `vault.max_bytes`) |
| `connectors` | yes | see below |
| `routes` | yes | see below |
| `agents` | yes | see below |
| `policy_engines` | no | local AGT conditional policies; default `[]`, see below |
| `approvers` | no | `[{id, tenants[]}]`; ids may not collide with agent ids |
| `backend_inventory` | production with network connectors (development source after rc2) | trusted backend/account, tenant and canonical-origin declarations; see [inventory reference](backend-inventory.md) |
| `service`, `vault`, `outcomes`, `audit`, `inspection`, `sensitivity`, `egress`, `retention` | no | sections below |

## Production profile rules

`production-linux-peer-bound` additionally requires: `deployment.guard_uid`;
`service.socket_group`; a unique nonzero `uid` for every agent that differs
from `guard_uid`; unique agent identities; `agents × per_peer_connections ≤
max_connections`; the `sensitivity` control on every route; time-bound request
IDs; `egress.mode` `proxy` when any network connector exists (never
`direct_development_only`); `egress.client_uids == [guard_uid]`; every network
connector destination on `egress.allow`; `service.max_requests_per_second`;
scheduled retention (`retention.scheduled` true); an outcome ledger large enough
for the configured rate and retention schedule
(`outcome_capacity_insufficient_for_request_rate`, with the required and
configured sizes in `detail`); and, for every non-retrieval route, `produces` at
least the highest `clearance` of any route to the same backend
(`produces_below_destination_clearance`). The backend is the connector's
declared `data_domain` (shared across tenants) or else the tenant's canonical
destination. Development source after rc2 additionally requires every production
network connector to match one trusted backend inventory entry, with an exact
matching `data_domain` and authorized route tenants. Missing origins fail closed.
Inventory correctness remains the operator's responsibility; Guard cannot prove
that independently declared backends do not share storage.

Development profiles report the same sizing problems as `warnings` in
`config validate` and `doctor` instead of refusing.

## `service`

| Field | Default | Range |
|---|---|---|
| `max_connections` | 32 | 1–1024 |
| `per_peer_connections` | 4 | 1–1024 (production reserves this per agent UID) |
| `socket_group` | null | GID owning the service socket directory (production) |
| `request_timeout_seconds` | 60 | ≤ 300 |
| `read_timeout_seconds` | 2 | ≤ 10 (unauthenticated read deadline) |
| `max_frame_bytes` | 1048576 | 1 KiB–16 MiB |
| `control_timeout_seconds` | 2 | required controls that exceed it deny |
| `transport_timeout_seconds` | 30 | connector calls that exceed it are outcome unknown |
| `drain_timeout_seconds` | 10 | shutdown wait before cancelling in-flight work |
| `approval_ttl_seconds` | 900 | 30–3600 |
| `max_requests_per_second` | null (production: required) | 0.01–100000; every configured agent gets an equal share (token bucket, burst of two seconds); requests over an agent's share get `busy` with reason `rate_limited` and are neither tracked nor executed. This rate is the input to outcome-ledger sizing |

## `vault`, `outcomes`, `audit`, `retention`

- `vault`: `max_bytes` (64 MiB), `max_entries` (10000, ≤ 200000), `token_ttl_seconds` (300).
- `outcomes`: `capacity` (10000, ≤ 1000000), `max_request_age_seconds` (86400),
  `clock_skew_seconds` (300), `time_bound_request_ids` (true; required in production).
  Validation requires capacity ≥ 1.1 × `max_requests_per_second` ×
  (`outcome_archive_age_seconds` + `outcome_archive_interval_seconds` + `clock_skew_seconds`),
  and the same for the busiest tenant's equal share; `config validate` prints the
  computation as `outcome_sizing`. See [capacity planning](operations/capacity-planning.md).
- `audit.full_verify_every` (10000 appends; 0 = only at open and on demand).
- `retention`: `scheduled` (true; required in production) runs these jobs inside the
  service: outcome archival every `outcome_archive_interval_seconds` (3600, 60–86400)
  for records older than `outcome_archive_age_seconds` (30 days; must exceed the request
  window); audit archival every `audit_archive_interval_seconds` (3600) when active
  events exceed `audit_archive_threshold_events` (100000), keeping
  `audit_archive_keep_events` (10000); vault purge of expired entries every
  `vault_purge_interval_seconds` (600). Archival works in bounded chunks; results and
  failures appear in `service status` (`retention`) and `doctor` warnings;
  `enkstein-guard retention run --store <name>` runs one job now.

## `inspection`

`private_pack`: absolute path to an operator private policy pack or `null`.
Implicit loading from the home directory is disabled while the service runs.

## Connectors

| `type` | Fields | Binding |
|---|---|---|
| `fixture` | `behavior`: `echo` (default), `accept`, `fail`, `slow`, `delay` (`delay_seconds`, 1) | synthetic; route supplies `resource`/`destination`; reported by `doctor` |
| `chat_completions` | `endpoint` (https, port 443, path ending `/chat/completions`, canonical host: lower-case ASCII/punycode, no trailing dot, canonical IP literal), `model`, `credential` (secret name), `authentication` (`bearer`/`x-api-key`), `timeout_seconds` (20), `max_response_bytes` (1 MiB), `ca_file` (optional private CA) | resource = model, destination = endpoint host |
| `virustotal_ip` | `credential`, `timeout_seconds` (15) | resource `ip-reputation`, destination `www.virustotal.com` |
| `retrieval_local` | `collection`, `max_results` (5, ≤ 20), `max_chars` (4000) | resource `collection:<name>`, destination `guard-retrieval` |

Every connector except `retrieval_local` accepts `data_domain` (identifier,
compared case-insensitively): connectors that reach the same backend under
different host names (DNS aliases, alternate domains) must share one
`data_domain`, so the production round-trip rule labels data read back through
any of them at least as high as data written through any of them. Guard cannot
discover such aliases itself; as a hint, validation warns
(`connectors_may_alias_one_backend`) when network connectors to different host
names under the same parent domain (last two labels) do not all declare a
`data_domain` — declare the same one for one backend, different ones otherwise.

`chat_completions` request bodies from agents may contain only text chat
fields: `messages` (roles `system`, `developer`, `user`, `assistant`, `tool`;
content as text or text parts; function tool calls), `temperature`, `top_p`,
`max_tokens`, `max_completion_tokens`, `stop`, `seed`, `response_format`,
`presence_penalty`, `frequency_penalty`, `tools` (type `function` only),
`tool_choice`, `parallel_tool_calls`, `reasoning_effort`; `model` must equal the
connector's and `stream` must be false. Image, audio and file parts, hosted
tools, web search, `store`, `metadata` and every other field are refused before
dispatch, because the provider would fetch, run or keep data outside Guard's
destination allowlist. Features a provider enables without a request field are
the operator's choice of provider and model.

In production, `connector secret-set` refuses a value already stored for another
tenant (`secret_value_shared_across_tenants`): one provider account shared by
tenants shares provider-side state across them.

## Routes

| Field | Notes |
|---|---|
| `name`, `tenant`, `operation`, `connector` | required; route names are the agent-facing API |
| `resource`, `destination` | required for `fixture`; must match the connector binding otherwise |
| `clearance` | required: highest level the destination may receive (`public` < `internal` < `confidential` < `restricted`) |
| `produces` | level floor of responses (default `public`) |
| `controls` | subset of `local_prompt`, `sensitivity` (default both); `task_boundary` and `approval` are added automatically |
| `approval` | `none` (default), `required`, `on_demand`; needs an approver for the tenant |
| `privacy` | Defaults to `tokenize` for `chat_completions` connectors, `none` otherwise. `tokenize` replaces detected sensitive values with agent-scoped vault references before controls/transport and tokenizes responses; `restore` restores references for this destination only, with the required clearance floor |
| `privacy_exception_reason` | Required trimmed 1–256 character operator reason for model `none`/`restore` exceptions; rejected for tokenized model and non-model routes. Diagnostics report exception existence without echoing the reason |
| `task_boundaries` | `[{principal, workflow, fields: [{path[], kind: str/int/bool, required?, choices?, minimum?, maximum?, max_length?}]}]`; requests from other principals/workflows or with other fields are denied |
| `grounding` | `{citations: required/optional, mode: citations/extractive}`; mode defaults to `citations`, checking references and quoted spans. `extractive` requires `citations: required`, an exact answer/citations envelope, and only authorized verbatim source spans. See [extractive grounding](extractive-grounding.md) and [chat adapter](extractive-chat-adapter.md) |
| `policy_engine` | Optional name of one same-tenant `policy_engines` entry. The host automatically adds required control `agt.<name>` after privacy preparation. Unknown, cross-tenant, or internal security-inspector selections are rejected. |

## Local AGT `policy_engines`

`policy_engines` is empty by default and has at most 32 entries. It is a narrow,
local conditional-permission compiler, not arbitrary AGT configuration:

```json
{
  "name": "ticket-policy",
  "kind": "agt",
  "tenant": "tenant-a",
  "bindings": [{
    "agent": "support-agent",
    "route": "ticket.update",
    "conditions": [{"field": "ticket.priority", "operator": "eq", "value": "high"}]
  }]
}
```

Objects use exactly the shown keys. Names use normal Guard identifiers and
`kind` is only `agt`. An engine has 1–256 unique `(agent, route)` bindings and
each binding has 1–16 conditions. The agent must already exist in the engine's
tenant and already hold that exact same-tenant route grant; the route must
select this engine through `policy_engine`. Unused engines, unknown references,
cross-tenant bindings, security-inspector routes, and duplicate pairs are
rejected. A binding narrows an existing grant—it never adds a route, role,
tenant, clearance, or tool. Requests from an unbound identity to a selected
route are denied.

`field` is relative to the JSON payload after Guard's privacy preparation. It
has 1–8 dot-separated identifier segments, each 1–64 characters, beginning
with a letter or `_`; wildcard, index, empty, path/code, and `__`-prefixed
segments are rejected. Operators are `eq`, `lte`, or `gte`. Values are non-null
JSON scalars (`bool`, integer, finite float, or string up to 256 characters);
`lte`/`gte` require a non-boolean number. All conditions are ANDed. Runtime
leaves must exist, be non-null scalars, and have the exact configured scalar
type—there is no coercion and booleans never act as numbers.

`config validate` performs this syntax and binding validation without importing
the optional SDK. A configured service requires
`agent-governance-toolkit-control-plane==5.0.0`; missing, incompatible, or
structurally unexpected SDK behavior makes service startup fail closed. Default
configurations do not load it. The engine is frozen during trusted startup and
its verdict may only deny: authentication, route grant, tenant, clearance,
deterministic controls, approval, privacy preparation, audit, and dispatch stay
authoritative. There is no shadow mode, payload rewrite, custom code/plugin,
arbitrary YAML, endpoint, credential, NeMo, Cisco, or network activation.

`policy explain`, `config validate`, and `doctor` expose names, counts, selected
routes, and local runtime state without echoing configured condition values.
These diagnostics do not establish musl compatibility, production deployment,
or live vendor integration.

## Agents

`{id, tenant, principal, routes[], uid?, clearance (internal), groups[], task (default)}`.
`routes` must belong to the agent's tenant. `clearance` is the highest level the
agent may receive; `groups` feed document ACLs; `task` is the workflow ID used
by task boundaries.

## `sensitivity`

| Field | Default |
|---|---|
| `detected_level` | `confidential` (email, phone, Luhn-valid card numbers in text or as JSON numbers) |
| `secret_level` | `restricted` (credential, private-key and dashed SSN patterns) |
| `field_rules` | `[{path[], level}]` (`*` matches any key or list item) |
| `declared_context` | `[{name, level, file (absolute), canary?}]` operator-declared confidential text |
| `unlabelled_heuristics` | `monitor` (record only), `off`, `enforce` |

## `egress`

| Field | Default |
|---|---|
| `mode` | `none`; `proxy` for production network connectors; `direct_development_only` for local development |
| `socket` | proxy Unix socket (separate directory) |
| `client_uids` | UIDs allowed to use the proxy (production: `[guard_uid]`) |
| `socket_group` | group owning the proxy socket directory |
| `allow` | `[{host, port, addresses?}]`; `addresses` lists explicit networks (otherwise only globally routable addresses are accepted) |
| `connect_timeout_seconds`, `idle_timeout_seconds`, `max_connections` | 10, 60, 64 |
