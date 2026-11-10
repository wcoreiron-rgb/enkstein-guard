# Optional AGT CLI policy

The optional AGT policy engine narrows existing agent-to-route grants with local
conditions over the prepared JSON payload. It does not add routes, widen grants,
change roles, rewrite payloads, restore vault references, or contact a model or
service. Existing authentication, tenant checks, clearance, privacy preparation,
deterministic controls, and route authorization remain authoritative.

This document describes the staged source-package contract for
`0.5.0rc3.dev12`. Results from an installed `0.5.0rc3.dev11` distribution do not
validate this staged feature or establish production availability.

## Configuration contract

`policy_engines` is an optional top-level list and defaults to empty. It accepts
at most 32 entries. One AGT definition has this exact shape:

```json
{
  "name": "orders-policy",
  "kind": "agt",
  "tenant": "tenant-a",
  "bindings": [
    {
      "agent": "orders-agent",
      "route": "orders.read",
      "conditions": [
        {"field": "approved", "operator": "eq", "value": true},
        {"field": "order.amount", "operator": "lte", "value": 100}
      ]
    }
  ]
}
```

Each engine has 1–256 bindings. A binding has exactly `agent`, `route`, and
`conditions`, and each `(agent, route)` pair is unique. It contains 1–16
conditions with exactly `field`, `operator`, and `value`.

Fields are relative to the prepared JSON payload. They contain 1–8 dot-separated
identifier segments; each segment is 1–64 characters, starts with a letter or
underscore, and then contains only letters, digits, underscores, or hyphens.
Any segment containing a double underscore, wildcards, array indices, empty segments, and path
syntax are rejected.

Supported operators are `eq`, `lte`, and `gte`. Values are non-null JSON scalar
booleans, integers, finite floats, or strings of at most 256 characters. `lte`
and `gte` accept only integers or finite floats, never booleans. All conditions
in one binding are combined with AND.

At runtime the leaf must exist, be non-null and scalar, and have the exact Python
type of its configured value. There is no boolean/integer or integer/float
coercion. Missing fields, non-finite floats, objects, arrays, and type mismatches
deny the request before vendor evaluation.

The binding agent must be a configured identity with the same tenant, must
already hold the exact route grant, and the route must belong to that tenant and
select the same engine through its `policy_engine` field. Unknown, cross-tenant,
internal security-inspection, unselected, duplicate, and unused bindings are
rejected. An identity/route pair without an exact binding is denied; request
payload fields cannot assert or override tenant, principal, agent, or route.

## Optional SDK and startup

Pure definition validation does not import the optional SDK. Constructing a
configured control requires the tested distribution
`agent-governance-toolkit-control-plane==5.0.0` and its expected
`PolicyEngine`, `Condition`, and `ConditionalPermission` API. Missing, wrong,
or incompatible SDKs and failure to freeze the engine must reject service
startup. A core installation without the optional SDK remains valid only while
no AGT policy is configured.

Construction creates exact JSON roles `[tenant,principal,agent]`, adds only the
bound route names and `args.<field>` conditional permissions, freezes the engine,
and returns the required async control `agt.<name>`. Private condition and
identity snapshots are detached from the mutable input configuration. The
mutable engine is not returned.

The local strict checks run before the unchanged vendor adapter. AGT can only
contribute an allow recommendation or a denial; it cannot override another
control's denial or dispatch a route. Vendor exceptions, invalid verdicts,
shadow mode, and control timeouts fail closed as required-control errors, with
no approval or availability fallback. Fixed public errors do not include SDK or
payload details.

AGT evaluation is local and does not require endpoints, credentials, sockets,
plugins, arbitrary YAML, Python policy code, NeMo, or Cisco AI Defense. Native
vault references remain opaque strings in the prepared payload. Local unit tests
with socket creation disabled verify the pinned SDK contract, but do not prove
live-provider behavior, deployment support, or production acceptance.

## Staged deployment artifact

The build tools accept an explicit `--agt-wheel` in addition to `--guard-wheel`.
Omitting it keeps the core dependency set; configuring AGT in that installation
still rejects startup when the SDK is missing. Supplying it admits only the
reviewed pure Python AGT 5.0.0 wheel with SHA256
`e1c49dd3e407ae2e8e3267c4bc5b77d065c196a6553f85e99fc9d1a179f161dd`.
Both glibc and musl wheelhouse builders include this artifact in their hash lock,
check its metadata and copied bytes, and preserve previous wheels and locks in a
new directory under `dist/preserved-wheelhouses/` before refreshing them. No
floating AGT package-index resolution or optional model/SQL dependencies occurs.

Its source is the official public AGT archive at commit
`86db4607dcb67e5dbe48b885bc535f77be5e244d`, archive SHA256
`d188680c60a6d6be25799fa8b0236e869c45c0a978650b9aabba254bd646492c`.
The control-plane subtree was built offline with Python 3.11.14, pip 26.2.1 and
setuptools 83.0.0, `--no-deps --no-build-isolation --no-index`,
`SOURCE_DATE_EPOCH=1767225600` and `PYTHONHASHSEED=0`. Two consecutive builds in
that same environment matched; independent build-environment reproducibility
has not been established. The original archive, all 99 unchanged source-file
hashes, license, logs and wheel provenance remain in staged verification.

The actual wheel metadata has no base dependencies and says Python >=3.8;
upstream's `setup.py` overrides the >=3.11 minimum in its `pyproject.toml`.
Support for additional interpreters is not inferred. A minimal Mac core
environment imported this exact wheel and passed 13 AGT runtime/CLI tests with
socket creation blocked. This is bootstrap source evidence. Installed Guard,
Linux glibc and Alpine ARM64 image/profile validation remain required before
deployment support is accepted.
