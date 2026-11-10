# Foundation: steps 1–4

Delivered: inventory, versioned decision contract, installable package and a
mediated application execution path. Changes are restricted to this project.

## Supported boundary

Trusted bootstrap registers credentials, principals, tenant-bound route grants,
required controls, fixed resources/destinations and async transports. The caller
submits only credential, route name and JSON payload. Registries are copied and
immutable for the lifetime of the runtime. Reconstruct it to change policy.

`GuardRuntime.execute` snapshots JSON before its first await. Inspectors and
transports receive fresh payload copies. A digest binds payload, fresh operation
ID, identity, resource, destination and policy version. Results from an earlier
request cannot authorize another request. No API accepts cached external allows.

Missing required controls prevent startup. Exceptions, timeouts, malformed or
mismatched results deny before transport invocation. Deny wins; approval and mask
also block until implemented. Audit must accept an authorization record before
execution. Completion is recorded separately. Transport exceptions/timeouts
report unknown external outcome; do not blindly retry non-idempotent operations.

## Authentication and trust assumptions

The local credential adapter requires tokens at least 32 characters long and
retains SHA-256 hashes internally. Generate random credentials; length alone does
not prove entropy. Tokens map to host-configured identities; model-provided
tenant claims are not accepted. Route/tenant permissions are checked every call.
Argument-level authorization is the responsibility of required controls.

There is no OIDC, network listener, rotation/revocation service or secret delivery
system yet. Bootstrap, controls, transports and synchronous audit sink are trusted.
The sink must be bounded and durable in a production deployment. Demo events in
memory are not durable audit storage.

## Limitations

This is an application boundary, not a Python sandbox. Code possessing a raw
transport can invoke it directly, and same-process code can introspect internals.
An independent gateway plus OS/network/credential restrictions is needed for
process-level non-bypassability. Diagnostics keep that protection unavailable.

Async timeouts are cooperative: blocking or cancellation-suppressing callbacks
cannot be forcibly killed. Untrusted engines need isolated workers. Local prompt
inspection remains heuristic. No vault, output inspection, broad egress defense,
complete injection protection or full OWASP/ATLAS validation is claimed.

Validated scope is macOS/Python 3.14 with fake transports, not real cloud or agent
framework deployment. The initial Foundation application slice is implemented;
production isolation and framework integration release gates remain outstanding.

## Reference and tests

After installing, run `python examples/mediated_runtime.py`. It allows one fake
model request, denies a private-key fixture, and asserts one transport call.
Tests cover identity/scope denial, tenant binding, control errors/timeouts,
approval/masking, stale results, input mutation, audit outages, secret-free errors
and actual transport call counts. Evidence is under `verification/`.

## Executed verification

Version `0.1.0.dev1`: 38 tests passed against the freshly installed wheel in
isolated mode from `/tmp`. Private policy packs were disabled during verification.
Offline wheel installation, reference execution, doctor and coverage commands
passed. Artifact hash: `verification/foundation-artifact.json`; complete test
output: `verification/foundation-tests.log`.

The broader milestone gate requiring non-bypassability outside the application
is not met. Treat this as the completed SDK/application slice, not production
Foundation sign-off. Independent gateway/isolation remains explicit remaining work.
