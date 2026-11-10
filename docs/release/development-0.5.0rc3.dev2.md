# Development validation — 0.5.0rc3.dev2

Unreleased AI security engine iteration. Root integration review is complete;
candidate container validation has not passed. This document does not declare
production acceptance or independent human security review.

The optional configured engine assesses a tokenized inspection copy before
selected actions. Strict model results are bound to the exact operation and
can add denial or require approval; they cannot grant permissions, change
credentials or rewrite the executed payload. Encrypted actor-scoped rolling
history supplies bounded sequence context. The normal audit remains the record
of final authorization and execution outcomes.

The internal inspector has a fixed tenant-bound route, model and brokered
credential. Its configured local controls must succeed before any provider
dispatch. Privacy, history and deterministic-boundary failures always deny.
Only model uncertainty or provider failure can use the explicitly configured
deny or bound-approval fallback.

The preserved rc3.dev1 build completed its own capacity, three-hour soak and
snapshot checks. Those results do not validate this changed source. New wheel,
image, dependency and configuration identity checks are required for rc3.dev2.
The synthetic production-profile harness ran against the new image and failed
four assertions. Synthetic assessments test control wiring, not a real model's
resistance to attack.

## Frozen candidate

- Wheel SHA256: `396795348d121a1356490aab0ac76448e7ae8ffbc1a45a7d15590806a84718d7`.
- Package-content SHA256: `309a0f1c5280032a4465b07aa057966be6ccb37ee4d911efffa3606fc00ae904`.
- Image: `enkstein-guard:0.5.0rc3.dev2`, Linux ARM64.
- Image ID: `sha256:c95685befc6c73729c83188ba23a61133cbc4a564cba4cfc524a25df171ad51c`.
- Exact input revision and native/musl locks: `verification/0.5.0rc3.dev2/frozen-candidate.json`.

The image's installed package matches the wheel and its runtime dependency
inventory matches the musl lock. Native and musl locks name the same wheel.

## Executed candidate checks

| Check | Result |
|---|---|
| macOS installed wheel, Python 3.14 | 481 passed, 3 platform skips, zero failures/errors; 484 executed |
| Native Linux installed wheel, Python 3.12, exact locked dependencies | 477 passed, 7 macOS-only skips, zero failures/errors; 484 executed; privileged namespace fixtures in the dedicated VM |
| Optional SDK installed-wheel checks | 4 passed; AGT/NeMo/LangGraph real, Cisco mocked |
| Installed-wheel adversarial scenarios | 42 prevented in scenario, 7 benign allowed, 7 confirmed gaps; 56 executed, zero unexpected failures/skips |
| Mapping 2.3 | Generated from passing Linux component evidence; packaged data matches executed candidate reports; 20 OWASP rows and 17 selected ATLAS techniques; no full-category acceptance |
| Installed report identity review | All four reports match the wheel package and frozen revision; native Linux inventory matches its lock |
| Production boundary | 38/38 passed |
| Disk-full recovery | 20/20 passed |
| Synthetic AI profile | 36/40 passed, four failed assertions; not accepted |

An earlier unprivileged Linux source run skipped two namespace fixtures. It is
preserved as bootstrap evidence and is not substituted for the passing
privileged installed-wheel run. macOS/optional environments remain supplemental
and do not claim to match the native Linux deployment lock. Skips are not passes.

Root review fixed broker context corruption, double tokenization of prepared
vault references, stale configuration diagnostics, skipped internal route
controls, and local-control cancellation reaching approval fallback. The
regressions exercise the real host, IPC, secret broker and provider adapter with
synthetic responses. Their scope is recorded in `root-security-review.json`.

## AI fixture failure — preserved

The fixture placed its expected-allow sensitive request after three recorded
denial votes. The engine correctly escalated that later allow vote to
`require_approval`; the fixture expected dispatch without approval. Seven
inspection calls and two business calls were observed, with the sensitive
business call withheld. A reproduction using the installed control and the same
response fixture confirms that moving the benign sensitive case before the
attack cases allows it. No enforcement relaxation is required.

The failed report, exact wheel/image, both dependency locks and a matching
169-file input snapshot are preserved in this version's evidence directory.
A corrected fixture will receive fresh versioned evidence. No scan, capacity
or endurance acceptance is claimed for this candidate.

AI-enabled route capacity and full-history performance are unmeasured. The
previous non-AI capacity targets do not establish them. Operators must also
budget the additional [history storage](../operations/ai-security-sizing.md).

The seven known attack gaps, broader original requirements and external
release gates remain open. See the original requirements register and
[AI engine operator guide](../ai-security-operator.md).
