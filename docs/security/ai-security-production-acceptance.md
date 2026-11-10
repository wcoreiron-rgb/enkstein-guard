# AI security production acceptance

This acceptance profile validates synthetic AI-control wiring and tenant/process
isolation for the `production-linux-peer-bound` deployment. It does not measure
or claim real-model robustness, semantic security classification quality, or
production-provider availability.

The harness is prepared in `deployment/test_ai_security_profile.py`. It must be
run only after the staged wheel and container image have been built and root has
approved container/VM acceptance:

```bash
ENKSTEIN_POLICY_PACK=/nonexistent/guard-stage-tests \
GUARD_TEST_IMAGE=enkstein-guard:<candidate-version> \
python deployment/test_ai_security_profile.py
```

Importing the module does not call Docker. The explicit entry point creates a
unique Compose project, uses only that project's containers and volumes, writes
`container-ai-security-profile.json`, and removes only its own project and
temporary run directory.

## Synthetic topology

- Guard runs as UID 10001 with `network_mode: none`.
- Tenant agents run as distinct UIDs 11001 and 11002 with
  `network_mode: none`; they can see only the Guard IPC socket and their own
  credential.
- The independent egress proxy is the only Guard-side process attached to the
  egress network.
- A local acceptance-only TLS upstream serves one fixed hostname and path.
- Per tenant, a `synthetic-model` business connector and a
  `synthetic-security` inspector connector use separate broker credentials on
  that same allowed hostname.
- Each tenant has an internal `security.assess` route. Internal routes are not
  granted to agents. Each business route names its tenant-bound security
  engine and uses privacy tokenization.

The upstream reads the inspector request's bound `action_digest` and returns a
strict `SecurityAssessment`. Scenario markers select only deterministic fixture
responses: benign low risk, model deny, critical risk, malformed extra field,
or low confidence. No external API, credential, or model is used.

## Required checks

The generated report enumerates every check, including:

- readiness, peer binding, loopback-only Guard networking, and healthy
  independent egress;
- two configured tenant-bound engines and no agent grant to either internal
  inspector route;
- distinct agent UIDs, absent agent egress/state mounts, and failed direct
  network probes;
- benign low-risk assessments dispatch the business request;
- deny, critical, malformed, and low-confidence assessments leave the business
  HTTP counter unchanged;
- an agent cannot call an inspector route or another tenant's business route;
- inspection and business calls are counted separately;
- only the two fixed models and `/v1/chat/completions` TLS path are used;
- inspector and business calls carry the intended distinct brokered API-key
  hashes;
- synthetic card and `sk-` values, plus broker secrets, are absent from both
  request bodies; the business body retains native vault references while the
  inspection copy contains only non-restorable `protected-reference:<sha256>`
  markers and none of the business references;
- the intended business request is dispatched only after AI allow, with its
  configured privacy tokenization intact;
- candidate wheel, installed image package, image ID, dependency lock,
  configuration hash/policy version, and source/test/tool/deployment revision
  digests are recorded and mutually consistent through the existing evidence
  helpers.

Expected fixture call totals are seven inspection requests and three business
requests: tenant A runs benign, deny, critical, malformed, low-confidence, and
sensitive scenarios; tenant B runs one benign scenario. Unauthorized internal
and cross-tenant calls occur before inspection and must not increment either
counter.

## Evidence and limitations

Successful execution writes
`verification/<candidate>/container-ai-security-profile.json` and preserves the
exact synthetic Guard configuration under that evidence directory. A report is
passing only when every enumerated check is true. Failed runs include redacted
diagnostics and still tear down the unique Compose project.

This profile demonstrates synthetic control flow, credential brokerage,
privacy boundaries, and tenant/process isolation on one Docker host. It is not
a live-provider acceptance, an adversarial evaluation of a real LLM, a capacity
benchmark, or a multi-host isolation claim.

