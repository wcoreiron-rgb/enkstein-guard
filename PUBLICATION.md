# Enkstein Guard — development preview

One CLI-first security enforcement layer for supported AI applications and agents.
Protect configured model, data, tool and action paths with vault-backed privacy,
identity and tenant restrictions, exact-action approvals, audit and recovery.

This public source preview is based on **0.5.0rc3.dev12**. It is not a signed
production release. Installing the package does not intercept arbitrary apps or
network traffic. Applications must integrate with Guard and use the documented
trusted service/deployment boundary.

## Evaluate locally

Python 3.11+ is required. From a checkout, use an isolated environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/enkstein-guard --version
.venv/bin/python examples/private_runtime.py
```

The example uses synthetic local callbacks, not a live model or business API.
For configuration and runtime operation see [the operator guide](docs/cli-operator-guide.md).
Commands in older guides that refer to local dist/ bundles require a separately
built artifact; no wheel, image, private keys or runtime databases are published
in this repository preview. No package registry publication has occurred.

## What is implemented

- Encrypted local vault, recognized-sensitive-value replacement before supported
  model calls, and explicitly authorized destination-bound restoration.
- Trusted tenant/agent identity, route grants, task restrictions and retrieval ACLs.
- Configured credential brokering, model-provider restrictions and egress controls.
- Exact-action human approvals, durable request tracking, audit and key rotation.
- Supported embedded orchestration/delegation with shared labels and budgets.
- Optional inspection/policy engines with deterministic denial remaining authoritative.

Model routes default to tokenization, but documented operator-configured privacy
exceptions exist. Arbitrary secrets/undeclared confidential information are not
universally recognized. Streaming and multimodal support remain open. The newer
dev13 application client is separate staged work and is **not included here**.

## Evidence and known gaps

Dev12 completed scoped local Mac/Linux installed-wheel, boundary, disk-full,
synthetic AI, capacity and three-hour soak checks. These are workstation/local
measurements; hosted CI must run separately for this exact repository commit.
The recorded attack suite has **42 prevented, 7 benign and 7 confirmed gaps**
out of 56 scenarios. Skips and gaps are not passes. Real-model robustness and
universal OWASP/ATLAS coverage are not established.

The [development report](docs/release/development-0.5.0rc3.dev12.md) records exact
historical artifact identities and limits. Those archived local files are not
all included in this repository; publishing source does not recreate their
signatures or provenance. See [data protection](docs/data-protection.md),
[default model privacy](docs/default-model-privacy.md),
[the requirements register](docs/original-requirements-roadmap.md) and
[the completion plan](docs/product-completion-plan.md).

The README is preserved byte-for-byte from the validated candidate. This file
provides the current public-preview entry point. Third-party engines require
separate compatible installations/configuration; no third-party engine code or
vendor wheel is redistributed here. See THIRD_PARTY_NOTICES.md and LICENSE.

GitHub Actions performs source bootstrap checks only. The separate attack gate
intentionally remains red while the seven confirmed gaps remain; it does not
convert known gaps into passing security acceptance. Core skip reasons and
failed-step logs are retained as CI artifacts.
