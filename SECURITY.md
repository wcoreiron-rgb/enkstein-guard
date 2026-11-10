# Security and supported scope

This repository is a development preview, not a signed production release or a
certified security product. See PUBLICATION.md and the dev12 development report
for the exact local evidence and remaining requirements. No universal OWASP,
ATLAS, secret-detection or prompt-injection prevention claim is made.

Protection requires explicit application integration, trusted configuration and
the supported enforcement/deployment boundary. Installing the package alone
does not intercept arbitrary processes. Tests with synthetic secrets and fake
providers do not establish robustness against every real model or live service.

Known limitations include malicious use of approved component capabilities,
model/training-data poisoning, semantic grounding, undeclared confidential
context, paraphrased declared context, generic retrieval connectors without
document authorization and legacy unbound IPC. See the requirements register.

For suspected vulnerabilities, use the repository Security tab and its private
"Report a vulnerability" option. Never include real credentials, customer
records or exploitable private deployment details in a public issue. If private
reporting is unavailable, request a private reporting channel without posting
sensitive details. Independent human security review remains an open gate.
