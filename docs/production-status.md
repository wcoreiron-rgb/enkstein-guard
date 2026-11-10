# Production milestone status

Status: **release candidate built; production acceptance incomplete**.

Version 0.4.0rc1 adds encrypted durable local audit with serialized writes,
startup and pre-write integrity verification, explicit key initialization,
external-checkpoint verification, and rejection of changed keys. Tests exercise
restart, corruption, suffix deletion, concurrent writers, unsafe permissions,
invalid events and key replacement. Audit requires explicit trusted-host wiring.

The installed wheel passed 123 core tests on local macOS/Python 3.14 and four
optional SDK/framework tests on Python 3.11. Cisco inspection remains mocked at
the service boundary. A Linux/macOS Python 3.11/3.13/3.14 CI matrix was added but
has not run on hosted runners. No PyPI publication was attempted.

The dependency vulnerability audit was attempted twice and failed because the
local TLS certificate chain could not be validated. Certificate verification
was kept enabled. No clean vulnerability result is claimed. The complete error
is in verification/production-vulnerability-audit.log.

See production-operations.md for backup, recovery, upgrades and remaining gates.
The packaged coverage matrix continues to mark complete category acceptance as
planned; component tests are not substituted for comprehensive OWASP/ATLAS
validation. Network enforcement, cloud isolation, distributed workflow recovery,
live-service validation and release signing remain unfinished requirements.

Artifact digest and exact test counts: verification/production-artifact.json.
