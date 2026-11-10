# Enkstein Guard product purpose

This describes the intended product. It does not claim that the current preview
implements every part of the scope.

Enkstein Guard is a reusable, CLI-first security enforcement layer that
developers incorporate into agentic solutions and AI-enabled applications.
Applications use Guard whenever AI accesses models, data, tools or systems,
delegates work, or proposes and executes actions. Local PCs and cloud runtimes
are deployment targets for the product.

The developer experience is one coherent product: install or deploy Guard,
connect the application's AI and action paths through supported SDK/adapters or
the Guard service, configure trusted identities, permissions and policies, and
operate the protected application through the CLI. Security belongs in the
application's execution path and developer workflow.

## Unified protection responsibilities

- Inspect supported model inputs/outputs, retrieved content and shared context.
- Protect secrets and sensitive data with scoped vault references, redaction and
  credential brokering; permit restoration only at authorized destinations.
- Check tools, API calls, data access, delegation and business actions before
  execution, preserving tenant/agent isolation, least privilege and task scope.
- Bind sensitive approvals to the exact actor, operation and payload; maintain
  auditability, recovery, budgets, quotas and duplicate-execution protection.
- Combine deterministic enforcement, appropriately constrained AI assessment and
  useful vendor capabilities behind the same integration and policy experience.
- Allow legitimate authorized work while refusing prohibited actions and
  failing closed at privacy, identity, history and internal security boundaries.

Models may deny or request explicitly permitted bound approval. They cannot
override deterministic denials, grant permissions, choose credentials or
endpoints, or rewrite the payload that will execute. Trusted broker context
remains local; model-visible inspection copies are redacted.

## Product acceptance

Each declared supported framework, connector, platform and deployment must have
an explicit interception/enforcement boundary, usable integration instructions,
executed legitimate/adversarial workflows and bypass-resistance evidence.
Platform, provider and integration coverage must be stated precisely. Applicable
OWASP/ATLAS threats, residual gaps and operational performance need evidence.

Local test or endurance completion is one engineering milestone. Product
completion also requires the supported installation/deployment experience,
realistic authorized nonproduction integrations, broader applicable security
coverage, independent review and release readiness. No universal protection
guarantee follows from package installation or a passing local test suite.

The [original requirements register](original-requirements-roadmap.md) remains
the completion register. Dev12 is a validated local candidate and remains
narrower than this full product purpose.
