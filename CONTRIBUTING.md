# Contributing To AgentNexus

AgentNexus is an open-core enterprise Agent gateway. Contributions must preserve the public core, the enterprise extension boundary, and the governance path around identity, policy, tickets, secrets, connectors, and audit.

## Development Principles

- Keep the open-core repo independently buildable and runnable.
- Make every change reviewable in small logical units.
- Add tests for behavior changes and API contracts.
- Prefer existing architecture and local patterns over new frameworks.
- Do not add private customer data, credentials, or commercial connector details.
- Do not bypass Access Ticket, Step Grant, Policy, Secret Provider, or Audit.

## Branch And Commit Guidance

- Use focused branches such as `feat/goal-01-go-skeleton` or `fix/policy-mask-fields`.
- Keep commits small enough to review.
- Use clear commit messages:
  - `feat: add gateway-api skeleton`
  - `fix: reject undeclared connector fields`
  - `docs: clarify open-core boundaries`

## Pull Request Requirements

Every PR should include:

- Purpose and scope.
- Files or modules changed.
- Verification commands run.
- Any intentionally skipped verification and why.
- API, SDK, schema, or migration impact.
- Confirmation that no enterprise-only or customer-specific material was added.

## Review Expectations

Reviewers should prioritize:

- Repository boundary violations.
- Security and governance bypasses.
- Public contract compatibility.
- Missing tests or weak verification.
- Secrets, customer details, or private roadmap leakage.
- Unnecessary new dependencies or architecture drift.

See `docs/governance/review-checklist.md` for the detailed checklist.
