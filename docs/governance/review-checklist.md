# Review Checklist

Use this checklist for human and AI-assisted review.

## Repository Boundary

- [ ] Open-core builds and runs without `agentnexus-enterprise`.
- [ ] No enterprise-only connector, license, customer template, or production private-deploy code was added.
- [ ] No customer names, private credentials, private endpoints, or private roadmap details were added.
- [ ] Public SDK/API changes live outside `internal`.

## Governance And Security

- [ ] Resource access goes through Access Ticket, Policy/OpenFGA, Step Grant, Secret Provider, and Audit.
- [ ] Connector access rejects undeclared resources and fields by default.
- [ ] Secret values are not logged, returned, or stored in fixtures.
- [ ] Audit events include enough context to trace identity, policy, ticket, connector call, and result evidence.

## Engineering Quality

- [ ] The change follows existing package and naming patterns.
- [ ] New abstractions have a clear reason.
- [ ] Tests cover successful and denied paths where security or authorization is involved.
- [ ] Verification commands are included in the PR.
- [ ] Generated files include a reproducible command or source.

## AI Coding Review

- [ ] The AI followed `AGENTS.md`.
- [ ] The AI did not widen scope without approval.
- [ ] The AI did not remove tests or hide failures.
- [ ] The completion report lists commands run and remaining risks.
