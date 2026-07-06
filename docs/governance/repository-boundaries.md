# Repository Boundaries

## Open-Core Repository

This repository, `agentnexus`, owns the public runnable core.

It may contain:

- Gateway Runtime API.
- Gateway Agent Control Plane.
- Public SDKs and API contracts.
- Connector Manifest schema and basic connector runtime.
- Policy DSL interfaces and base evaluator.
- Access Ticket and Step Grant foundations.
- Audit event schema and hash-chain foundation.
- Secret Provider interfaces and local/dev implementations.
- Local SaaS-dev and private-dev deployment profiles.
- Open-core admin console and shared UI primitives.

It must not contain:

- Commercial connector implementations.
- Customer-specific adapters, templates, mappings, or fixtures.
- Production private-deployment automation.
- License enforcement logic.
- Enterprise marketplace private metadata.
- Private credentials, customer names, or internal commercial roadmap.

## Enterprise Repository

`agentnexus-enterprise` is a private extension layer. It may consume released open-core contracts, SDKs, images, and Helm charts.

Enterprise code must not import open-core `internal` packages. If enterprise work needs a new extension point, add a public SDK/API contract in open-core first.

## Boundary Decision Rule

When unsure where code belongs, ask:

1. Is it required for the public core to run locally?
2. Is it a generic extension point rather than a customer or commercial implementation?
3. Can it be documented publicly without leaking private business details?

If the answer is yes to all three, it can usually live in open-core. Otherwise, place it in enterprise or redesign the boundary.
