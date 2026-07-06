# Engineering Rules

## Architecture

- Use Go for core services.
- Use Google ADK Go v2 for Gateway Agent work.
- Access llmrouter only through `adk-llmrouter-model`.
- Use PostgreSQL for durable state.
- Use NATS JetStream for task and event delivery.
- Use OpenFGA plus Policy DSL for authorization.
- Use a pluggable Secret Provider for credentials.
- Use S3-compatible object storage for artifacts.
- Reuse Claw runtime UI design language without importing desktop-only runtime state.

## Governance Path

Business resource access must pass through:

1. Request context with enterprise and actor identity.
2. Access Ticket creation.
3. Policy and OpenFGA decision.
4. Step Grant for the specific action.
5. Connector execution through declared resources and fields.
6. Audit event append with evidence and hashes.

Shortcuts around this path are not allowed.

## Tests And Verification

- Unit test pure business logic.
- Integration test PostgreSQL, NATS, OpenFGA, and connector behavior where relevant.
- Gate network-dependent tests behind explicit environment variables.
- Keep fixtures generic and public-safe.
- Every Goal or PR must include executable verification.

## Dependencies

Add dependencies only when they support the architecture and reduce real complexity.
Document why a dependency is needed when it affects public contracts, deployment, or security posture.
