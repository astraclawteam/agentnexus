# AgentNexus Open-Core Implementation Plan

> This public plan is sanitized for the open-core repository. It avoids local workspace paths, private repository names, customer details, credentials, and enterprise-only implementation details.

**Goal:** Build AgentNexus as an Agent-first enterprise gateway open-core runtime with stable public contracts, governance foundations, connector runtime, local/dev deployment profiles, and an admin console.

**Architecture:** AgentNexus has an Agent Control Plane backed by Google ADK Go v2 and a Runtime Data Plane backed by Go services. The runtime uses PostgreSQL, NATS JetStream, OpenFGA, S3-compatible object storage, and a pluggable Secret Provider while preserving SaaS, private, and hybrid deployment compatibility.

**Tech Stack:** Go, Google ADK Go v2, llmrouter through `adk-llmrouter-model`, MCP Go SDK, PostgreSQL, pgx, sqlc, goose, NATS JetStream, OpenFGA, chi, oapi-codegen, ConnectRPC, S3-compatible storage, Secret Provider, Docling sidecar, React, TypeScript, and Claw-runtime-style UI primitives.

---

## Open-Core Scope

The open-core repository owns:

- Gateway Runtime API.
- Gateway Agent Control Plane.
- Public SDKs and API contracts.
- Connector Manifest schema.
- Basic connector runtime.
- Policy, Access Ticket, Step Grant, Secret Provider, and Audit foundations.
- Local/dev SaaS and private deployment profiles.
- Open-core admin console and shared UI primitives.

The open-core repository must not contain:

- Customer-specific adapters, templates, mappings, fixtures, or credentials.
- Commercial connector implementation details.
- Enterprise license enforcement.
- Production private-deployment automation.
- Private roadmap, customer names, private endpoints, or secrets.

## Public Contracts

Enterprise and third-party extensions must depend on published contracts, not private implementation details:

- Go module: `github.com/astraclawteam/agentnexus/services/agentnexus`.
- Public Go SDKs: `sdk/go/*`.
- OpenAPI contracts: `services/agentnexus/api/openapi`.
- Proto contracts: `services/agentnexus/api/proto/agentnexus/*/v1`.
- OCI images: `agentnexus/<service>:<semver-or-sha>`.
- Helm chart: `agentnexus`.
- Connector Manifest schema with explicit versioning.

Packages under `services/agentnexus/internal/*` are private implementation details.

## Locked Architecture Decisions

- Project name: `AgentNexus`; internal identifiers use lowercase `agentnexus`.
- Service entrypoints: `gateway-api`, `gateway-agent`, `connector-worker`, and `connector-agent`.
- Task Orchestrator is an MVP internal module, not a standalone process entrypoint.
- Gateway Agent framework: Google ADK Go v2.
- Model access: llmrouter only through `adk-llmrouter-model`.
- Task/event backbone: NATS JetStream.
- Permission model: OpenFGA plus Policy DSL.
- Policy decision values: `allow`, `deny`, `need_external_receipt`, and `allow_with_masking`.
- External receipt module: External Receipt Relay.
- External receipt tables: `external_receipt_requests` and `external_receipts`.
- External receipt target field: `receipt_target`.
- Connector Agent enters MVP with outbound-only registration and execution.
- Frontend uses Claw-runtime-style shared UI primitives and tokens.

## Goal Sequence

### Goal 0: Lock Architecture Baseline

- Confirm the project name, technology decisions, repository boundaries, and public contract locations.
- Verify no unresolved decision markers remain in the architecture spec.
- Publish this sanitized open-core plan.

Verification:

```powershell
Select-String -Path 'docs/plans/2026-07-06-agentnexus-open-core-implementation-plan.md' -Pattern '鏈喅绛東鏈敹鏁泑寰呮媿鏉?
```

Expected: no matches.

### Goal 1: Create Go Workspace And Dev Skeleton

- Create `services/agentnexus`.
- Initialize Go module `github.com/astraclawteam/agentnexus/services/agentnexus`.
- Add service entrypoints for `gateway-api`, `gateway-agent`, `connector-worker`, and `connector-agent`.
- Add config loading, health status, unit tests, and build/test commands.

Verification:

```powershell
go test ./...
go build ./cmd/gateway-api
go build ./cmd/gateway-agent
go build ./cmd/connector-worker
go build ./cmd/connector-agent
```

### Goal 2: Define API Contracts And Service Boundaries

- Define Gateway Runtime OpenAPI.
- Define Gateway Agent OpenAPI.
- Define task, connector, and audit proto contracts.
- Add request context parsing and validation.

Verification:

```powershell
go test ./internal/app -run TestRequestContext
```

### Goal 3: Build Persistence Foundation

- Add PostgreSQL migrations for enterprises, users, org graph, tasks, tickets, connectors, and audit.
- Add sqlc queries and storage foundation.
- Add integration tests gated by available PostgreSQL infrastructure.

Verification:

```powershell
go test ./tests/integration -run TestPostgresCore
```

### Goal 4: Implement ADK Go v2 And llmrouter Adapter Spike

- Completed ADK Go v2 dependency setup.
- Completed `adk-llmrouter-model` message, stream, tool call, usage, and error mappings.
- Completed network-free mapping tests and env-gated integration tests.

Verification:

```powershell
go test ./internal/llmroutermodel
```

### Goal 5: Build Task Orchestrator On PostgreSQL And NATS JetStream

- Completed durable task runs, task steps, confirmation checkpoints, and valid state transitions.
- Completed NATS JetStream subjects for task events.
- Completed infrastructure-dependent test gates with explicit environment variables.

Verification:

```powershell
go test ./internal/tasks
```

### Goal 6: Implement IAM, Org Graph, And OpenFGA Checks

- Implement enterprise, user, external identity, org unit, membership, and org version logic.
- Define OpenFGA relationship model and checks.
- Add unit tests and env-gated OpenFGA integration tests.

Verification:

```powershell
go test ./internal/iam
```

### Goal 7: Implement Agent-First Organization Import

- Implement normalized org source structures and provider interfaces.
- Implement mocked WeCom, Feishu, and DingTalk org source providers.
- Implement Excel/CSV import, preview, conflict detection, confidence rules, and confirmation checkpoints.

Verification:

```powershell
go test ./internal/connectors/orgsource
```

### Goal 8: Build Connector Manifest Runtime L0/L1

- Define public Connector Manifest SDK types.
- Validate manifests.
- Enforce default deny for undeclared resources and fields.
- Enforce read-only defaults.
- Implement HTTP/OpenAPI, readonly database, and file storage adapters.

Verification:

```powershell
go test ./internal/connectors/...
```

### Goal 9: Implement Policy DSL, Tickets, Grants, And Audit Hash Chain

- Implement Policy DSL decisions.
- Implement Access Ticket and Step Grant lifecycle.
- Implement append-only audit hash chains.

Verification:

```powershell
go test ./internal/policy ./internal/tickets ./internal/audit
```

### Goal 10: Implement Lightweight Connector Agent

- Implement outbound-only Connector Agent registration and execution.
- Reject unknown connector instances and dynamic code payloads.
- Return audit context with each result.

Verification:

```powershell
go test ./internal/connectors/agent
```

### Goal 11: Implement External Receipt Relay

- Resolve receipt targets from external sources, connector config, Policy DSL org rules, or user selection.
- Implement delivery abstraction, receipt verification, and result propagation.

Verification:

```powershell
go test ./internal/receipts
```

### Goal 12: Implement Admin Console With Claw Runtime UI Reuse

- Create shared Claw-runtime-style UI package.
- Create admin console shell with Enterprise Pulse, dashboard metrics, resource map, Access Ticket table, Connector Health, and Gateway Agent launcher.
- Add frontend rendering tests.

Verification:

```powershell
npm test --workspace packages/enterprise-gateway-console
```

### Goal 13: Package Open-Core Dev Profiles

- Add SaaS-dev and private-dev Docker Compose profiles.
- Add local/dev Helm chart skeleton.
- Document dependency toggles for PostgreSQL, NATS, object storage, and Secret Provider.

Verification:

```powershell
docker compose -f compose.private-dev.yaml config
```

### Goal 14: Run End-To-End MVP Scenario

- Seed an enterprise.
- Simulate Gateway Agent organization import.
- Create org version, case ticket, policy decision, step grant, connector read, and audit events.
- Verify audit hash chain.
- Write demo instructions.

Verification:

```powershell
go test ./tests/e2e -run TestMVPOrgImportAndAccess
```

## Implementation Risks

- ADK Go v2 and llmrouter adapter assumptions must be validated early and isolated behind `internal/llmroutermodel`.
- Integration tests must be env-gated so contributors can run unit tests without local PostgreSQL, NATS, OpenFGA, object storage, or llmrouter.
- Public-adjacent schemas must stabilize early: Connector Manifest, Policy DSL, Access Ticket, Step Grant, audit events, OpenAPI, and Proto contracts.
- Repository boundary checks must stay active so enterprise-only material does not enter open-core.
- UI reuse should remain a small shared package; desktop-only runtime stores and native bridges must not enter the console.
