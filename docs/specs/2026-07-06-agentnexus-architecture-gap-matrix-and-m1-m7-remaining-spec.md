# AgentNexus Architecture Gap Matrix And M1-M7 Remaining Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this spec task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile the current AgentNexus repository against `E:\xiaozhiclaw\docs\superpowers\specs\2026-07-06-enterprise-agent-gateway-technical-architecture.md`, identify what is complete, and define the remaining M1-M7 execution scope.

**Architecture:** The enterprise architecture remains the source of truth. Week-One work is treated as a verified development slice, not as completion of the full MVP architecture. Remaining work must keep the open-core boundary clean: public SDK/API/Manifest/runtime in `agentnexus`; commercial connectors, license enforcement, customer templates, and production private deployment controls outside this repository.

**Tech Stack:** Go 1.25, Google ADK Go v2, llmrouter through `internal/llmroutermodel`, NATS JetStream, PostgreSQL with pgx, OpenFGA, stdlib HTTP router currently used by services, React + TypeScript + Vite console, Docker Compose and Helm skeletons.

---

## Source Of Truth

- Architecture document: `E:\xiaozhiclaw\docs\superpowers\specs\2026-07-06-enterprise-agent-gateway-technical-architecture.md`
- Current implementation branch: `codex/week-one-dev-flows`
- Current implementation commit: `5908a4c Implement M3 connector lifecycle`
- Week-One implementation spec: `E:\xiaozhiclaw\agentnexus\docs\specs\2026-07-06-agentnexus-week-one-next-step-spec.md`
- Open-core implementation plan: `E:\xiaozhiclaw\agentnexus\docs\plans\2026-07-06-agentnexus-open-core-implementation-plan.md`

## Current Baseline Summary

Completed in open-core:

- `gateway-api` exposes health, readiness, console overview, organization import preview, connector manifest validation, and connector smoke endpoints.
- `gateway-agent` runs as an HTTP service and exposes first-deployment dry-run planning.
- `gateway-api` exposes runtime API route skeletons for locate, read, act, and ticket lookup, with M4 authorization loop foundations behind the default runtime API.
- Generic `oa_http` organization provider can fetch departments, employees, and memberships from a generic HTTP source.
- Organization import confirm persists departments, employees, memberships, external identity bindings, org events, and org versions.
- Mock WeCom, Feishu, and DingTalk organization providers exist, and generic vendor HTTP wrappers exist for normalized vendor bridge endpoints.
- Connector manifest validation, runtime smoke execution, instance draft/smoke/confirm APIs, and Postgres-backed connector instance persistence exist for file/db/http-style resources.
- `internal/llmroutermodel` maps ADK model requests/responses/tools to llmrouter and has an env-gated integration test.
- Policy DSL, OpenFGA-style in-memory relationship checks, ticket, task, connector agent registration, connector runtime, audit hash chain, runtime authorization e2e, and MVP e2e tests exist as foundations.
- Minimal receipt model, target resolver, and receipt validation foundations exist.
- React console renders a Claw-runtime-style admin view and can call `GET /api/console/overview`.
- Docker Compose and Helm skeletons exist for dev profile validation.

Important limitation:

- The running console currently uses real local frontend/backend processes, but `GET /api/console/overview` still returns open-core development overview data, not fully live enterprise aggregation.
- `gateway-agent` OpenAPI must not advertise Agent run/message/confirmation operations until M5 implements the matching handlers.

## Architecture Gap Matrix

| Architecture Area | Required By Architecture | Current State | Gap | Milestone | Priority | Acceptance Signal |
| --- | --- | --- | --- | --- | --- | --- |
| Project identity | All code, modules, images, charts, subjects use `agentnexus`. | Mostly aligned. | Need scan and enforce naming in remaining generated files. | M1 | P0 | `rg -n "agentatlas|old gateway name|enterprise-admin-gateway" agentnexus` returns no product-name drift outside historical docs. |
| Gateway Agent framework | Gateway Agent uses Google ADK Go v2 Workflow Graph Runtime. | ADK dependency exists; `gateway-agent` only serves dry-run plan. | No ADK workflow graph, no agent run endpoint, no tool execution loop. | M5 | P0 | `POST /v1/agent/runs` creates a persisted task run and executes one ADK tool-backed workflow in tests. |
| Model entry | ADK calls models only through `adk-llmrouter-model`. | `internal/llmroutermodel` exists and integration test is env-gated. | Not wired into running `gateway-agent`; no service config for llmrouter. | M5 | P0 | `gateway-agent` can answer an agent run using `LLMROUTER_BASE_URL`, `LLMROUTER_API_KEY`, and `LLMROUTER_MODEL` without direct vendor SDK usage. |
| Agent Tool Layer | Agent calls internal tools instead of bypassing gateway systems. | Connector validation/smoke handlers exist; no agent tool registry. | No tool catalog, no ADK tool declarations, no MCP tool bridge. | M5 | P0 | Tool registry exposes org preview, connector validate, connector smoke, deployment plan, and audit append as callable ADK tools. |
| MCP / Skill configuration | Tool protocol selected as MCP Go SDK; internal/external tools share semantics. | No MCP server/client registry in `gateway-agent`. | Missing MCP config model, registry, and safe invocation path. | M5 | P1 | `gateway-agent` loads an MCP tool config and lists allowed tools in a test without executing arbitrary code. |
| Task Orchestrator | Business task state is persisted in PostgreSQL and driven by NATS events. | Internal task package, Postgres store, and NATS publisher tests exist. | Real org, connector, receipt, and agent flows do not consistently create durable task runs or domain events yet. | M1/M5 | P0 | Task run create/update/wait states persist across process restart in integration test and are used by at least one real workflow. |
| NATS JetStream | Unified async task, event, connector-agent communication substrate. | Integration tests exist for NATS; compose includes NATS. | Core flows do not publish/consume domain events. | M1/M5/M6 | P1 | Org import preview, connector smoke, and receipt wait emit domain events to configured NATS subjects in tests. |
| PostgreSQL business store | Enterprise, users, org graph, connector config, policies, tickets, audit indexes persisted. | Storage foundations and pgx dependency exist. | Missing migrations and repositories for most business entities. | M1-M4 | P0 | `go test ./internal/storage/...` runs migrations and CRUD tests for enterprise, org, connector, policy, ticket, audit index. |
| OpenFGA | ReBAC for organization and resource visibility. | OpenFGA validation appears in tests/plans; not a required runtime path. | Runtime read/act path does not enforce OpenFGA relations. | M4 | P0 | Runtime API test denies access when OpenFGA relation is absent and allows when relation exists. |
| Policy DSL | Data scope, masking, risk, external receipt, explanation. | Policy DSL foundations exist. | Not fully bound to runtime API, org graph, connector fields, and receipt relay. | M4 | P0 | Runtime read test returns `allow_with_masking`, masked fields, matched rules, and explanation. |
| Access Ticket Service | `case_ticket` and `step_grant` with TTL, revocation, audit, and high-risk DB validation. | Ticket foundations exist; e2e simulation covers parts. | No stable runtime API route and persistent signed ticket lifecycle. | M4 | P0 | `/v1/runtime/read` creates step grant and rejects revoked/expired ticket in integration tests. |
| Gateway Runtime API | Stable API for Claw, AgentRag, business agents: locate/read/act/tickets. | OpenAPI, router handlers, request envelope validation, and M4 authorization loop foundations exist. | Needs stronger persistent ticket/grant backing, real OpenFGA adapter path, and broader fail-closed audit coverage. | M1/M4 | P0 | `POST /v1/runtime/locate`, `/read`, `/act`, and `GET /v1/runtime/tickets/{id}` pass handler and closed-loop e2e tests. |
| Enterprise IAM / Org Graph | Enterprise users, external identities, departments, project groups, org versions. | Confirmed import can persist users, departments, memberships, external identities, org events, and org versions. | Needs conflict workflow depth, project groups, manager relations, and Agent-first orchestration. | M2 | P0 | Confirmed org import writes users/departments/memberships/external identity bindings and returns org_version. |
| Organization import automation | Agent-first natural language import from WeCom/Feishu/DingTalk/OA, preview, conflict detection, confirmation. | Generic OA preview and confirm APIs exist; mock providers and generic vendor HTTP wrappers exist. | No natural-language agent flow, OAuth setup, or full official-vendor API behavior yet. | M2/M5 | P0 | User prompt "import from WeCom" creates org import task, checks auth, fetches source, previews, confirms, persists. |
| WeCom/Feishu/DingTalk organization sources | Built-in organization source adapters using official SDKs/OpenAPI. | Mock providers and normalized vendor HTTP wrappers exist. | Missing official/vendor-specific field mapping, pagination, auth config, rate limits, and real env-gated vendor tests. | M2 | P0 | Env-gated tests fetch at least one department and employee from each configured vendor adapter. |
| Connector Package Manifest | Package manifest validates resources/actions/scopes/schema/tests. | Manifest now supports scopes, input schema, output schema, smoke tests, risk metadata, and rejects executable uploads. | Missing JSON Schema contract file and version promotion lifecycle. | M3 | P0 | JSON Schema validates package manifest including resources, operations, scopes, fields, credentials, and smoke tests. |
| Connector Instance Config | Per-enterprise base_url, account set, field mapping, data scope, credential_ref. | Instance draft/smoke/confirm APIs and Postgres persistence exist; tests prove secret refs persist without secret values. | Needs package/instance version promotion, active version lookup, health events, and richer enterprise isolation checks. | M3 | P0 | Instance config can be drafted, validated, smoke tested, confirmed, and persisted without storing secrets. |
| Connector Runtime safety | Schema validation, masking, rate limit, timeout, retry, audit event for calls. | Runtime validates resource/fields/read-only, resolves credentials, and has schema/masking/rate-limit helpers. | Helpers are not yet a complete execution pipeline; masking is not driven by Policy DSL result; timeout/retry/latency metrics missing. | M3/M4 | P0 | Connector read test validates schema, masks configured fields, writes audit event, and rejects undeclared fields. |
| Connector Agent | Lightweight outbound enterprise-side agent for internal systems. | Registration signing and executor foundations exist. | No full NATS outbound proxy flow or SaaS-to-enterprise request lifecycle. | M7 | P1 | SaaS-side connector read request is delivered to connector-agent over NATS and returns a signed result. |
| Gateway Agent Worker | Long tasks parse attachments, OpenAPI, schema, Excel, images, org docs; generate drafts/tests. | No worker implementation for agent-generated artifacts. | Missing artifact ingestion, parser sidecar integration, draft store, task pipeline. | M5 | P1 | Uploaded OpenAPI fixture produces connector manifest draft and smoke test plan in a persisted artifact. |
| Artifact / Draft Store | Versioned generated drafts with source, input hash, and confirmation record. | Not implemented. | Missing object storage integration and draft metadata tables. | M5 | P1 | Draft records include version, source artifact hash, generated output hash, confirmation status. |
| External Receipt Relay | Locate target in Claw/IM, send receipt, validate source, timeout/remind/revoke. | Minimal receipt model, target resolver, and validation foundations exist. | Missing store, delivery interfaces, callback API, timeout/remind/revoke, and runtime resume. | M6 | P1 | Policy decision requiring receipt creates receipt request and accepts signed callback to release waiting step. |
| Audit Ledger | Append-only audit events, hash chain, queries, export, fail-closed for high risk. | Hash chain foundation exists and e2e verifies it. | Not enforced across every tool, connector, policy, receipt, and agent step. | M4/M6 | P0 | Tests fail high-risk read if audit append fails and verify hash chain across runtime and agent flows. |
| Secret Provider | Vault/K8s Secret/local encrypted provider through abstraction. | Secret resolver interface and fake/dev resolvers exist. | No local encrypted provider, no route/service injection, no rotation story. | M1/M3/M7 | P0 | Gateway API resolves `secret://agentnexus/dev/...` through local encrypted provider in integration test. |
| SaaS/private profiles | Same codebase with profile-specific dependencies and isolation. | Compose and Helm dev skeletons exist. | No production-grade profiles, no tenant isolation enforcement, no secret provider selection. | M7 | P1 | Compose private-dev and Helm render include gateway-api, gateway-agent, connector-worker, connector-agent, postgres, nats, object storage, secret provider config. |
| Observability | Health, metrics, trace_id, task queue, connector latency, audit failures. | Health/ready endpoints exist. | Missing metrics/logging/tracing conventions and dashboards. | M7 | P2 | Integration test sees trace_id propagated from API request to audit event and task run. |
| Admin Console | Claw-runtime-style console with resource map, tickets, connectors, pulse, floating agent. | UI exists and calls console overview API. | Overview data is static dev data; no real task/ticket/org/connector aggregation. | M1-M5 | P1 | Console overview endpoint aggregates persisted org/ticket/connector/task health and frontend renders API source. |

## Milestone Coverage Summary

| Milestone | Architecture Intent | Current Completion | Remaining Risk |
| --- | --- | --- | --- |
| M1: Gateway Skeleton | Entrypoints, runtime API, task/event/store baseline, static admin console API. | Partially complete. Service entrypoints, console API, runtime API skeleton, Postgres task store, NATS publisher, Compose/Helm skeleton exist. | Runtime foundation still needs hardening as stable contract and real workflow event usage. |
| M2: Agent-first Organization Import | Vendor org connectors, natural-language import, preview, confirmation, persistence. | Partially complete. Generic OA HTTP preview, confirm persistence, org graph store/service, mock providers, and vendor HTTP wrappers exist. | Official vendor behavior, OAuth/auth config, conflict workflow depth, and Agent-first flow are missing. |
| M3: Connector Runtime | HTTP/OpenAPI, DB read-only, file adapters, manifest, instance config, smoke. | Partially complete. Manifest metadata, runtime, smoke API, instance lifecycle, and Postgres persistence exist. | Runtime safety pipeline, policy-bound masking, retry/timeout, health, version promotion, and full audit integration are incomplete. |
| M4: Policy / Ticket / Audit Loop | OpenFGA + Policy DSL + ticket/step grant + audit chain. | Partially complete. In-memory OpenFGA-style checks, Policy DSL, ticket/grant foundations, runtime authorization e2e, and fail-closed high-risk audit test exist. | Real OpenFGA service path, persistent ticket/grant lifecycle, receipt resume, and all-flow audit coverage remain. |
| M5: Gateway Agent Assistant | ADK agent with llmrouter, tool registry, document parsing, draft generation. | Mostly incomplete. llmrouter adapter exists but is not wired into agent service. | No ADK workflow, tool layer, MCP, artifact/draft store, or real agent run. |
| M6: External Receipt Relay | Receipt target resolution, IM/Claw relay, callbacks, waiting states. | Not complete. | Entire relay workflow is missing. |
| M7: Private Delivery Package | Compose/Helm, connector-agent, secret provider, profile strategy, ops. | Partially complete. Dev skeleton exists. | Production-grade delivery, secret provider, connector-agent proxy, observability are missing. |

---

## Remaining Execution Spec

This section defines the remaining architecture work. Each milestone should be delivered through small PRs and verified independently.

### M1 Remaining: Gateway Skeleton Completion

**Goal:** Make the skeleton real enough that all later milestones have stable API, persistence, and configuration foundations.

**Files:**

- Modify: `services/agentnexus/internal/config/config.go`
- Create: `services/agentnexus/internal/config/llmrouter.go`
- Create: `services/agentnexus/internal/config/secret_provider.go`
- Create: `services/agentnexus/internal/storage/migrations.go`
- Create: `services/agentnexus/internal/storage/schema/*.sql`
- Create: `services/agentnexus/internal/storage/store.go`
- Create: `services/agentnexus/internal/tasks/postgres_store.go`
- Create: `services/agentnexus/internal/app/runtime_api.go`
- Create: `services/agentnexus/internal/app/runtime_api_test.go`
- Modify: `services/agentnexus/internal/app/gateway_api.go`
- Modify: `services/agentnexus/api/openapi/gateway-runtime.yaml`
- Modify: `services/agentnexus/deploy/compose/compose.private-dev.yaml`
- Modify: `services/agentnexus/deploy/compose/compose.saas-dev.yaml`
- Modify: `services/agentnexus/deploy/helm/agentnexus/values.yaml`

- [ ] Add config structs for PostgreSQL, NATS, object storage, Secret Provider, and llmrouter.
- [ ] Add table migrations for `enterprises`, `enterprise_users`, `task_runs`, `task_steps`, `connector_packages`, `connector_instances`, `case_tickets`, `step_grants`, `audit_events`, and `audit_hash_heads`.
- [ ] Add migration runner invoked by tests, not by service startup.
- [ ] Implement PostgreSQL task store with create, update status, append step, wait checkpoint, and fetch by id.
- [ ] Implement `POST /v1/runtime/locate`, `POST /v1/runtime/read`, `POST /v1/runtime/act`, and `GET /v1/runtime/tickets/{id}` as stable router handlers with request envelope validation.
- [ ] Return clear `400` for missing `enterprise_id`, `actor_user_id`, or `request_id`.
- [ ] Keep runtime handlers initially backed by interfaces so M4 can bind policy/ticket/audit without rewriting routes.
- [ ] Add Compose env for `LLMROUTER_BASE_URL`, `LLMROUTER_MODEL`, `AGENTNEXUS_SECRET_PROVIDER`, and profile-specific service ports.

**Verification:**

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/config ./internal/storage ./internal/tasks ./internal/app -run "TestRuntime|TestTask|TestStorage|TestConfig"
go test ./...
docker compose -f deploy\compose\compose.private-dev.yaml config
```

**Acceptance Criteria:**

- Runtime API routes exist and validate request envelopes.
- Task state can persist and be reloaded from PostgreSQL in an env-gated integration test.
- OpenAPI and handler DTOs use the same field names.
- No model provider key is read by frontend code.

### M2 Remaining: Agent-First Organization Import

**Goal:** Move organization import from generic preview-only dev flow to real persisted org graph with vendor adapters and confirmation.

**Files:**

- Create: `services/agentnexus/internal/connectors/orgsource/wecom_http.go`
- Create: `services/agentnexus/internal/connectors/orgsource/feishu_http.go`
- Create: `services/agentnexus/internal/connectors/orgsource/dingtalk_http.go`
- Create: `services/agentnexus/internal/connectors/orgsource/vendor_config.go`
- Create: `services/agentnexus/internal/connectors/orgsource/vendor_integration_test.go`
- Create: `services/agentnexus/internal/iam/org_graph_store.go`
- Create: `services/agentnexus/internal/iam/org_import_service.go`
- Create: `services/agentnexus/internal/app/org_import_confirm.go`
- Modify: `services/agentnexus/internal/app/org_import_preview.go`
- Modify: `services/agentnexus/internal/app/gateway_api.go`
- Modify: `services/agentnexus/api/openapi/org-import.yaml`

- [ ] Define vendor config structs for WeCom, Feishu, and DingTalk with only credential refs and endpoint/base config.
- [ ] Implement vendor adapters that normalize vendor data into `orgsource.Snapshot`.
- [ ] Keep generic `oa_http` for customers that expose a normalized bridge endpoint.
- [ ] Add env-gated tests for each vendor:
  - `AGENTNEXUS_TEST_WECOM_*`
  - `AGENTNEXUS_TEST_FEISHU_*`
  - `AGENTNEXUS_TEST_DINGTALK_*`
- [ ] Implement `OrgImportService` that writes confirmed departments, employees, memberships, external identity bindings, and `org_version`.
- [ ] Add `POST /api/org/import/confirm` that accepts a preview id or snapshot hash and writes confirmed imports.
- [ ] Reject confirm when preview contains conflicts and no human confirmation id is supplied.
- [ ] Audit preview and confirm actions.

**Verification:**

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/connectors/orgsource
go test ./internal/iam -run TestOrgImport
go test ./internal/app -run TestOrgImport
go test ./tests/integration -run "TestOAOrgSource|TestWeComOrgSource|TestFeishuOrgSource|TestDingTalkOrgSource"
```

**Acceptance Criteria:**

- Mock and generic OA import still pass.
- Confirmed import creates a new org version.
- External identities can store WeCom userId, Feishu open_id, DingTalk unionId, email, phone, and llmrouter user_id.
- Vendor credentials are referenced through `credential_ref` only.

### M3 Remaining: Connector Runtime And Plugin Lifecycle

**Goal:** Make connectors installable as packages and configurable as per-enterprise instances with safe smoke tests.

**Files:**

- Modify: `sdk/go/connector/manifest.go`
- Modify: `sdk/go/connector/validate.go`
- Create: `services/agentnexus/internal/connectors/instance/config.go`
- Create: `services/agentnexus/internal/connectors/instance/store.go`
- Create: `services/agentnexus/internal/connectors/runtime/masking.go`
- Create: `services/agentnexus/internal/connectors/runtime/schema_validation.go`
- Create: `services/agentnexus/internal/connectors/runtime/rate_limit.go`
- Create: `services/agentnexus/internal/app/connector_instances.go`
- Modify: `services/agentnexus/internal/app/connector_plugins.go`
- Modify: `services/agentnexus/api/openapi/connector-plugins.yaml`

- [ ] Extend manifest schema with scopes, input schema, output schema, smoke test declarations, and risk metadata.
- [ ] Add connector instance config containing `enterprise_id`, `package_name`, `base_url`, account set, field mapping, data scope, and credential refs.
- [ ] Add `POST /api/connectors/instances/draft`.
- [ ] Add `POST /api/connectors/instances/{id}:smoke`.
- [ ] Add `POST /api/connectors/instances/{id}:confirm`.
- [ ] Ensure smoke can run without persisting secrets and without executable code upload.
- [ ] Add masking pipeline based on manifest and policy result.
- [ ] Add runtime audit event interface and emit audit entries for connector calls.

**Verification:**

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./sdk/go/connector/...
go test ./internal/connectors/...
go test ./internal/app -run "TestConnectorPackage|TestConnectorInstance"
go test ./tests/e2e -run TestMVPOrgImportAndAccess
```

**Acceptance Criteria:**

- Manifest validation rejects duplicate fields, undeclared operations, missing schemas for high-risk resources, and executable-code upload.
- Instance config persists only credential refs, not secret values.
- Smoke response reports adapter, resource, operation, credential resolved, schema valid, masking valid, and audit event id.

### M4 Remaining: Policy, Ticket, OpenFGA, Audit Closed Loop

**Goal:** Make runtime access impossible without identity, OpenFGA relation check, Policy DSL decision, ticket/grant, and audit.

**Files:**

- Create: `services/agentnexus/internal/authorization/openfga_client.go`
- Create: `services/agentnexus/internal/authorization/authorizer.go`
- Modify: `services/agentnexus/internal/policy/evaluator.go`
- Modify: `services/agentnexus/internal/tickets/case_ticket.go`
- Modify: `services/agentnexus/internal/tickets/step_grant.go`
- Modify: `services/agentnexus/internal/audit/event.go`
- Modify: `services/agentnexus/internal/audit/hash_chain.go`
- Modify: `services/agentnexus/internal/app/runtime_api.go`
- Create: `services/agentnexus/tests/e2e/runtime_policy_ticket_audit_test.go`

- [ ] Add authorization interface with OpenFGA-backed implementation and in-memory test implementation.
- [ ] Bind runtime locate/read/act to `enterprise_id`, `actor_user_id`, and `request_id`.
- [ ] Create `case_ticket` on locate and `step_grant` on read/act.
- [ ] Evaluate Policy DSL after OpenFGA allows relation visibility.
- [ ] Implement decisions: `allow`, `deny`, `need_external_receipt`, `allow_with_masking`.
- [ ] Apply masking before returning connector data.
- [ ] Append audit events for locate, read, act, deny, masking, receipt-wait, and connector call.
- [ ] Fail closed when audit append fails for high-risk read/act.

**Verification:**

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/authorization ./internal/policy ./internal/tickets ./internal/audit ./internal/app
go test ./tests/e2e -run TestRuntimePolicyTicketAudit
```

**Acceptance Criteria:**

- Runtime read without relation is denied.
- Runtime read with relation and policy allow returns data.
- Runtime read with policy masking returns masked data and masking audit.
- High-risk action requiring receipt returns waiting state.
- Hash chain verifies across all runtime events.

### M5 Remaining: Gateway Agent Assistant, Tool Registry, MCP, Drafts

**Goal:** Turn `gateway-agent` from a dry-run endpoint into an Agent-first control plane that can plan and execute safe tool-backed workflows.

**Files:**

- Modify: `services/agentnexus/cmd/gateway-agent/main.go`
- Modify: `services/agentnexus/internal/app/gateway_agent_router.go`
- Create: `services/agentnexus/internal/agent/runtime.go`
- Create: `services/agentnexus/internal/agent/workflows.go`
- Create: `services/agentnexus/internal/agent/tools/registry.go`
- Create: `services/agentnexus/internal/agent/tools/org_import.go`
- Create: `services/agentnexus/internal/agent/tools/connector_draft.go`
- Create: `services/agentnexus/internal/agent/tools/deployment_plan.go`
- Create: `services/agentnexus/internal/agent/mcp/config.go`
- Create: `services/agentnexus/internal/artifacts/store.go`
- Create: `services/agentnexus/internal/artifacts/draft.go`
- Modify: `services/agentnexus/api/openapi/gateway-agent.yaml`

- [ ] Add `POST /v1/agent/runs`.
- [ ] Add `POST /v1/agent/runs/{id}/messages`.
- [ ] Add `POST /v1/agent/runs/{id}/confirmations`.
- [ ] Load llmrouter config from environment and Secret Provider.
- [ ] Instantiate `llmroutermodel.New` only inside gateway-agent runtime.
- [ ] Register internal tools for org preview, connector validate, connector smoke, deployment plan, audit append, and confirmation wait.
- [ ] Add MCP config loader that allows only declared local or remote MCP tools.
- [ ] Persist agent run state and tool-call audit events.
- [ ] Add draft store for connector manifests, instance configs, policy drafts, and org import drafts.
- [ ] Require confirmation before persisting org import, publishing connector instance, enabling write operation, or applying deployment actions.

**Verification:**

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/agent/...
go test ./internal/app -run TestGatewayAgent
go test ./tests/integration -run TestLLMRouterModelIntegration
go build ./cmd/gateway-agent
```

**Acceptance Criteria:**

- A test agent run can choose the org preview tool and return a preview result.
- Tool calls are audited.
- MCP config with an undeclared tool is rejected.
- Model vendor access is only through `internal/llmroutermodel`.
- Frontend Agent panel can submit a message and receive run status from backend.

### M6 Remaining: External Receipt Relay

**Goal:** Support policy-driven external approval/receipt flows through Claw and enterprise IM targets.

**Files:**

- Create: `services/agentnexus/internal/receipts/relay.go`
- Create: `services/agentnexus/internal/receipts/target_resolver.go`
- Create: `services/agentnexus/internal/receipts/callbacks.go`
- Create: `services/agentnexus/internal/receipts/store.go`
- Create: `services/agentnexus/internal/app/receipt_api.go`
- Modify: `services/agentnexus/internal/app/gateway_api.go`
- Modify: `services/agentnexus/api/openapi/gateway-runtime.yaml`
- Create: `services/agentnexus/tests/e2e/external_receipt_relay_test.go`

- [ ] Add receipt request table and status lifecycle: created, sent, approved, denied, narrowed, instructed, expired, revoked.
- [ ] Implement target resolver priority:
  1. Data source or external approval system target.
  2. Connector instance `receipt_target`.
  3. Policy DSL org relation target.
  4. Gateway Agent asks user to choose.
- [ ] Add Claw delivery interface and IM delivery interface.
- [ ] Add vendor delivery adapters as interfaces with fake implementations in open-core tests.
- [ ] Add callback endpoint that validates receipt source and request id.
- [ ] Resume waiting runtime step when callback approves or narrows access.
- [ ] Audit send, callback, timeout, denial, and resume.

**Verification:**

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/receipts ./internal/app
go test ./tests/e2e -run TestExternalReceiptRelay
```

**Acceptance Criteria:**

- Policy decision `need_external_receipt` creates a receipt request.
- Fake IM adapter receives a message payload with no raw secret values.
- Callback approval releases a waiting step grant.
- Callback denial blocks the runtime action.
- Timeout leaves an auditable expired state.

### M7 Remaining: Private Delivery Package And Operations

**Goal:** Make open-core deployable as a credible dev/private baseline while keeping commercial production controls outside the repo.

**Files:**

- Modify: `services/agentnexus/deploy/compose/compose.private-dev.yaml`
- Modify: `services/agentnexus/deploy/compose/compose.saas-dev.yaml`
- Modify: `services/agentnexus/deploy/helm/agentnexus/values.yaml`
- Modify: `services/agentnexus/deploy/helm/agentnexus/templates/*.yaml`
- Create: `services/agentnexus/internal/secrets/provider.go`
- Create: `services/agentnexus/internal/secrets/local_encrypted.go`
- Create: `services/agentnexus/internal/secrets/k8s_secret.go`
- Create: `services/agentnexus/internal/observability/logging.go`
- Create: `services/agentnexus/internal/observability/metrics.go`
- Modify: `services/agentnexus/cmd/connector-agent/main.go`
- Create: `services/agentnexus/docs/private-dev-deployment.md`

- [ ] Add local encrypted Secret Provider for private-dev.
- [ ] Add K8s Secret Provider adapter behind the same interface.
- [ ] Wire gateway-api, gateway-agent, connector-worker, and connector-agent to Secret Provider config.
- [ ] Add Helm values for gateway-agent port, secret provider mode, llmrouter config refs, NATS, PostgreSQL, object storage, and connector-agent.
- [ ] Add connector-agent outbound NATS connection lifecycle and signed registration flow.
- [ ] Add structured logs with `trace_id`, `enterprise_id`, `request_id`, and task id.
- [ ] Add basic metrics for request count, connector latency, task duration, receipt wait count, and audit append failures.
- [ ] Document private-dev deployment and real credential injection without committing secrets.

**Verification:**

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/secrets ./internal/observability ./internal/connectors/agent
go build ./cmd/gateway-api ./cmd/gateway-agent ./cmd/connector-worker ./cmd/connector-agent
docker compose -f deploy\compose\compose.private-dev.yaml config
helm template agentnexus .\deploy\helm\agentnexus
```

**Acceptance Criteria:**

- Compose and Helm render all four services plus dependencies.
- No service requires raw API keys in frontend code.
- Secret refs resolve through provider abstraction in integration tests.
- Connector-agent can register and reject unknown connector instances.
- Metrics and logs include traceable request/task context.

---

## Cross-Cutting Rules For All Remaining Work

- [ ] Do not store raw customer credentials, API keys, tokens, or private endpoints in the repo.
- [ ] Do not add customer-specific field mapping to open-core. Use generic adapters, official vendor adapters, or extension points.
- [ ] Do not allow executable connector code upload in open-core.
- [ ] Do not let Gateway Agent bypass Policy Engine, Ticket Service, Secret Provider, or Audit Ledger.
- [ ] Do not let frontend read model API keys or enterprise system credentials.
- [ ] Do not publish production config automatically; high-risk changes require human confirmation.
- [ ] Keep enterprise-only license enforcement, customer templates, commercial connectors, and production private deployment controls outside `agentnexus`.

## Recommended PR Order

1. Rebaseline contracts and drift scan against the current commit chain through `5908a4c`.
2. M1 runtime foundation hardening.
3. M4 runtime authorization closed loop.
4. M2 vendor OA import completion.
5. M3 connector runtime safety completion.
6. M5 gateway-agent ADK runtime and internal tool registry.
7. M5 MCP config and artifact/draft store.
8. M6 external receipt relay.
9. M7 private-dev secret provider, connector-agent proxy, Helm/Compose hardening, observability.
10. Frontend live integration and browser automation.

## Final Architecture Verification Checklist

- [ ] `go test ./...`
- [ ] `go test ./tests/e2e/...`
- [ ] Env-gated tests pass when PostgreSQL, NATS, OpenFGA, llmrouter, and optional OA vendor credentials are configured.
- [ ] `go build ./cmd/gateway-api ./cmd/gateway-agent ./cmd/connector-worker ./cmd/connector-agent`
- [ ] `docker compose -f services\agentnexus\deploy\compose\compose.private-dev.yaml config`
- [ ] `helm template agentnexus services\agentnexus\deploy\helm\agentnexus`
- [ ] `npm test --workspace packages/enterprise-gateway-console`
- [ ] `npm run build --workspace packages/enterprise-gateway-console`
- [ ] Browser automation verifies console loads from `gateway-api`, not fallback data.
- [ ] Browser automation verifies Gateway Agent panel submits a real run and receives backend run status.
- [ ] Secret scan confirms no raw keys, tokens, customer endpoints, or private customer names.

## Explicit Scope Boundary

This document does not mean all M1-M7 work should be merged in one PR. It is a tracking and execution spec. Each milestone above should be split into PR-sized tasks with failing tests first, implementation second, verification third, and a short PR summary that maps back to this document.
