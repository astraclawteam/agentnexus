# AgentNexus Week-One Next Step Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this spec task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In one engineering week, move AgentNexus from open-core MVP simulation to three verifiable dev flows: OA organization import preview, connector/plugin smoke verification, and Gateway Agent first-deployment dry run.

**Architecture:** Keep this in open-core and avoid customer-specific logic. Add small HTTP/API surfaces and env-gated integration tests around the existing org source, connector runtime, task orchestrator, and dev deployment profiles. Real credentials, customer overlays, production private deployment automation, and commercial adapters remain out of this repository.

**Tech Stack:** Go 1.25, stdlib HTTP router currently used by `gateway-api`, existing connector SDK/manifest runtime, YAML/JSON fixtures, Docker Compose dev profiles, React console only for status visibility when needed.

---

## Current Baseline

Merged GitHub `main` is at `259fc39 Implement goal mode foundation (#2)`.

Already working:

- Admin console can call `GET /api/console/overview` from `gateway-api`.
- Organization import domain exists through `orgsource.Provider`, `Snapshot`, `PreviewImport`, and mock WeCom/Feishu/DingTalk providers.
- Connector manifest validation and runtime execution exist for file/db/http-openapi style resources.
- Connector Agent has registration signing and an executor that rejects unknown instances and dynamic code.
- MVP e2e simulation passes with fixture-based org import, policy, ticket, connector read, and audit hash-chain verification.
- Dev deployment profiles exist for Docker Compose and Helm skeleton validation.

Known gaps:

- No real OA HTTP provider is implemented yet. Current org source providers are mocks.
- No connector package/instance API exists for installing or smoke-testing plugins through `gateway-api`.
- `gateway-agent` still only prints health and exits; no Agent-run HTTP service drives deployment.
- Production deployment automation is intentionally out of open-core scope.

## One-Week Scope

This week should produce testable dev workflows, not production hardening.

In scope:

- Generic read-only OA HTTP organization provider with local `httptest` coverage and env-gated real OA integration test.
- Minimal connector/plugin verification API: validate manifest, create in-memory instance, run smoke read.
- Gateway Agent first-deployment dry-run: generate a deployment plan, validate compose config, create task steps, require human confirmation before any future execution.
- Documentation for how to run the three verifications.

Out of scope:

- Customer-specific OA field mapping.
- Secrets committed to repo.
- Full plugin marketplace, version promotion, billing, license checks, or enterprise-only connector implementations.
- Real production deployment execution.
- Kubernetes production ingress/network policy/secret manager automation.

## Success Criteria

By the end of the week:

- A developer can run an OA mock server test and see departments/employees imported into a preview.
- If real OA env vars are provided, an env-gated test can fetch organization data from that OA without storing credentials in the repo.
- A developer can submit a connector manifest to an API and receive validation/smoke status.
- A developer can trigger a Gateway Agent deployment dry-run and receive a plan that references the dev compose profile and required confirmations.
- The following commands pass:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./...
docker compose -f deploy\compose\compose.private-dev.yaml config

cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console
npm run build --workspace packages/enterprise-gateway-console
```

## File Ownership Map

Expected new or modified files:

- `services/agentnexus/internal/connectors/orgsource/oa_http.go`: generic OA HTTP provider.
- `services/agentnexus/internal/connectors/orgsource/oa_http_test.go`: local mock-server tests.
- `services/agentnexus/tests/integration/oa_org_source_test.go`: env-gated real OA integration test.
- `services/agentnexus/tests/fixtures/org_import/oa_http_org_sample.json`: mock OA fixture.
- `services/agentnexus/internal/app/connector_plugins.go`: connector package/instance verification handlers and DTOs.
- `services/agentnexus/internal/app/connector_plugins_test.go`: API tests for manifest validation and smoke execution.
- `services/agentnexus/api/openapi/connector-plugins.yaml`: public open-core contract for plugin verification.
- `services/agentnexus/internal/app/deployment_plan.go`: deployment dry-run planner.
- `services/agentnexus/internal/app/deployment_plan_test.go`: deployment planner tests.
- `services/agentnexus/internal/app/gateway_agent_router.go`: minimal Gateway Agent HTTP router for dry-run endpoint, if implemented in `gateway-agent`.
- `services/agentnexus/cmd/gateway-agent/main.go`: run HTTP server instead of print-and-exit.
- `services/agentnexus/api/openapi/gateway-agent.yaml`: add deployment dry-run operation if needed.
- `services/agentnexus/docs/week-one-verification.md`: operator/dev verification guide.

## Task 1: OA HTTP Organization Provider

**Purpose:** Enable dev testing against a generic OA-compatible HTTP source without adding customer-specific code.

**Files:**

- Create: `services/agentnexus/internal/connectors/orgsource/oa_http.go`
- Create: `services/agentnexus/internal/connectors/orgsource/oa_http_test.go`
- Create: `services/agentnexus/tests/fixtures/org_import/oa_http_org_sample.json`
- Create: `services/agentnexus/tests/integration/oa_org_source_test.go`

- [ ] Write a failing unit test in `oa_http_test.go` using `httptest.Server`.

Expected test behavior:

```go
provider := NewOAHTTPProvider(OAHTTPConfig{
	BaseURL: server.URL,
	DepartmentsPath: "/departments",
	EmployeesPath: "/employees",
	Token: "test-token",
})
snapshot, err := provider.Fetch(context.Background())
```

Assert:

- request includes `Authorization: Bearer test-token`
- `snapshot.Departments` has at least one department
- `snapshot.Employees` has at least one employee
- duplicate department IDs on employees are normalized through existing `NormalizeSnapshot`

- [ ] Run the test and verify it fails because `NewOAHTTPProvider` is undefined.

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/connectors/orgsource -run TestOAHTTPProvider
```

- [ ] Implement `OAHTTPProvider` with conservative input shape:

```json
{
  "departments": [
    {"id": "dept_rd", "parent_id": "", "name": "R&D", "manager_employee_id": "user_ada"}
  ],
  "employees": [
    {"id": "user_ada", "display_name": "Ada", "email": "ada@example.test", "phone": "", "manager_employee_id": "", "department_ids": ["dept_rd"]}
  ],
  "memberships": [
    {"employee_id": "user_ada", "department_id": "dept_rd", "role": "manager"}
  ]
}
```

Mapping should remain generic. Do not hard-code real OA vendor fields in open-core.

- [ ] Add env-gated integration test `tests/integration/oa_org_source_test.go`.

Required env vars:

- `AGENTNEXUS_TEST_OA_BASE_URL`
- `AGENTNEXUS_TEST_OA_TOKEN`
- `AGENTNEXUS_TEST_OA_DEPARTMENTS_PATH`
- `AGENTNEXUS_TEST_OA_EMPLOYEES_PATH`

If any are missing, skip with a clear message.

- [ ] Verify:

```powershell
go test ./internal/connectors/orgsource
go test ./tests/integration -run TestOAOrgSource
```

Expected: unit test passes; integration test passes when env is set, skips when env is missing.

## Task 2: Organization Import Preview API

**Purpose:** Let testers call the OA provider through a stable local API instead of only Go tests.

**Files:**

- Modify: `services/agentnexus/internal/app/gateway_api.go`
- Create: `services/agentnexus/internal/app/org_import_preview.go`
- Create: `services/agentnexus/internal/app/org_import_preview_test.go`
- Create: `services/agentnexus/api/openapi/org-import.yaml`

- [ ] Write failing API test for `POST /api/org/import/preview`.

Request body:

```json
{
  "provider": "oa_http",
  "base_url": "http://127.0.0.1:18080",
  "departments_path": "/departments",
  "employees_path": "/employees",
  "token_ref": "secret://agentnexus/dev/oa-token"
}
```

In unit tests, use a fake secret resolver returning `test-token`.

Expected response:

```json
{
  "provider": "oa_http",
  "requires_confirmation": false,
  "auto_importable_employee_ids": ["user_ada"],
  "conflicts": []
}
```

- [ ] Implement handler using existing `app.BuildOrgImportPreview`.

Do not persist imported employees in this task. This endpoint is preview-only.

- [ ] Add OpenAPI contract with explicit note: preview-only, no credentials in request body except `token_ref`.

- [ ] Verify:

```powershell
go test ./internal/app -run TestOrgImportPreview
```

## Task 3: Connector Plugin Verification API

**Purpose:** Make the plugin/connector system verifiable through `gateway-api`.

**Files:**

- Create: `services/agentnexus/internal/app/connector_plugins.go`
- Create: `services/agentnexus/internal/app/connector_plugins_test.go`
- Modify: `services/agentnexus/internal/app/gateway_api.go`
- Create: `services/agentnexus/api/openapi/connector-plugins.yaml`

- [ ] Write failing test for `POST /api/connectors/packages/validate`.

Input: connector manifest JSON/YAML equivalent to `tests/fixtures/connectors/file_storage_manifest.yaml`.

Expected:

```json
{
  "valid": true,
  "name": "file-storage-demo",
  "resources": ["legal_contracts"]
}
```

- [ ] Write failing test for `POST /api/connectors/instances/smoke`.

Input:

```json
{
  "connector_instance_id": "connector_file_storage_1",
  "manifest": { "...": "..." },
  "resource": "legal_contracts",
  "operation": "read",
  "fields": ["title", "body", "owner_email"],
  "credential_ref": "secret://agentnexus/dev/file-storage"
}
```

Expected:

```json
{
  "ok": true,
  "adapter": "file_storage",
  "credential_resolved": true
}
```

- [ ] Implement handlers using existing `manifest.Validate` and `connectorruntime.New`.

Use an in-memory dev secret resolver only for smoke tests. Do not expose secret values in responses.

- [ ] Verify:

```powershell
go test ./internal/app -run TestConnectorPlugin
go test ./internal/connectors/...
```

## Task 4: Gateway Agent First-Deployment Dry Run

**Purpose:** Verify the Agent can plan a first deployment without performing unsafe production actions.

**Files:**

- Create: `services/agentnexus/internal/app/deployment_plan.go`
- Create: `services/agentnexus/internal/app/deployment_plan_test.go`
- Create or modify: `services/agentnexus/internal/app/gateway_agent_router.go`
- Modify: `services/agentnexus/cmd/gateway-agent/main.go`
- Modify: `services/agentnexus/api/openapi/gateway-agent.yaml`

- [ ] Write failing planner test for private-dev compose profile.

Input:

```go
input := FirstDeploymentPlanInput{
  Profile: "private-dev",
  ComposeFile: "deploy/compose/compose.private-dev.yaml",
}
```

Expected plan includes:

- `validate_compose_config`
- `start_gateway_api`
- `start_gateway_agent`
- `start_connector_worker`
- `verify_console_overview_api`
- `human_confirmation_before_apply`

- [ ] Implement `BuildFirstDeploymentPlan`.

It must only build a plan. It must not run Docker, Helm, shell commands, or mutate files.

- [ ] Add HTTP endpoint to Gateway Agent:

`POST /v1/agent/deployments/first-run:plan`

Expected response:

```json
{
  "profile": "private-dev",
  "mode": "dry_run",
  "steps": [
    {"name": "validate_compose_config", "command": "docker compose -f deploy/compose/compose.private-dev.yaml config"}
  ],
  "requires_confirmation": true
}
```

- [ ] Modify `cmd/gateway-agent/main.go` to start HTTP server on `AGENTNEXUS_HTTP_ADDR`, matching `gateway-api` style.

- [ ] Verify:

```powershell
go test ./internal/app -run TestFirstDeploymentPlan
go build ./cmd/gateway-agent
```

## Task 5: End-To-End Dev Verification Script Documentation

**Purpose:** Give the team one clear runbook for the next review.

**Files:**

- Create: `services/agentnexus/docs/week-one-verification.md`
- Modify: `services/agentnexus/README.md`

- [ ] Document OA mock verification:

```powershell
go test ./internal/connectors/orgsource -run TestOAHTTPProvider
go test ./internal/app -run TestOrgImportPreview
```

- [ ] Document optional real OA verification with env vars.

Do not include real URLs, tokens, screenshots, or customer names.

- [ ] Document plugin verification:

```powershell
go test ./internal/app -run TestConnectorPlugin
go test ./internal/connectors/...
```

- [ ] Document Agent deployment dry-run:

```powershell
go test ./internal/app -run TestFirstDeploymentPlan
docker compose -f deploy/compose/compose.private-dev.yaml config
```

- [ ] Add a README link to the week-one verification guide.

## Day-by-Day Execution Plan

Day 1:

- Finish Task 1 unit provider.
- Confirm OA fixture and normalization behavior.

Day 2:

- Finish Task 1 env-gated real OA test.
- Finish Task 2 preview API.

Day 3:

- Finish Task 3 connector package validation and smoke API.
- Keep persistence out unless absolutely necessary.

Day 4:

- Finish Task 4 deployment dry-run planner and Gateway Agent route.
- Validate `gateway-agent` can stay running as an HTTP service.

Day 5:

- Finish Task 5 runbook.
- Run full verification.
- Browser-check console only if API output affects the frontend.
- Open PR with one-week scope summary.

## Final Verification Checklist

- [ ] `go test ./...`
- [ ] `go build ./cmd/gateway-api ./cmd/gateway-agent ./cmd/connector-worker ./cmd/connector-agent`
- [ ] `docker compose -f services\agentnexus\deploy\compose\compose.private-dev.yaml config`
- [ ] `npm test --workspace packages/enterprise-gateway-console`
- [ ] `npm run build --workspace packages/enterprise-gateway-console`
- [ ] Run a placeholder and secret scan across `services\agentnexus` and `docs`; investigate any placeholder markers, customer names, passwords, or token literals before opening the PR.

## Decision Boundaries

Escalate before implementing if:

- A real OA requires customer-specific field mappings.
- A connector needs executable code upload.
- A deployment step would execute Docker/Helm automatically instead of returning a dry-run plan.
- A test requires storing real credentials or private endpoints in the repository.

## Expected PR Summary

The PR should say:

- Adds generic OA HTTP organization source provider and preview API.
- Adds connector/plugin manifest validation and smoke verification API.
- Adds Gateway Agent first-deployment dry-run planning endpoint.
- Adds week-one verification runbook.
- Keeps real credentials, production deployment, and customer-specific adapters out of open-core.
