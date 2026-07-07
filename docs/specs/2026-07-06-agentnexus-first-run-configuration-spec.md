# AgentNexus First-Run Configuration Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this spec task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the current development console from a static open-core overview into a verifiable first-run setup flow that lets a real operator configure an enterprise, secret references, OA organization import, connector smoke, and Gateway Agent deployment dry-run without touching mock data.

**Architecture:** First-run setup must orchestrate existing backend primitives instead of duplicating domain logic in the frontend. Raw API keys and tokens must never be stored in React state beyond form entry, persisted in the repository, or returned by APIs; the UI stores and submits secret references only. The console overview must stop pretending development fixture data is live data and must render setup status until persisted enterprise data exists.

**Tech Stack:** Go 1.25, stdlib HTTP router in `gateway-api`, existing `internal/secrets`, `orgsource`, IAM org graph, connector manifest/runtime/instance services, `gateway-agent` HTTP API, React + TypeScript + Vite console, Vitest, Docker Compose private-dev profile.

---

## Current Verified Problem

Browser and API validation on 2026-07-06 showed:

- `gateway-api:8080` and `gateway-agent:8081` can run from current code.
- `POST /api/connectors/packages/validate` works.
- `POST /v1/agent/deployments/first-run:plan` works.
- `POST /v1/agent/runs` returns an allow-listed internal tool catalog.
- `GET /api/console/overview` still returns static development data from `NewConsoleOverview`.
- The console page still displays `示例企业（Gateway API）` and `不包含真实客户数据`.
- The UI has no visible first-run, API key, enterprise secret, WeCom, DingTalk, Feishu, or MCP configuration entry.
- `同步组织`, `导出审计`, `过滤`, and `Smoke` are visual buttons only and do not trigger backend workflows.
- The floating Gateway Agent chat only records a local message and does not call `gateway-agent`.

This spec fixes that product gap. It does not attempt to finish the entire M1-M7 architecture.

## User Outcome

A normal first-time operator must be able to:

1. Open `http://127.0.0.1:5173/`.
2. See that no enterprise is configured yet.
3. Create or select an enterprise context.
4. Configure secret references for model/API/OA/connector credentials without pasting secrets into source code.
5. Choose an organization source: generic OA HTTP, WeCom, DingTalk, or Feishu.
6. Run organization import preview.
7. Confirm import and see real imported org counts in the dashboard.
8. Validate and smoke-test at least one connector manifest.
9. Run the Gateway Agent first-deployment dry-run plan.
10. Use the floating Agent panel to create a persisted agent run instead of a local-only chat entry.

## Out Of Scope

- Production OAuth approval screens for WeCom, DingTalk, or Feishu.
- Storing raw customer tokens in the database.
- Building a full connector marketplace.
- Direct Docker/Helm apply from the browser.
- Full MCP remote tool execution. This spec only requires showing and validating an allow-listed MCP/tool configuration shape.
- Commercial/customer-specific adapters.

## First-Run UX Contract

The console must use this state model:

| State | UI Behavior | Data Source |
| --- | --- | --- |
| `unconfigured` | Show first-run setup as the primary screen. Do not show fake enterprise metrics as if they were real. | `GET /api/setup/status` |
| `configured_without_org` | Show setup progress and prompt for org import preview. Dashboard metrics stay empty or zero. | Setup API + org graph |
| `org_preview_ready` | Show preview counts, conflicts, and confirmation action. | `POST /api/org/import/preview` |
| `configured` | Show real overview aggregated from persisted org graph, connector instances, tickets, receipts, and audit summaries. | `GET /api/console/overview` |
| `api_unavailable` | Show local development fixture warning and retry action. | Frontend fallback only |

The UI may keep an explicit demo mode, but demo mode must be visibly labeled `Demo fixture` and must not be the default when `gateway-api` is reachable.

## API Contract

### `GET /api/setup/status`

Returns first-run state and safe configuration metadata.

Example response:

```json
{
  "state": "unconfigured",
  "enterprise_id": "",
  "enterprise_name": "",
  "admin_user_id": "",
  "secret_provider": {
    "mode": "env",
    "writable": false,
    "accepted_ref_prefixes": ["secret://env/"]
  },
  "services": {
    "gateway_api": "ready",
    "gateway_agent": "unknown",
    "postgres": "not_configured",
    "nats": "not_configured"
  },
  "next_required_actions": [
    "create_enterprise",
    "configure_secret_refs",
    "import_org"
  ]
}
```

### `POST /api/setup/enterprise`

Creates or updates the local first-run enterprise context.

Request:

```json
{
  "enterprise_id": "ent_dev",
  "enterprise_name": "Local Development Enterprise",
  "admin_user_id": "admin_dev",
  "environment_label": "private-dev"
}
```

Response:

```json
{
  "enterprise_id": "ent_dev",
  "enterprise_name": "Local Development Enterprise",
  "state": "configured_without_org"
}
```

### `POST /api/setup/secrets/validate`

Validates that configured secret references can be resolved by the active provider. It must not return secret values.

Request:

```json
{
  "refs": {
    "llmrouter_api_key": "secret://env/LLMROUTER_API_KEY",
    "oa_token": "secret://env/AGENTNEXUS_OA_TOKEN",
    "file_storage": "secret://env/AGENTNEXUS_FILE_STORAGE_TOKEN"
  }
}
```

Response:

```json
{
  "valid": true,
  "results": {
    "llmrouter_api_key": {"resolved": true},
    "oa_token": {"resolved": true},
    "file_storage": {"resolved": false, "error": "secret env is not set"}
  }
}
```

### `POST /api/org/import/preview`

Keep the existing endpoint, but make it usable from setup.

Required behavior:

- Accept `provider` values: `oa_http`, `wecom`, `feishu`, `dingtalk`.
- Accept `token_ref` or `credential_ref`, never raw token.
- Return `snapshot_hash`, counts, conflicts, and confirmation readiness.
- For vendor providers, use normalized vendor HTTP bridge config until official vendor adapters are implemented.

Example request:

```json
{
  "provider": "oa_http",
  "base_url": "http://127.0.0.1:18080",
  "departments_path": "/departments",
  "employees_path": "/employees",
  "token_ref": "secret://env/AGENTNEXUS_OA_TOKEN",
  "enterprise_id": "ent_dev"
}
```

Example response:

```json
{
  "provider": "oa_http",
  "snapshot_hash": "sha256:...",
  "department_count": 2,
  "employee_count": 3,
  "membership_count": 3,
  "requires_confirmation": false,
  "auto_importable_employee_ids": ["user_ada"],
  "conflicts": []
}
```

### `POST /api/org/import/confirm`

Keep existing confirm behavior, but require first-run context.

Request must include:

```json
{
  "enterprise_id": "ent_dev",
  "provider": "oa_http",
  "snapshot_hash": "sha256:...",
  "human_confirmation_id": "confirm_first_org_import"
}
```

Response must include:

```json
{
  "enterprise_id": "ent_dev",
  "org_version": "orgv_...",
  "department_count": 2,
  "employee_count": 3,
  "membership_count": 3
}
```

### `GET /api/console/overview?enterprise_id=ent_dev`

Replace static `NewConsoleOverview` as the default path.

Required behavior:

- If no enterprise exists, return `state: "unconfigured"` and zero metrics.
- If enterprise exists but org graph is empty, return `state: "configured_without_org"` and zero org metrics.
- If data exists, aggregate from real stores/services.
- Include `source.kind = "api_live"` for real aggregation.
- Use `source.kind = "development_fixture"` only when explicitly requested with `?demo=true`.

### `POST /v1/agent/runs`

Already exists in `gateway-agent`; frontend must call it.

First-run UI request:

```json
{
  "enterprise_id": "ent_dev",
  "actor_user_id": "admin_dev",
  "request_id": "setup-run-...",
  "trace_id": "setup-trace-...",
  "goal": "Configure first-run enterprise setup"
}
```

The UI must display returned `tools` and `status`.

## File Ownership Map

Expected new or modified files:

- Create: `services/agentnexus/internal/app/setup_status.go`
- Create: `services/agentnexus/internal/app/setup_status_test.go`
- Create: `services/agentnexus/internal/app/setup_secrets.go`
- Create: `services/agentnexus/internal/app/setup_secrets_test.go`
- Modify: `services/agentnexus/internal/app/gateway_api.go`
- Modify: `services/agentnexus/internal/app/org_import_preview.go`
- Modify: `services/agentnexus/internal/app/org_import_confirm.go`
- Modify: `services/agentnexus/internal/app/console_overview.go`
- Modify: `services/agentnexus/cmd/gateway-api/main.go`
- Modify: `services/agentnexus/internal/secrets/provider.go`
- Create: `services/agentnexus/api/openapi/setup.yaml`
- Modify: `services/agentnexus/api/openapi/org-import.yaml`
- Modify: `packages/enterprise-gateway-console/src/console-data.ts`
- Create: `packages/enterprise-gateway-console/src/setup-api.ts`
- Create: `packages/enterprise-gateway-console/src/FirstRunSetup.tsx`
- Create: `packages/enterprise-gateway-console/src/FirstRunSetup.test.tsx`
- Modify: `packages/enterprise-gateway-console/src/AgentNexusDashboard.tsx`
- Modify: `packages/enterprise-gateway-console/src/GatewayAgentLauncher.tsx`
- Modify: `packages/enterprise-gateway-console/src/ConnectorHealth.tsx`
- Modify: `packages/enterprise-gateway-console/src/AccessTicketsTable.tsx`
- Modify: `packages/enterprise-gateway-console/src/AgentNexusDashboard.test.tsx`
- Modify: `services/agentnexus/docs/week-one-verification.md`
- Create: `services/agentnexus/docs/first-run-configuration.md`

## Task 1: Secret Provider Injection And Setup Status API

**Purpose:** Make first-run setup able to validate secret refs and report whether the backend is ready for real configuration.

**Files:**

- Modify: `services/agentnexus/internal/secrets/provider.go`
- Create: `services/agentnexus/internal/app/setup_status.go`
- Create: `services/agentnexus/internal/app/setup_status_test.go`
- Create: `services/agentnexus/internal/app/setup_secrets.go`
- Create: `services/agentnexus/internal/app/setup_secrets_test.go`
- Modify: `services/agentnexus/internal/app/gateway_api.go`
- Modify: `services/agentnexus/cmd/gateway-api/main.go`

- [ ] Write `TestSetupStatusUnconfigured` for `GET /api/setup/status`.
- [ ] Expected response has `state: "unconfigured"`, accepted secret prefix `secret://env/`, and `create_enterprise` in `next_required_actions`.
- [ ] Write `TestSetupSecretsValidateDoesNotLeakValues`.
- [ ] Set `AGENTNEXUS_TEST_SECRET_VALUE=super-secret-value` in test only.
- [ ] Validate `secret://env/AGENTNEXUS_TEST_SECRET_VALUE`.
- [ ] Assert response contains `"resolved":true` and does not contain `super-secret-value`.
- [ ] Implement setup status handler.
- [ ] Implement setup secret validation handler using `internal/secrets`.
- [ ] Modify `gateway-api` router to register:
  - `GET /api/setup/status`
  - `POST /api/setup/secrets/validate`
- [ ] Modify `cmd/gateway-api/main.go` to inject the active secret resolver into `NewGatewayAPIRouter`.

Verification:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/app -run "TestSetupStatus|TestSetupSecrets"
go test ./internal/secrets
```

Acceptance:

- Secret refs can be validated through API.
- Raw secret values never appear in responses or logs.
- First-run status no longer requires reading source code to know where API keys are configured.

## Task 2: Enterprise Context And Live Console Overview

**Purpose:** Stop showing fake enterprise data as the default reachable API state.

**Files:**

- Create: `services/agentnexus/internal/app/setup_enterprise.go`
- Create: `services/agentnexus/internal/app/setup_enterprise_test.go`
- Modify: `services/agentnexus/internal/app/console_overview.go`
- Modify: `services/agentnexus/internal/app/console_overview_test.go`
- Modify: `services/agentnexus/internal/app/gateway_api.go`

- [ ] Write failing test for `POST /api/setup/enterprise`.
- [ ] Request creates `enterprise_id: ent_dev`, `enterprise_name: Local Development Enterprise`, `admin_user_id: admin_dev`.
- [ ] Response returns `state: configured_without_org`.
- [ ] Write failing test for `GET /api/console/overview?enterprise_id=ent_dev` immediately after enterprise creation.
- [ ] Expected source kind is `api_live`, employee count is `0`, department count is `0`, and no string contains `示例员工`.
- [ ] Keep explicit demo endpoint behavior with `GET /api/console/overview?demo=true`.
- [ ] Implement in-memory first-run setup store first; wire to PostgreSQL later through the existing store interfaces.
- [ ] Update overview builder to aggregate from IAM org graph when available.
- [ ] Require `enterprise_id` for live overview; return `400` for missing `enterprise_id` unless `demo=true`.

Verification:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/app -run "TestSetupEnterprise|TestConsoleOverview"
```

Acceptance:

- Reachable `gateway-api` no longer defaults to fake metrics.
- Demo data is opt-in.
- UI can distinguish unconfigured, configured-empty, and configured-live states.

## Task 3: Organization Source Setup, Preview, And Confirm

**Purpose:** Let a first-run operator import a real organization graph through the UI using secret refs.

**Files:**

- Modify: `services/agentnexus/internal/app/org_import_preview.go`
- Modify: `services/agentnexus/internal/app/org_import_preview_test.go`
- Modify: `services/agentnexus/internal/app/org_import_confirm.go`
- Modify: `services/agentnexus/internal/app/org_import_confirm_test.go`
- Modify: `services/agentnexus/internal/connectors/orgsource/vendor_http.go`
- Modify: `services/agentnexus/api/openapi/org-import.yaml`

- [ ] Extend preview request with `enterprise_id`, `credential_ref`, and `provider` values `oa_http`, `wecom`, `feishu`, `dingtalk`.
- [ ] Add counts to preview response: `department_count`, `employee_count`, `membership_count`.
- [ ] Write test that preview with `token_ref` resolves `secret://env/AGENTNEXUS_TEST_OA_TOKEN`.
- [ ] Write test that raw `token` in request is rejected with `400`.
- [ ] Write test that confirm requires matching `snapshot_hash`.
- [ ] Confirm import must persist departments, users, memberships, external identities, and org version through existing IAM service.
- [ ] Update OpenAPI to state: raw credentials are forbidden; only refs are accepted.

Verification:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/app -run "TestOrgImportPreview|TestOrgImportConfirm"
go test ./internal/connectors/orgsource
```

Acceptance:

- First-run import preview can be run from API and UI.
- Confirmed import changes the live console counts.
- Vendor entries are present but still open-core generic bridge based unless official vendor adapters are separately implemented.

## Task 4: Frontend First-Run Setup Wizard

**Purpose:** Give a normal user a visible setup path instead of a static dashboard.

**Files:**

- Create: `packages/enterprise-gateway-console/src/setup-api.ts`
- Create: `packages/enterprise-gateway-console/src/FirstRunSetup.tsx`
- Create: `packages/enterprise-gateway-console/src/FirstRunSetup.test.tsx`
- Modify: `packages/enterprise-gateway-console/src/AgentNexusDashboard.tsx`
- Modify: `packages/enterprise-gateway-console/src/console-data.ts`
- Modify: `packages/enterprise-gateway-console/src/AgentNexusDashboard.test.tsx`

- [ ] Add typed client functions:
  - `loadSetupStatus`
  - `saveEnterpriseSetup`
  - `validateSecretRefs`
  - `previewOrgImport`
  - `confirmOrgImport`
  - `loadConsoleOverview`
- [ ] Add first-run wizard steps:
  - `环境检查`
  - `企业信息`
  - `密钥引用`
  - `组织来源`
  - `导入预览`
  - `完成`
- [ ] Add English copy for the same steps.
- [ ] When setup state is `unconfigured`, render the wizard as the primary screen.
- [ ] Do not render metric cards with `1,284`, `27`, `16`, or `3,642` unless `demo=true`.
- [ ] Add fields for:
  - enterprise id
  - enterprise name
  - admin user id
  - llmrouter API key secret ref
  - OA token secret ref
  - connector credential secret ref
  - provider selector: OA HTTP, WeCom, Feishu, DingTalk
  - base URL
  - departments path
  - employees path
- [ ] Add preview result panel with counts and conflicts.
- [ ] Add confirm import action.
- [ ] After confirm, reload live overview.

Verification:

```powershell
cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console
npm run build --workspace packages/enterprise-gateway-console
```

Acceptance:

- First launch does not show mock enterprise data as real.
- User can see exactly where API key secret refs are configured.
- UI text includes first-run setup in Chinese and English.
- Tests fail if demo fixture metrics appear in unconfigured mode.

## Task 5: Wire Console Buttons To Real Backends

**Purpose:** Remove dead controls from the dashboard.

**Files:**

- Modify: `packages/enterprise-gateway-console/src/ConnectorHealth.tsx`
- Modify: `packages/enterprise-gateway-console/src/AccessTicketsTable.tsx`
- Modify: `packages/enterprise-gateway-console/src/GatewayAgentLauncher.tsx`
- Modify: `packages/enterprise-gateway-console/src/setup-api.ts`
- Create: `packages/enterprise-gateway-console/src/GatewayAgentLauncher.test.tsx`

- [ ] `Smoke` button calls connector smoke API for the selected connector instance or opens setup connector smoke form if no instance exists.
- [ ] `同步组织` opens the organization import step.
- [ ] `导出审计` calls an audit export endpoint only if implemented; otherwise hide the button behind a disabled state with clear unavailable text.
- [ ] `过滤` filters visible tickets locally until server-side ticket query exists.
- [ ] Gateway Agent chat calls `POST /v1/agent/runs` on first message.
- [ ] Gateway Agent chat displays returned tool names.
- [ ] Gateway Agent chat calls `POST /v1/agent/runs/{id}/messages` for subsequent messages.
- [ ] Never store or display raw secrets in the Agent chat transcript.

Verification:

```powershell
cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console -- --run GatewayAgentLauncher FirstRunSetup AgentNexusDashboard
npm run build --workspace packages/enterprise-gateway-console
```

Acceptance:

- No primary dashboard button is decorative.
- Agent messages create persisted backend runs.
- The browser can show a tool catalog returned by `gateway-agent`.

## Task 6: API Documentation And Operator Runbook

**Purpose:** Make first-run configuration repeatable for developers and reviewers.

**Files:**

- Create: `services/agentnexus/api/openapi/setup.yaml`
- Modify: `services/agentnexus/api/openapi/org-import.yaml`
- Create: `services/agentnexus/docs/first-run-configuration.md`
- Modify: `services/agentnexus/docs/week-one-verification.md`
- Modify: `services/agentnexus/README.md`

- [ ] Document secret ref rules:
  - development: `secret://env/ENV_VAR_NAME`
  - raw tokens forbidden in request bodies
  - responses never include resolved values
- [ ] Document local env example:

```powershell
$env:AGENTNEXUS_HTTP_ADDR = ":8080"
$env:LLMROUTER_API_KEY = "<redacted>"
$env:AGENTNEXUS_OA_TOKEN = "<redacted>"
go run ./cmd/gateway-api
```

- [ ] Document Gateway Agent local run:

```powershell
$env:AGENTNEXUS_HTTP_ADDR = ":8081"
go run ./cmd/gateway-agent
```

- [ ] Document browser verification:
  - open `http://127.0.0.1:5173/`
  - complete enterprise setup
  - validate secret refs
  - preview org import
  - confirm org import
  - run connector smoke
  - start Gateway Agent run
- [ ] Add README link to `docs/first-run-configuration.md`.

Verification:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./...

cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console
npm run build --workspace packages/enterprise-gateway-console
```

Acceptance:

- A reviewer can perform first-run setup without reading source code.
- Docs explain exactly where API keys are configured.
- Docs do not include real endpoints, tokens, customer names, or private screenshots.

## Task 7: End-To-End Browser Automation

**Purpose:** Prove the setup flow from the user’s point of view.

**Files:**

- Create: `packages/enterprise-gateway-console/src/first-run.e2e.spec.ts` if Playwright is already configured.
- Otherwise create: `services/agentnexus/docs/first-run-browser-verification.md` with a reproducible in-app browser checklist.

- [ ] Start `gateway-api` on `8080`.
- [ ] Start `gateway-agent` on `8081`.
- [ ] Start Vite console on `5173`.
- [ ] Open `http://127.0.0.1:5173/`.
- [ ] Assert the unconfigured page does not contain `示例企业（Gateway API）`.
- [ ] Fill enterprise id/name/admin.
- [ ] Fill secret refs using `secret://env/...`.
- [ ] Run secret validation.
- [ ] Run org import preview against a local mock OA server.
- [ ] Confirm import.
- [ ] Assert dashboard shows imported employee and department counts.
- [ ] Click connector smoke and assert an API-backed result is shown.
- [ ] Send Gateway Agent message and assert backend run id/tool list is shown.

Verification:

```powershell
cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console
npm run build --workspace packages/enterprise-gateway-console
```

Acceptance:

- The browser proof follows the same path a normal user would follow.
- The first-run path fails the test if mock metrics are shown as live data.

## Final Verification Checklist

- [ ] `cd E:\xiaozhiclaw\agentnexus\services\agentnexus`
- [ ] `go test ./...`
- [ ] `go build ./cmd/gateway-api ./cmd/gateway-agent ./cmd/connector-worker ./cmd/connector-agent`
- [ ] `docker compose -f deploy\compose\compose.private-dev.yaml config`
- [ ] `cd E:\xiaozhiclaw\agentnexus`
- [ ] `npm test --workspace packages/enterprise-gateway-console`
- [ ] `npm run build --workspace packages/enterprise-gateway-console`
- [ ] Browser validation proves first-run setup, org preview/confirm, connector smoke, and agent run.
- [ ] `rg -n "super-secret|resolved-secret|真实客户|客户名称|password|token =" services\agentnexus packages docs` reviewed before PR.

## Execution Order

1. Task 1: Secret provider injection and setup status.
2. Task 2: Enterprise context and live overview.
3. Task 3: Organization setup preview/confirm.
4. Task 4: Frontend first-run wizard.
5. Task 5: Real dashboard actions and Agent run wiring.
6. Task 6: OpenAPI and runbook.
7. Task 7: Browser automation proof.

## PR Summary Template

The PR should say:

- Adds first-run setup status, enterprise context, and secret-ref validation APIs.
- Replaces default static console overview with live setup-aware overview; demo fixture becomes opt-in.
- Adds first-run console wizard for enterprise, secret refs, OA source, import preview, and confirmation.
- Wires connector smoke and Gateway Agent run actions to backend APIs.
- Documents local API key configuration through secret refs.
- Adds browser/user-path verification so mock metrics cannot be mistaken for real configured data.
