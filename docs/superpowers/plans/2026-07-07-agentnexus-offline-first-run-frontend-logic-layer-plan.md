# AgentNexus Offline First-Run Frontend And Logic Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework AgentNexus first-run from a thin form-driven page into a product-grade offline-first setup workflow. A customer admin should be able to open the local console, understand the current deployment state, create an enterprise tenant, configure safe secret references, import organization data, verify connectors, generate a Gateway Agent dry-run, and enter a live console without reading source code.

**Architecture:** Split the current implementation into four explicit layers: frontend shell/state machine, typed API client/domain adapters, backend setup orchestration services, and browser acceptance tests. The UI must only render live state returned by `gateway-api` or clearly labeled dev/demo state. Secrets remain outside the browser and repository; the frontend handles only secret references.

**Tech Stack:** React + TypeScript + Vite, Vitest + Testing Library, browser automation through the in-app browser or Playwright, Go stdlib HTTP handlers in `gateway-api`, Go `gateway-agent`, existing IAM/org graph, connector runtime, secret resolver, Docker Compose private-dev profile.

---

## 1. Product Problems To Fix

Current first-run is technically callable but not yet product-correct.

- The first-run UI is a single large component with hidden assumptions and weak task guidance.
- Chinese copy contains mojibake and mixed English, so the experience is not usable for Chinese customer admins.
- The user cannot tell whether this is dev admin mode, real local admin mode, or an unsecured placeholder.
- Environment status is hard-coded in setup status instead of being a real diagnostics surface.
- Secret validation tells little about what to fix and does not yet block raw token-like values in the UI.
- Organization import exists, but source guidance, preview explanation, and unsupported vendor states are incomplete.
- Connector verification and Gateway Agent dry-run exist as backend capabilities, but are not first-run guided steps.
- The console can still feel like a dashboard mock because setup checklist, empty states, and live-data provenance are not strong enough.

## 2. Target Product Flow

The frontend must follow this state machine:

```text
boot
  -> api_unavailable
  -> admin_required_or_dev_admin
  -> tenant_required
  -> environment_check
  -> secrets_required
  -> org_import_required
  -> connector_verification_recommended
  -> agent_dry_run_recommended
  -> configured
```

Required entry conditions:

- `api_unavailable`: show a blocked screen with exact local service fix.
- `tenant_required`: show enterprise tenant creation, not dashboard metrics.
- `environment_check`: show dependency diagnostics and block only critical failures.
- `secrets_required`: explain where API keys are configured and accept only secret refs.
- `org_import_required`: preview before import and confirm before persistence.
- `configured`: show live console with setup checklist and explicit data source.

## 3. Frontend Layering

### 3.1 App Shell

Owns bootstrapping and high-level routing only.

Target files:

- Modify `packages/enterprise-gateway-console/src/App.tsx`
- Create `packages/enterprise-gateway-console/src/app/AppShell.tsx`
- Create `packages/enterprise-gateway-console/src/app/app-mode.ts`

Responsibilities:

- Load setup status on startup.
- Distinguish API unavailable, setup required, and configured console.
- Never render console demo data unless explicit demo mode is enabled.
- Provide locale, enterprise context, and actor context to child screens.

Implementation tasks:

- [ ] Move direct dashboard rendering out of `App.tsx` into `AppShell`.
- [ ] Add `deriveAppMode(status)` with unit tests for all setup states.
- [ ] Add API-unavailable screen with retry action.
- [ ] Make demo mode opt-in through an explicit flag, not a fallback that looks live.

### 3.2 First-Run State Machine

Owns setup step order and transitions. UI components must not decide the global setup state by themselves.

Target files:

- Create `packages/enterprise-gateway-console/src/first-run/first-run-machine.ts`
- Create `packages/enterprise-gateway-console/src/first-run/first-run-types.ts`
- Modify or replace `packages/enterprise-gateway-console/src/FirstRunSetup.tsx`

Responsibilities:

- Convert backend setup status into active step.
- Know which steps are required, recommended, skipped, completed, blocked.
- Carry `enterprise_id`, `admin_user_id`, and `actor_user_id`.
- Return clear next actions for the UI.

Implementation tasks:

- [ ] Add `deriveFirstRunStep(status, checklist)` tests.
- [ ] Support required steps: admin, tenant, environment, secrets, org import.
- [ ] Support recommended steps: connector verification, Gateway Agent dry-run.
- [ ] Include transition guards so a user cannot confirm org import before preview.

### 3.3 First-Run Screens

Each step gets its own focused component with one primary action and visible help text.

Target files:

- Create `packages/enterprise-gateway-console/src/first-run/FirstRunShell.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/SetupStepper.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/SetupHelpPanel.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/AdminAccessStep.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/EnterpriseTenantStep.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/EnvironmentCheckStep.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/SecretRefsStep.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/OrgImportStep.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/ConnectorVerificationStep.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/GatewayAgentDryRunStep.tsx`
- Create `packages/enterprise-gateway-console/src/first-run/steps/EnterConsoleStep.tsx`

Implementation tasks:

- [ ] Replace the monolithic `FirstRunSetup.tsx` with `FirstRunShell`.
- [ ] Keep a unique primary button per step.
- [ ] Add plain-language Chinese and English copy for every step.
- [ ] Show local/offline deployment badge in first-run.
- [ ] Show enterprise tenant identity after creation.
- [ ] Show unsupported WeCom/DingTalk/Feishu adapter states honestly until backend adapters exist.

### 3.4 Copy And Localization

All first-run copy must be deliberate product text, not inline fragments scattered across components.

Target files:

- Create `packages/enterprise-gateway-console/src/i18n/first-run-copy.ts`
- Create `packages/enterprise-gateway-console/src/i18n/console-copy.ts`
- Modify `packages/enterprise-gateway-console/src/console-data.ts` only if shared display labels must move.

Implementation tasks:

- [ ] Move Chinese and English first-run copy into `first-run-copy.ts`.
- [ ] Fix all mojibake in first-run and live console copy.
- [ ] Keep technical identifiers such as `secret://env/AGENTNEXUS_OA_TOKEN` untranslated.
- [ ] Add a test that fails if obvious mojibake markers appear in rendered first-run text.

### 3.5 API Client Layer

Split one broad `setup-api.ts` into domain clients with typed request and response models.

Target files:

- Create `packages/enterprise-gateway-console/src/api/http.ts`
- Create `packages/enterprise-gateway-console/src/api/setup-client.ts`
- Create `packages/enterprise-gateway-console/src/api/org-client.ts`
- Create `packages/enterprise-gateway-console/src/api/connector-client.ts`
- Create `packages/enterprise-gateway-console/src/api/agent-client.ts`
- Create `packages/enterprise-gateway-console/src/api/console-client.ts`
- Deprecate `packages/enterprise-gateway-console/src/setup-api.ts` after migration.

Responsibilities:

- Centralize JSON parsing and error mapping.
- Return product-readable error objects, not only `request failed`.
- Keep secret values out of logs, thrown errors, and rendered diagnostics.

Implementation tasks:

- [ ] Add `HTTPError` with status, code, safe message, and safe details.
- [ ] Add typed setup client for status, admin, enterprise, environment, secret validation, checklist.
- [ ] Add typed org client for preview, confirm, graph.
- [ ] Add typed connector client for manifest validation, draft, smoke, confirm.
- [ ] Add typed agent client for first-run deployment plan and agent runs.
- [ ] Update component tests to use domain client fakes.

## 4. Backend Logic Layering

### 4.1 Setup Orchestration Service

`gateway-api` needs one coherent setup application service instead of isolated handlers.

Target files:

- Create `services/agentnexus/internal/app/setup_service.go`
- Modify `services/agentnexus/internal/app/setup_status.go`
- Modify `services/agentnexus/internal/app/setup_enterprise.go`
- Modify `services/agentnexus/internal/app/gateway_api.go`

Responsibilities:

- Aggregate setup state from tenant, admin/session, environment diagnostics, secrets, org graph, connectors, agent dry-run, and audit.
- Produce the frontend state machine source of truth.
- Avoid hard-coded fake service statuses.

Implementation tasks:

- [ ] Introduce `SetupService` with `Status(ctx, enterpriseID)` and `Checklist(ctx, enterpriseID)`.
- [ ] Move status derivation out of HTTP handlers.
- [ ] Return required, recommended, blocked, and completed checklist items.
- [ ] Add tests for all first-run states.

### 4.2 Local Admin And Session Honesty

If real auth is not implemented, the product must explicitly say `dev_admin`, not pretend production login exists.

Target files:

- Create `services/agentnexus/internal/app/setup_admin.go`
- Create `services/agentnexus/internal/app/setup_admin_test.go`
- Modify `services/agentnexus/internal/app/gateway_api.go`

API targets:

- `POST /api/setup/admin/init`
- `POST /api/setup/login`
- `GET /api/setup/session`

Implementation tasks:

- [ ] Add `dev_admin` mode for private-dev profile with clear response metadata.
- [ ] Add placeholder-safe local admin init contract if production local auth is deferred.
- [ ] Include `actor_user_id` in setup responses and audit-worthy actions.
- [ ] Do not label dev admin as secure production auth.

### 4.3 Environment Diagnostics

The first-run UI needs real diagnostics before asking a customer to configure business data.

Target files:

- Create `services/agentnexus/internal/app/setup_environment.go`
- Create `services/agentnexus/internal/app/setup_environment_test.go`
- Modify `services/agentnexus/internal/app/gateway_api.go`

API target:

- `GET /api/setup/environment`

Checks:

- gateway-api readiness
- gateway-agent reachability if configured
- PostgreSQL env/config presence
- NATS env/config presence
- Docker Compose private-dev config path exists
- secret provider mode
- system clock and hostname metadata

Implementation tasks:

- [ ] Return `ready`, `warning`, or `blocked` per check.
- [ ] Include safe fix hints.
- [ ] Keep private endpoint and secret values redacted.
- [ ] Make setup status consume environment diagnostics.

### 4.4 Secret Reference Validation

Secret validation should prevent unsafe user behavior.

Target files:

- Modify `services/agentnexus/internal/app/setup_secrets.go`
- Modify `services/agentnexus/internal/app/setup_secrets_test.go`
- Add frontend tests for `SecretRefsStep`.

Implementation tasks:

- [ ] Reject raw token-like values that do not match accepted ref prefixes.
- [ ] Return per-ref status: resolved, missing, invalid_format, unsupported_provider.
- [ ] Do not expose resolved secret values.
- [ ] Surface actionable fix text for missing env refs.

### 4.5 Organization Import Persistence Flow

The UI should describe OA HTTP as the current open-core working path and other vendors as adapter states.

Target files:

- Modify `services/agentnexus/internal/app/org_import_preview.go`
- Modify `services/agentnexus/internal/app/org_import_confirm.go`
- Modify `services/agentnexus/internal/app/org_import_preview_test.go`
- Modify `services/agentnexus/internal/app/org_import_confirm_test.go`

Implementation tasks:

- [ ] Require `enterprise_id` and `actor_user_id` where appropriate.
- [ ] Return preview summary, conflict summary, and snapshot hash.
- [ ] Confirm only known previews.
- [ ] Persist to IAM org graph under the selected enterprise tenant.
- [ ] Return unsupported-provider responses for unavailable WeCom/DingTalk/Feishu adapters.

### 4.6 Connector Verification Guided Logic

Connector backend APIs exist, but first-run needs a guided path and persistent instance lifecycle.

Target files:

- Modify `services/agentnexus/internal/app/connector_plugins.go`
- Modify `services/agentnexus/internal/app/connector_instances.go`
- Modify `services/agentnexus/internal/app/connector_instances_test.go`
- Add frontend connector step files listed above.

Implementation tasks:

- [ ] Validate manifest and show resources/operations.
- [ ] Create draft connector instance with `credential_ref`.
- [ ] Run smoke test without exposing credentials.
- [ ] Confirm instance only after successful smoke or explicit warning.
- [ ] Feed connector status into setup checklist and console health.

### 4.7 Gateway Agent Dry-Run Logic

Gateway Agent first-run must be visible as a safe dry-run, not hidden behind backend-only tests.

Target files:

- Modify `services/agentnexus/internal/app/deployment_plan.go`
- Modify `services/agentnexus/internal/app/gateway_agent_router.go`
- Modify `services/agentnexus/cmd/gateway-agent/main.go`
- Add frontend `GatewayAgentDryRunStep.tsx`.

Implementation tasks:

- [ ] Return dry-run plan steps to the frontend.
- [ ] Include `requires_confirmation: true`.
- [ ] Do not execute Docker, Helm, shell commands, or file mutations from the plan endpoint.
- [ ] Feed dry-run status into setup checklist.

## 5. Console After Setup

The console must become an operations surface, not a mock dashboard.

Target files:

- Modify `packages/enterprise-gateway-console/src/AgentNexusDashboard.tsx`
- Modify `packages/enterprise-gateway-console/src/EnterprisePulse.tsx`
- Modify `packages/enterprise-gateway-console/src/AccessTicketsTable.tsx`
- Modify `packages/enterprise-gateway-console/src/ConnectorHealth.tsx`
- Modify `packages/enterprise-gateway-console/src/GatewayAgentLauncher.tsx`
- Modify `services/agentnexus/internal/app/console_overview.go`

Implementation tasks:

- [ ] Add a persistent setup completion checklist.
- [ ] Show `Gateway API live data` or `Demo mode` explicitly.
- [ ] Hide demo metrics unless demo mode is explicit.
- [ ] Replace empty tables with empty states that explain what is missing and what to do next.
- [ ] Add action routing from empty states back into setup steps.

## 6. Browser Automation Acceptance

Target files:

- Create `packages/enterprise-gateway-console/src/first-run.browser.test.ts` if existing test setup supports browser automation, or create a documented Playwright script under `packages/enterprise-gateway-console/e2e/first-run.spec.ts`.
- Modify package scripts only if the repo already uses that pattern.

Acceptance path:

- [ ] Open `http://127.0.0.1:5173/`.
- [ ] Verify API unavailable state if backend is stopped.
- [ ] Start backend and verify first-run shell appears, not dashboard mock metrics.
- [ ] Create or enter dev admin mode.
- [ ] Create enterprise tenant.
- [ ] Run environment check.
- [ ] Validate secret refs.
- [ ] Preview OA HTTP org import.
- [ ] Confirm org import.
- [ ] Enter console.
- [ ] Assert console shows live data source.
- [ ] Assert demo values like `1,284` and `3,642` are absent unless demo mode is enabled.
- [ ] Generate Gateway Agent first-deployment dry-run plan.
- [ ] Assert dry-run requires human confirmation.

## 7. Implementation Order

Use this order to avoid another UI-only drift.

1. Backend setup state source of truth: `SetupService`, checklist, environment diagnostics.
2. Frontend typed API clients and `AppShell` mode gate.
3. First-run state machine and shell.
4. Tenant, environment, and secret steps.
5. Organization import step with preview and confirm.
6. Connector verification step.
7. Gateway Agent dry-run step.
8. Live console checklist and empty states.
9. Browser automation and full verification.

## 8. Verification Commands

Backend:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/app -run "TestSetup|TestOrgImport|TestConnector|TestFirstDeploymentPlan|TestGatewayAgent"
go test ./...
go build ./cmd/gateway-api ./cmd/gateway-agent ./cmd/connector-worker ./cmd/connector-agent
docker compose -f deploy\compose\compose.private-dev.yaml config
```

Frontend:

```powershell
cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console
npm run build --workspace packages/enterprise-gateway-console
```

Manual or browser automation:

```powershell
cd E:\xiaozhiclaw\agentnexus
npm run dev --workspace packages/enterprise-gateway-console
```

Then verify first-run from `http://127.0.0.1:5173/`.

## 9. Definition Of Done

- [ ] A new customer admin can understand the first action from the first screen.
- [ ] First-run is driven by backend setup status and checklist, not hidden component state.
- [ ] Chinese and English copy are complete and contain no mojibake.
- [ ] API keys are configured as secret references only.
- [ ] OA HTTP import preview and confirm write to the enterprise tenant org graph.
- [ ] Connector smoke and Gateway Agent dry-run are visible guided steps.
- [ ] Console after setup shows live data provenance and no unlabeled mock metrics.
- [ ] Browser automation proves the offline-first setup path.
- [ ] All verification commands pass.

