# AgentNexus Week-One Verification

This guide verifies the open-core week-one development flows:

- OA HTTP organization import preview.
- Connector manifest validation and smoke verification.
- Gateway Agent first-deployment dry-run planning.

Do not commit real OA URLs, tokens, credentials, screenshots, or customer names.

## OA Mock Verification

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/connectors/orgsource -run TestOAHTTPProvider
go test ./internal/app -run TestOrgImportPreview
```

The mock OA flow uses a local `httptest` server and the generic JSON shape in `tests/fixtures/org_import/oa_http_org_sample.json`.

## Optional Real OA Verification

Set these environment variables only in your local shell or CI secret store:

```powershell
$env:AGENTNEXUS_TEST_OA_BASE_URL = "https://example.invalid"
$env:AGENTNEXUS_TEST_OA_TOKEN = "<redacted>"
$env:AGENTNEXUS_TEST_OA_DEPARTMENTS_PATH = "/departments"
$env:AGENTNEXUS_TEST_OA_EMPLOYEES_PATH = "/employees"

go test ./tests/integration -run TestOAOrgSource
```

If any variable is missing, the integration test skips with a clear message.

## Connector Plugin Verification

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/app -run TestConnectorPlugin
go test ./internal/connectors/...
```

The smoke endpoint resolves only `credential_ref` and does not return secret values.

## Gateway Agent Deployment Dry Run

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./internal/app -run TestFirstDeploymentPlan
go build ./cmd/gateway-agent
docker compose -f deploy\compose\compose.private-dev.yaml config
```

The dry-run plan returns commands and human confirmation requirements only. It does not run Docker, Helm, or production deployment automation.

When the private-dev compose profile is running, the Gateway Agent dry-run endpoint is reachable on the host at `http://127.0.0.1:8081/v1/agent/deployments/first-run:plan`.

## First-Run Configuration

The console now starts from setup status when `gateway-api` is reachable. See [first-run-configuration.md](first-run-configuration.md) for the browser flow and secret-ref rules.

## Full Verification

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./...
go build ./cmd/gateway-api ./cmd/gateway-agent ./cmd/connector-worker ./cmd/connector-agent
docker compose -f deploy\compose\compose.private-dev.yaml config

cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console
npm run build --workspace packages/enterprise-gateway-console
```
