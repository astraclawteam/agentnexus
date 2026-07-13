# AgentNexus First-Run Configuration

This guide verifies the local first-run path. Do not commit real URLs, tokens, customer names, screenshots, or private endpoints.

## Secret Refs

Development uses environment-backed secret references:

```powershell
$env:LLMROUTER_API_KEY = "<redacted>"
$env:AGENTNEXUS_OA_TOKEN = "<redacted>"
$env:AGENTNEXUS_FILE_STORAGE_TOKEN = "<redacted>"
```

Use these refs in API/UI forms:

```text
secret://env/LLMROUTER_API_KEY
secret://env/AGENTNEXUS_OA_TOKEN
secret://env/AGENTNEXUS_FILE_STORAGE_TOKEN
```

Raw tokens are forbidden in request bodies. API responses must show only whether a ref resolved.

## Start Services

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
$env:AGENTNEXUS_HTTP_ADDR = ":8080"
go run ./cmd/gateway-api
```

In another shell:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
$env:AGENTNEXUS_HTTP_ADDR = ":8081"
go run ./cmd/gateway-agent
```

In the repo root:

```powershell
cd E:\xiaozhiclaw\agentnexus
npm run dev --workspace packages/enterprise-gateway-console
```

Open `http://127.0.0.1:5173/`.

## Browser Flow

1. Confirm the page shows first-run setup, not demo metrics.
2. Save enterprise context:
   - enterprise id: `ent_dev`
   - enterprise name: `Local Development Enterprise`
   - admin user id: `admin_dev`
3. Validate secret refs.
4. Choose an organization provider:
   - `OA HTTP`
   - `WeCom`
   - `Feishu`
   - `DingTalk`
5. Enter base URL and `/departments`, `/employees` paths.
6. Run import preview.
7. Confirm import.
8. Confirm the dashboard reloads from live overview.
9. Open Gateway Agent chat and send a setup request.
10. Confirm the UI shows an agent run id and allow-listed tool names.

## API Smoke

```powershell
Invoke-RestMethod http://127.0.0.1:8080/api/setup/status

$body = @{
  refs = @{
    llmrouter_api_key = "secret://env/LLMROUTER_API_KEY"
    oa_token = "secret://env/AGENTNEXUS_OA_TOKEN"
  }
} | ConvertTo-Json
Invoke-RestMethod -Method Post -ContentType "application/json" -Body $body http://127.0.0.1:8080/api/setup/secrets/validate
```

## Verification

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./...

cd E:\xiaozhiclaw\agentnexus
npm test --workspace packages/enterprise-gateway-console
npm run build --workspace packages/enterprise-gateway-console
```
