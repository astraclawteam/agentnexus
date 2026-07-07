# AgentNexus Service

This module contains the open-core AgentNexus Go services.

## Service Entrypoints

- `cmd/gateway-api`: stable Runtime API entrypoint.
- `cmd/gateway-agent`: Gateway Agent Control Plane entrypoint.
- `cmd/connector-worker`: service-side connector execution worker.
- `cmd/connector-agent`: enterprise-side outbound connector agent.

## Development Commands

```powershell
go test ./...
go build ./cmd/gateway-api
go build ./cmd/gateway-agent
go build ./cmd/connector-worker
go build ./cmd/connector-agent
```

Week-one dev-flow verification is documented in [docs/week-one-verification.md](docs/week-one-verification.md).
First-run configuration is documented in [docs/first-run-configuration.md](docs/first-run-configuration.md).

Environment variables:

- `AGENTNEXUS_VERSION`: service version printed by entrypoints.
- `AGENTNEXUS_ENV`: deployment environment label, defaulting to `dev`.
- `AGENTNEXUS_HTTP_ADDR`: HTTP listen address for gateway services, defaulting to `:8080`.
- `LLMROUTER_API_KEY`: optional model gateway key, referenced as `secret://env/LLMROUTER_API_KEY`.
- `AGENTNEXUS_OA_TOKEN`: optional OA import token, referenced as `secret://env/AGENTNEXUS_OA_TOKEN`.
