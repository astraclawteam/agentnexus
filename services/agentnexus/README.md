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

Environment variables:

- `AGENTNEXUS_VERSION`: service version printed by entrypoints.
- `AGENTNEXUS_ENV`: deployment environment label, defaulting to `dev`.
