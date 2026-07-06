# AgentNexus Open-Core Development Deployment

This directory contains open-core development profiles only. Production private-deployment automation, customer overlays, managed secrets, hardened networking, and environment-specific release controls belong in the private `agentnexus-enterprise` repository.

## Profiles

- `compose/compose.saas-dev.yaml` runs the open-core services with local PostgreSQL, NATS, and object storage using SaaS-style defaults.
- `compose/compose.private-dev.yaml` runs the same open-core services with private-dev defaults and external dependency environment toggles.
- `helm/agentnexus` is a local/dev Helm chart skeleton for validating open-core workload shape.

## Shared Environment Variables

| Variable | Purpose |
| --- | --- |
| `AGENTNEXUS_ENV` | Runtime environment label, such as `saas-dev` or `private-dev`. |
| `AGENTNEXUS_PROFILE` | Deployment profile name. |
| `AGENTNEXUS_VERSION` | Open-core runtime version string. |
| `AGENTNEXUS_POSTGRES_EXTERNAL` | Set to `true` when using an external PostgreSQL service. |
| `AGENTNEXUS_POSTGRES_DSN` | PostgreSQL connection string. |
| `AGENTNEXUS_NATS_EXTERNAL` | Set to `true` when using an external NATS service. |
| `AGENTNEXUS_NATS_URL` | NATS URL. |
| `AGENTNEXUS_OBJECT_STORAGE_EXTERNAL` | Set to `true` when using external object storage. |
| `AGENTNEXUS_OBJECT_STORAGE_ENDPOINT` | S3-compatible object storage endpoint. |
| `AGENTNEXUS_SECRET_PROVIDER_EXTERNAL` | Set to `true` when secrets are resolved by an external provider. |
| `AGENTNEXUS_SECRET_PROVIDER` | Secret provider mode, defaulting to `local-dev`. |

## Compose

Validate the private-dev compose profile:

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus\deploy\compose
docker compose -f compose.private-dev.yaml config
```

Run the SaaS-dev profile:

```powershell
docker compose -f compose.saas-dev.yaml up
```

Run the private-dev profile:

```powershell
docker compose -f compose.private-dev.yaml up
```

The compose profiles use the official Go image and mount the repository so contributors can run the current open-core commands without building production images.

## Helm

Render the local/dev chart:

```powershell
helm template agentnexus .\helm\agentnexus
```

Use `values.yaml` to disable local dependencies and point at external development services:

```yaml
dependencies:
  postgres:
    external: true
    dsn: postgres://agentnexus:agentnexus@postgres.dev:5432/agentnexus?sslmode=require
  nats:
    external: true
    url: nats://nats.dev:4222
  objectStorage:
    external: true
    endpoint: https://object-storage.dev
  secretProvider:
    external: true
    mode: external-dev
```

Do not add production private-deployment automation here. Put production ingress, network policy, secret manager integration, customer overlays, image promotion, compliance controls, and release orchestration in `agentnexus-enterprise/private-deploy`.
