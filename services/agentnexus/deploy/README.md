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

## Browser OIDC Ingress Controls

The browser authorization endpoint has two independent admission controls. Keep their defaults unless deployment capacity and observed ingress behavior justify a deliberate change.

| Variable | Default | Purpose |
| --- | ---: | --- |
| `AGENTNEXUS_OIDC_AUTHORIZE_RATE_LIMIT_PER_MINUTE` | `120` | Maximum valid `/oauth2/authorize` requests per enterprise, client, and resolved source in each fixed UTC one-minute window. |
| `AGENTNEXUS_OIDC_LOGIN_ATTEMPT_PER_BROWSER_LIMIT` | `8` | Maximum unexpired login attempts per enterprise, client, and browser identifier. |
| `AGENTNEXUS_OIDC_LOGIN_ATTEMPT_GLOBAL_LIMIT` | `65536` | Maximum unexpired login attempts per enterprise and client across all browsers. This value must be greater than five times `AGENTNEXUS_OIDC_AUTHORIZE_RATE_LIMIT_PER_MINUTE`; invalid values stop startup. |
| `AGENTNEXUS_TRUSTED_PROXY_CIDRS` | empty | Optional comma-separated canonical CIDR prefixes for direct reverse proxies. Invalid, non-canonical, or duplicate prefixes stop startup. |

`X-Forwarded-For` is used only when the request's direct network peer is inside `AGENTNEXUS_TRUSTED_PROXY_CIDRS`. Leave the variable empty when AgentNexus is directly exposed or the immediate proxy is not fully controlled. Trusting an overly broad or incorrect CIDR lets clients spoof the source address and weaken source rate limiting.

HTTP `429` responses at `/oauth2/authorize` are a deployment observation signal: inspect ingress logs and request patterns, then distinguish normal retry bursts from abuse or an undersized limit before tuning. AgentNexus does not currently expose built-in metrics for this limiter, so deployments that need alerts or dashboards must derive them from ingress/application logs or add external telemetry.

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
