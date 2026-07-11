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

The browser authorization endpoint has three layered admission controls: source rate, per-browser outstanding attempts, and enterprise/client global outstanding attempts. Keep their defaults unless deployment capacity and observed ingress behavior justify a deliberate change.

| Variable | Default | Purpose |
| --- | ---: | --- |
| `AGENTNEXUS_OIDC_AUTHORIZE_RATE_LIMIT_PER_MINUTE` | `120` | Maximum valid `/oauth2/authorize` requests per enterprise, client, and resolved source in each fixed UTC one-minute window. |
| `AGENTNEXUS_OIDC_LOGIN_ATTEMPT_PER_BROWSER_LIMIT` | `8` | Maximum unexpired login attempts per enterprise, client, and browser identifier. |
| `AGENTNEXUS_OIDC_LOGIN_ATTEMPT_GLOBAL_LIMIT` | `65536` | Maximum unexpired login attempts per enterprise and client across all browsers. This value must be greater than five times `AGENTNEXUS_OIDC_AUTHORIZE_RATE_LIMIT_PER_MINUTE`; invalid values stop startup. |
| `AGENTNEXUS_TRUSTED_PROXY_CIDRS` | empty | Optional comma-separated canonical CIDR prefixes for direct reverse proxies. Invalid, non-canonical, or duplicate prefixes stop startup. |

`X-Forwarded-For` is used only when the request's direct network peer is inside `AGENTNEXUS_TRUSTED_PROXY_CIDRS`. Leave the variable empty when AgentNexus is directly exposed or the immediate proxy is not fully controlled. Trusting an overly broad or incorrect CIDR lets clients spoof the source address and weaken source rate limiting. An untrusted peer's `X-Forwarded-For` header is ignored. A malformed chain received from a trusted peer fails closed with HTTP `400` and `invalid_forwarded_chain` before the limiter, session store, login-attempt store, cookies, or redirects are touched.

Resolved IPv4 sources are isolated as `/32`. Resolved IPv6 sources are deliberately grouped by canonical `/64` before hashing, so temporary/privacy addresses in the same subscriber network share one source-rate bucket. Account for that grouping when investigating IPv6 `429` responses or selecting trusted proxy ranges.

Outstanding login-attempt quotas are exact across gateway instances. The PostgreSQL store serializes each enterprise/client scope, tracks active counts in second-aligned expiry buckets, and updates scope and browser counters in the same transaction as attempt creation or consumption. With the five-minute attempt TTL, an active quota read visits at most 300 counter buckets and never counts the attempt table. Expired attempt rows and old counter/rate-window rows are physical housekeeping only: each cleanup query removes at most 256 indexed rows, so a long-idle deployment cannot trigger an unbounded delete. Cleanup may temporarily lag after a large expiry burst, but expired buckets are excluded from quota totals and cannot consume active quota.

HTTP `429` responses at `/oauth2/authorize` are a deployment observation signal: inspect ingress logs and request patterns, then distinguish normal retry bursts from abuse or an undersized limit before tuning. AgentNexus does not currently expose built-in metrics for the limiter, quota counters, or batched cleanup, so deployments that need alerts or dashboards must derive them from ingress/application and PostgreSQL logs or add external telemetry. The repository tests enforce the SQL transaction and indexing contract, but live multi-instance PostgreSQL concurrency validation remains an integration/deployment gate rather than a built-in runtime check.

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

## Browser authentication production contract

Browser authentication is disabled unless `AGENTNEXUS_BROWSER_AUTH_ENABLED=true`. When enabled, every item below is required and any missing, malformed, weak, non-canonical, unreadable, or over-permissive secret stops startup. Production release preflight accepts only a `postgres://` URL with a host, database, and exactly one explicit `sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full`. Missing, weak, duplicate, conflicting, case-variant, percent-encoded bypass, malformed, keyword-format, and non-PostgreSQL DSNs fail before any deployment hook. `sslmode=disable` is test-only.

| Variable | Contract |
| --- | --- |
| `AGENTNEXUS_POSTGRES_DSN` | Runtime PostgreSQL DSN. Do not place a password in a checked-in file. |
| `AGENTNEXUS_OIDC_ENTERPRISE_ID` | Exact tenant served by this gateway instance. |
| `AGENTNEXUS_OIDC_ENTERPRISE_ISSUER_URL` | Upstream enterprise IdP issuer/discovery URL. |
| `AGENTNEXUS_OIDC_PUBLIC_ISSUER_URL` | Externally visible AgentNexus issuer. It determines all discovery endpoints. |
| `AGENTNEXUS_OIDC_CLIENT_ID` | AgentNexus client id at the upstream enterprise IdP. |
| `AGENTNEXUS_OIDC_UPSTREAM_CLIENT_SECRET_FILE` | Absolute 0600 regular file containing only the upstream IdP client secret. This is not a console credential. |
| `AGENTNEXUS_OIDC_CALLBACK_URL` | Must equal `<public issuer>/oauth2/idp/callback`. |
| `AGENTNEXUS_OIDC_CONSOLE_CLIENTS_JSON` | Console client id to exact redirect URI array, for example `{"agentatlas":["https://atlas.example.invalid/auth/callback"]}`. |
| `AGENTNEXUS_OIDC_CONSOLE_CLIENT_SECRET_FILES_JSON` | Same closed client-id set mapped to `[current, optional-previous]` absolute 0600 secret files. Raw downstream secrets are hashed immediately and are never stored in config logs or PostgreSQL. |
| `AGENTNEXUS_OIDC_SIGNING_KEY_ID` | Unique current ID-token signing key id. |
| `AGENTNEXUS_OIDC_SIGNING_KEY_PATH` | Absolute 0600 current private signing-key file. |
| `AGENTNEXUS_OIDC_PREVIOUS_SIGNING_KEYS_JSON` | Optional previous key-id to absolute public-key-file map retained during verifier rollover. |
| `AGENTNEXUS_APPROVAL_FACTS_SECRET_FILE` | Absolute 0600 HMAC secret shared only with the AgentAtlas BFF that attests change facts. If absent, approvals fail safely at high risk; an invalid configured file stops startup. |

Rate and proxy settings are `AGENTNEXUS_OIDC_AUTHORIZE_RATE_LIMIT_PER_MINUTE`, `AGENTNEXUS_OIDC_LOGIN_ATTEMPT_PER_BROWSER_LIMIT`, `AGENTNEXUS_OIDC_LOGIN_ATTEMPT_GLOBAL_LIMIT`, and `AGENTNEXUS_TRUSTED_PROXY_CIDRS` as described above. Never log `Authorization`, cookies, codes, PKCE verifiers, secret-file contents, private keys, approval attestations, Case Tickets, or Step Grants.

The token endpoint supports only `client_secret_basic`. The AgentAtlas confidential BFF sends the Basic credential; browser JavaScript never receives it. Missing/wrong/duplicate/malformed Basic authentication is rejected before an authorization code is read or consumed. The upstream IdP secret, downstream console secrets, ID-token signing keys, and approval-facts secret are four separate credential domains.

### Rotation

1. Downstream console secret: mount a new current file, keep the old file as the optional previous entry, restart and observe successful BFF exchanges, switch every BFF to the new current secret, then remove the previous entry and restart. Never put the same file or value in both slots.
2. ID-token signing key: deploy the new private key/current `kid` while listing the old public key under `AGENTNEXUS_OIDC_PREVIOUS_SIGNING_KEYS_JSON`; after the five-minute token lifetime plus clock-skew allowance, remove the old public key.
3. Upstream IdP secret: configure the new value at the IdP, atomically replace the mounted upstream file, and restart. Roll back by restoring the prior secret at both IdP and mount; never reuse a downstream secret.
4. Approval-facts HMAC: stop new approval submissions, let the maximum five-minute attestation window drain, rotate the BFF and gateway mounted file together, restart, and resume. Existing approval resolution records remain immutable. Roll back both sides together before resuming submissions.

Observe token `invalid_client`, upstream exchange failures, JWKS verification failures, authorize `429`, approval safe-high reasons, and database/audit rollback errors during every rotation. A failed audit must produce no sensitive success response.

## Database roles

Use environment-specific role names, but preserve this minimum separation:

| Role | Required access | Explicitly revoke |
| --- | --- | --- |
| migrator | schema ownership/DDL and data migration while application writes are stopped | normal application login after migration |
| publisher | `SELECT,INSERT` on `org_events`, `org_versions`; controlled snapshot `SELECT,INSERT,UPDATE` and publication-head trigger access | browser credentials, approval/audit/grant writes |
| runtime | DML needed for browser sessions/codes/login counters, approval resolutions/queue, Case Tickets/Step Grants/issuance/audit; read sealed organization/policy/resource ownership | DDL, snapshot/head mutation, migration history mutation |

Illustrative hardening (replace role names and expand exact sequences in the private deployment):

```sql
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO agentnexus_runtime, agentnexus_publisher;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON org_policy_snapshot_units, org_policy_snapshot_memberships, org_policy_publication_heads FROM agentnexus_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON org_versions, audit_events, step_grant_issuances, approval_resolution_idempotency FROM agentnexus_runtime;
GRANT SELECT ON org_versions, org_policy_snapshot_units, org_policy_snapshot_memberships, enterprise_approval_policies, enterprise_approval_policy_versions TO agentnexus_runtime;
```

The runtime role needs `INSERT` on append-only audit/evidence tables but never update/delete/truncate. The migrator owns migrations; do not run the gateway with migrator credentials.

## Irreversible 000006 release

Migration `000006` revokes every legacy database-id CaseTicket bearer and adds mandatory hash-only credentials. Old and new binaries cannot overlap. Build and install `cmd/release-preflight` beside the private deployment automation, then set these absolute executable paths: `AGENTNEXUS_RELEASE_PREFLIGHT_BIN`, `AGENTNEXUS_RELEASE_STOP_OLD_HOOK`, `AGENTNEXUS_RELEASE_BACKUP_HOOK`, `AGENTNEXUS_RELEASE_MIGRATE_HOOK`, `AGENTNEXUS_RELEASE_START_NEW_ISOLATED_HOOK`, `AGENTNEXUS_RELEASE_VERIFY_HOOK`, `AGENTNEXUS_RELEASE_STOP_NEW_HOOK`, and `AGENTNEXUS_RELEASE_OPEN_TRAFFIC_HOOK`.

`make release-auth` validates the strong TLS DSN before any hook, then enforces `STOP_OLD` (close traffic and stop all old writers) → `BACKUP` → `MIGRATE` → `START_NEW_ISOLATED` (must not register with a load balancer) → `VERIFY` → `OPEN_TRAFFIC`. Traffic opens only after successful verification. Verification or isolated-start failure automatically invokes `STOP_NEW` and leaves maintenance active. A `STOP_NEW` failure is a critical hard failure: do not open traffic or restart an old release until operators prove the isolated process is stopped and restore the recorded backup if rollback is required.

Preflight must confirm no old replicas/workers remain, the backup is restorable, secret mounts and file modes are correct, and `make test-auth` passed against real PostgreSQL. If migration/start/verification fails, keep maintenance closed, stop the isolated new binary, and restore the pre-migration database backup before starting the old release. SQL Down intentionally raises an exception; there is no destructive in-place rollback.

Ordinary `go test ./...` may skip live PostgreSQL acceptance and is not a release gate. The repository CI provisions a real PostgreSQL service and calls only the fail-closed `make test-auth` target; releases must use that same gate with `AGENTNEXUS_E2E_POSTGRES_DSN` set.
