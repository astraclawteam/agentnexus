# Decision — serve the published Agent-client trust registry; do not amend the contract

Date: 2026-07-22
Status: accepted, implemented in this change
Scope: `POST /v1/agent-clients`, `POST /v1/agent-clients/{agent_client_ref}/certifications`,
`POST /v1/agent-clients/{agent_client_ref}/certifications/{certification_ref}/revocations`
(contract v1.1.0, GA Task 0C)

## The observed defect

A joint AgentNexus/AgentAtlas run on 2026-07-22 reached `POST /v1/agent-clients` and got
Go's bare `404 page not found` — plain text, not the JSON error envelope, meaning no route
matched and the request never reached authentication. All three operations above are
declared in `api/openapi/gateway-runtime.yaml` under `security: [{trustedServiceSecret: []}]`
and announced in `api/CHANGELOG.yaml` 1.1.0. Any client generated from the published
contract gets a 404 with no explanation.

## What was actually missing

The defect report concluded the operations were "not implemented". That is true only of the
HTTP layer. Everything underneath was already built, and is exercised by tests:

| Layer | State before this change | Evidence |
|---|---|---|
| Domain types and validation | built, published, tested | `sdk/go/runtime/trust.go` — `VersionRange`, `SigningKey`, `CapabilityCeiling` (`Narrow` is an intersection, never a raise), `CertificationBinding.Validate`; `sdk/go/runtime/trust_test.go` |
| Database schema | built | `db/migrations/000007_agent_clients.sql` — immutable revisions enforced by trigger, append-only hash-chained status log, first-party-requires-registration CHECK |
| Queries and generated access | built | `db/queries/agent_clients.sql`, `db/generated/agent_clients.sql.go` |
| Registry service | built, tested | `internal/agenttrust/service.go`, `service_test.go` (597 lines), `postgres.go`, `postgres_integration_test.go` |
| HTTP surface | **absent** | no route, no handler, no dependency |
| Gateway composition | **absent** | `NewPostgresGatewayRouter` never constructed the registry |

This is the shape `internal/app/deps_required.go` already names: a dependency that is
"implemented, unit-tested, and constructed by nothing". Evidence was the previous instance;
the trust registry was the next one, and it was invisible because the wiring guard can only
check dependencies that are declared in `BrowserAuthDependencies`.

The registry was never reachable from the outside, so `MissingRequired` had nothing to
report on.

## Decision

Serve the published contract. Add the HTTP surface and wire the registry into
`NewPostgresGatewayRouter`, declaring it as a REQUIRED gateway dependency so it can never
silently go unwired again. Do not amend `api/openapi/gateway-runtime.yaml`, `api/CHANGELOG.yaml`
or `api/contract.lock`.

## Why not the alternative (amend the contract, remove what was never served)

Two reasons, both decisive.

**1. It would be the more expensive option, not the cheaper one, and the cost lands in
repositories this change may not touch.** The contract is digest-pinned in three places:

- `api/contract.lock` (this repository);
- `agentatlas/services/agentatlas/internal/nexusclient/gateway_runtime_parity_test.go`
  pins the sha256 as a Go constant next to a byte-identical snapshot of the whole document;
- `agentnexus-enterprise/tests/security/agent_certification_test.go` asserts a profile YAML
  that names the open-core OpenAPI artifact and changelog version, and the GA release gate
  digests those artifacts.

Removing three operations moves all three pins. Amending here alone leaves two other
repositories red.

**2. It would delete a working subsystem from the published surface.** The removal would have
to take `CertificationBinding`, `CapabilityCeiling`, `VersionRange` and `SigningKey` with it —
types the 1.0.0 decision names as the NORMATIVE contract surface ("the Go SDK is the normative
validation surface; OpenAPI annotations are descriptive"), which the enterprise repository
mirrors as frozen wire values, and which back a tested service and a migrated schema. The
honest description of the gap is "published and built, never routed", and the honest fix for
that is a route.

## What this decision does NOT fix, and must not be read as fixing

**It does not fix the 401 on `/v1/org-events`.** That was the motivating symptom, and the
defect report's framing — that `/v1/agent-clients` "is exactly the registration surface" for
the trusted service secret — does not survive reading the schemas:

- `AgentClientRegistrationRequest` carries `publisher`, `product`, `origin`. It accepts no
  secret and the response returns none. `AgentCertificationRequest` binds a *public* signing
  key and a release-manifest digest. Nothing in the registry mints, stores or accepts a
  shared secret, and `db/migrations/000007_agent_clients.sql` has no column for one.
- All three operations are themselves guarded by `trustedServiceSecret`. A surface that
  requires the credential cannot be the surface that issues it.

The registry answers "is this release certified, and what is its capability ceiling" — not
"here is your credential". Those are different questions and the contract only ever declared
the first.

**Where trusted-service enrolment actually lives today.** `trustedServiceSecret` is verified
by `consoleServiceCredentialVerifier` (`internal/app/browser_auth.go`) against
`OIDCConfig.ConsoleCredentials` — the same hashed credential set behind `consoleClientSecret`.
So in this build the two declared security schemes resolve to ONE credential store, and
enrolment is an out-of-band operator act: put the secret in a file and name it in
`AGENTNEXUS_OIDC_CONSOLE_CLIENT_SECRET_FILES_JSON`. There is no API for it and this decision
does not add one.

That aliasing is a real limitation and is recorded here because task C4 (verifying an Access
Ticket and returning an actor) will meet the same question. It is not fixed here: splitting
the two schemes into separate credential stores would break every deployment that currently
presents its console client secret as the service credential, and needs its own change with a
migration story.

What IS fixed here for the joint stack is the provisioning gap: AgentNexus's dev material now
materialises the trusted-service credential explicitly instead of leaving the counterpart to
be invented by whoever stands up the other product. See
`deploy/compose/dev-auth-material/provision.sh`.

## Consequences

- The three operations answer under `trustedServiceSecret` instead of 404.
- `BrowserAuthDependencies.AgentTrust` is REQUIRED: `MissingRequired` fails router
  composition if a future change drops the wiring, which is the guarantee that was missing.
- `manifest_signature` is now verified (ed25519, over the release-manifest digest bytes,
  against the certified `signing_key`) BEFORE `SignedBuildManifest` is attested to the
  registry. `internal/agenttrust/model.go` recorded this as "a later handler task"; it is no
  longer deferred, and a certification whose signature does not verify is a 400.
- No public contract artifact changes, so `api/contract.lock`, the AgentAtlas snapshot and
  the enterprise profile all stay valid.
