# AgentNexus whole-branch final-review remediation

## Scope and outcome

This remediation closes all five Important and both Minor findings from the whole-branch review of `9a2ee9a..1cab7e0`. Work stayed in the isolated AgentNexus worktree. No runtime-ui source or published `@xiaozhiclaw/runtime-ui@0.1.0` artifact changed.

## Systematic-debugging root causes

### 1. Confidential AgentAtlas BFF

Root cause: `OIDCConfig.ConsoleClients` represented only redirect allow-lists. `/oauth2/token` trusted a body `client_id` and called `ExchangeCode` without authenticating a confidential client. The single `ClientSecret` field was the raw upstream IdP secret, so upstream and downstream credential domains were not modeled separately.

Remediation:

- downstream `client_secret_basic` is mandatory before any authorization-code lookup/consumption;
- missing, wrong, duplicate, malformed, or non-canonical Basic credentials return `401 invalid_client` plus `WWW-Authenticate` with no code-store side effect;
- the form now contains exactly `grant_type`, `code`, `code_verifier`, and `redirect_uri`; a body `client_id` is rejected;
- each redirect client has a current and optional previous domain-separated SHA-256 credential hash; both hashes are compared on every authentication with `crypto/subtle`;
- `AGENTNEXUS_OIDC_CONSOLE_CLIENT_SECRET_FILES_JSON` uses an exact closed client set and duplicate-key-rejecting JSON parser; paths must be absolute/canonical, regular non-symlink files, owner-only on Unix, and secrets must satisfy length/printable/diversity requirements;
- raw downstream values exist only while a mounted file is read and hashed; the returned config stores hashes only;
- the upstream IdP credential moved to the separate `AGENTNEXUS_OIDC_UPSTREAM_CLIENT_SECRET_FILE` and `UpstreamClientSecret` field;
- discovery and OpenAPI advertise only `client_secret_basic`; E2E uses the confidential request.

RED evidence: `go test ./internal/browserauth ./internal/app -run 'ConsoleClient|RequiresConfidential|RejectsAmbiguous' -count=1` failed because credential APIs did not exist, missing response/scope returned `302`, and invalid Basic requests followed the public-client path.

GREEN evidence: the same focused suites passed, their combined full package suites passed, and the security-focused suite passed `-count=20`.

### 2. Frozen authorize and permission contract

Root cause: `response_type` and `scope` were validated only when present. The OpenAPI duplicated unconstrained `string` items for the two permission arrays, allowing an eighth permission or spelling drift.

Remediation:

- authorize requires exactly one `response_type=code` and exactly one non-empty scope containing the exact `openid` word before source limiting, cookies, sessions, or login-attempt writes;
- missing/duplicate/wrong values have handler negative coverage;
- `AgentAtlasPermission` is the single seven-value OpenAPI enum referenced by both `BrowserSession.permissions` and `PermissionDecision.permissions`;
- `BrowserTokenRequest` and the Basic security scheme are frozen in the contract test.

RED evidence: missing response type and scope both redirected to the IdP. The OpenAPI test failed because `AgentAtlasPermission` did not exist.

GREEN evidence: handler and OpenAPI contract tests pass, including `-count=20` focused execution.

### 3. Sensitive verify and logout audit atomicity

Root cause: `VerifyGrant` performed a pool read with no audit append. Logout revoked via the browser-session store, then appended audit in a second transaction; audit failure therefore left a revoked session and the handler also cleared its cookie before knowing the transaction outcome.

Remediation:

- the governed grant-store interface now exposes one atomic `VerifyStepGrantAndAudit` operation;
- PostgreSQL performs tenant-scoped grant read/validation, enterprise audit lock, previous-hash read, fully bound `step_grant.verify` event append, and commit in one transaction;
- verify audit inputs bind enterprise, actor, Case Ticket, Step Grant, resource, action, exact scope, and verification time; every repeat success gets its own chain event;
- audit/storage errors map to unavailable (`503`) rather than semantic denial; no success response or event is lost;
- logout is now a single `BrowserAuditSink.LogoutBrowserSession` atomic interface. PostgreSQL revokes and appends `browser_session.logout` under the tenant audit lock in one transaction;
- audit/store failure rolls back revocation and preserves both the browser cookie and live session; the cookie is cleared only after commit or for an already-invalid session;
- memory/fake stores implement the same observable all-or-nothing behavior;
- verification uses the one timestamp passed into the atomic store, avoiding a post-commit second clock check that could append allow audit but return denial.

RED evidence:

- the new memory test failed because verify had no audit API;
- logout audit failure reproduced an invalid/revoked session;
- live PostgreSQL injected audit failure first exposed an infrastructure-error-to-403 mapping bug, then exposed premature cookie clearing.

GREEN evidence:

- memory repeat/failure/tenant tests and PostgreSQL transaction-order/rollback tests pass;
- live `TestBrowserSessionAndApproval` passes with two successful verify events, injected verify `503` without an event, injected logout `503` with `/me` still `200`, successful logout event after trigger removal, and final `/me` `401`;
- all ledger hashes match the repository `sha256:<64 hex>` contract.

### 4. Migration 000006 deployment contract

Root cause: Up irreversibly revoked legacy database-id bearers, while Down silently dropped `token_hash` and the new evidence tables. Old and new binaries were therefore neither rolling-compatible nor safely downgrade-compatible.

Remediation:

- Down now always raises `migration 000006 is irreversible` and contains no destructive credential/evidence drops;
- rollback is explicitly backup restore, never an in-place schema downgrade;
- `deploy/release-auth.sh` fails closed unless stop-write maintenance is acknowledged, the production DSN requires TLS, and deployment-owned stop/backup/migrate/start/verify hooks are absolute regular executables;
- hook order forces old binaries/writes stopped, durable backup, migration, new binary only, then verification; old/new overlap is expressly forbidden;
- Make exposes `release-auth`; SQL/release contract tests lock the behavior.

RED evidence: migration contract found destructive Down statements and release contract could not find an orchestrator.

GREEN evidence: migration/release contract tests pass.

### 5. Deployment documentation

Root cause: deployment documentation described rate limiting but omitted the full browser-auth credential model, rotation, startup semantics, role separation, and irreversible release/restore procedure.

Remediation: deploy and migration READMEs now cover every browser-auth environment variable, TLS, redirect JSON, downstream current/previous files, upstream secret, signing current/previous keys, approval-facts HMAC rotation, rate/proxy controls, mounted-file modes, fail-start behavior, no-secret examples, runtime/publisher/migrator GRANT/REVOKE matrix, observation points, maintenance rollout, backup, verification, and restore-only rollback.

### Minor 1. Real PostgreSQL CI gate

Root cause: `make test-auth` failed closed locally, but no repository workflow provisioned PostgreSQL and invoked it. Ordinary `go test` can legally skip live tests.

Remediation: `.github/workflows/agentnexus-auth.yml` starts PostgreSQL 16 and invokes only `make test-auth`. A repository contract test rejects bypassing the Make release gate. Documentation distinguishes ordinary unit tests from the release gate.

### Minor 2. Console responsiveness

Root cause: `body { min-width: 1180px }` remained active until the 900px breakpoint, forcing whole-page horizontal scrolling for 901-1179px viewports.

Remediation: body has no fixed minimum; a 1179px breakpoint shrinks the shell/topbar, hides the nonessential source chip, reduces metrics to two columns, and stacks the lower grid. Workspace/panels stay `min-width:0`, the ticket table owns its local horizontal scroll, and the shared Sheet remains viewport-bounded.

RED evidence: the DOM/CSS contract matched the fixed 1180px body and found no 1179px breakpoint.

GREEN evidence: all 10 Console tests passed, including 20 repeated runs, and the production build passed.

## Verification performed

- `sqlc generate` twice: success and stable generated tree.
- Security-focused Go suites with `-count=20`: pass.
- Exact `test-auth` Go command with real PostgreSQL DSN: all six package groups pass.
- `go test -buildvcs=false ./... -count=1` with live DSN: all packages pass.
- `go vet -buildvcs=false ./...`: pass.
- four command builds with `-buildvcs=false`: pass.
- live main/serialization/audit rollback E2E: pass.
- migration, Make, CI, OpenAPI, and release contracts: pass.
- Console 10-test suite repeated 20 times: pass.
- Console production build, root workspace tests, and `npm ls @xiaozhiclaw/runtime-ui --all`: pass.
- registry query confirms `@xiaozhiclaw/runtime-ui@0.1.0`, SHA-1 `eb36cf164b3f56f021dba2bcd7d788516df91f84`, and the committed SHA-512 integrity.
- `git diff --check`: pass (Windows line-ending warnings only).

## Self-review

- No raw downstream secret field exists in OIDC config, database models, logs, API bodies, or OpenAPI.
- The upstream raw secret is a separate required IdP credential and is never accepted for downstream Basic authentication.
- Invalid Basic authentication occurs before `ExchangeCode` and is covered by a side-effect counter.
- Verify and logout production paths hold the audit lock and commit state plus chain event together.
- No eighth AgentAtlas permission, runtime-ui change, login popup/manual ticket path, auto-publish path, or legacy CaseTicket admission was introduced.
- Migration Down cannot erase post-cutover credentials/evidence.

## Environment concerns

- GNU Make is not installed in the restarted Windows environment. The fail-closed Make structure and CI invocation are contract-tested, and its exact `go test` command was executed successfully against the real PostgreSQL DSN. No external CI was run.
- Go 1.26.4 VCS stamping in this Windows worktree returns `error obtaining VCS status: exit status 128` for command packages in both dirty and clean states, even though the equivalent direct `git status`, `git log`, `git tag`, and `git rev-parse` commands all return zero. Full test/vet/build gates therefore use the standard `-buildvcs=false` escape hatch; this is an environment/toolchain limitation, not a passing no-flag claim.
- The race detector remains unavailable because `CGO_ENABLED=1` cannot find `gcc`; no race-pass claim is made.

## Second-round release hardening

The final release review found four remaining places where permissive parsing or an underspecified cutover could weaken the fail-closed contract.

### A. Production PostgreSQL DSN preflight

Root cause: the shell release guard inferred TLS with string matching. That could not reliably distinguish a unique canonical `sslmode` from missing, duplicated, encoded, malformed, or non-PostgreSQL input.

Remediation:

- a dedicated Go preflight parses the URL and query using the standard library before any deployment hook runs;
- only a `postgres` URL with host, database path, and exactly one lowercase `sslmode=require|verify-ca|verify-full` is accepted;
- missing or weak modes, duplicate keys (including percent-encoded aliases), encoded values, malformed percent escapes, fragments, control characters, outer whitespace, and non-PostgreSQL schemes fail closed;
- the command reports a generic error and never prints the DSN.

RED evidence: focused tests initially failed because the DSN validation API and release-preflight command did not exist.

GREEN evidence: the validator matrix passed 20 repeated runs, and actual release-script tests proved seven invalid DSNs execute no deployment hook.

### B. Isolated release cutover and cleanup

Root cause: the prior release contract did not make isolated startup, pre-traffic verification, and failed-new-instance cleanup independently enforceable.

Remediation: the script now enforces `STOP_OLD -> BACKUP -> MIGRATE -> START_NEW_ISOLATED -> VERIFY -> OPEN_TRAFFIC`. A failed isolated start or verification invokes `STOP_NEW`, leaves maintenance/traffic closed, and becomes a critical failure if cleanup itself fails. `OPEN_TRAFFIC` is unreachable until verification succeeds.

Actual-script evidence:

- success recorded the exact six-phase order and final traffic state `open`;
- verification failure recorded `STOP_NEW`, omitted `OPEN_TRAFFIC`, and left traffic `closed`;
- `STOP_NEW` failure emitted a critical error, omitted `OPEN_TRAFFIC`, and left traffic `closed`;
- the combined release-script E2E suite passed against real executable hook stubs and the built Go preflight command.

### C. Canonical confidential client identifiers

Root cause: startup configuration and Basic authentication did not share one explicit client-id grammar, permitting inconsistent admission across boundaries.

Remediation: both paths now use the same 1..256-byte ASCII grammar `[A-Za-z0-9._~-]`. Redirect lookups and authorization validation also reject noncanonical identifiers.

RED evidence: new startup, authorization, and Basic boundary tests admitted invalid identifiers before the shared validator existed.

GREEN evidence: focused client-id tests passed 20 repeated runs, including boundary length and invalid-character cases.

### D. Duplicate-rejecting JSON maps

Root cause: ordinary Go JSON map decoding silently accepted duplicate keys, so later entries could replace security-sensitive redirect, previous-signing-key, or secret-file mappings.

Remediation: all three maps now use one token-level strict decoder that rejects duplicate keys, wrong value shapes, and trailing JSON.

RED evidence: duplicate-key and malformed-shape tests were accepted by the previous decoders.

GREEN evidence: focused decoder, startup-config, and mounted-secret tests passed 20 repeated runs.

## Second-round verification

- `sqlc generate` twice: success and no generated diff.
- `go test -buildvcs=false ./internal/... -count=1`: all internal packages pass.
- `go test -buildvcs=false ./cmd/... ./db/... -count=1`: pass.
- `go test -buildvcs=false ./tests/integration -count=1`: pass.
- `go test -buildvcs=false ./tests/e2e -count=1`: pass, including actual release-script state assertions.
- exact auth/release package gate: pass.
- `go vet -buildvcs=false ./...`: pass.
- gateway-api, gateway-agent, connector-worker, connector-agent, and release-preflight builds with `-buildvcs=false`: pass.
- Console 10-test suite, Console production build, root workspace tests, and `npm ls @xiaozhiclaw/runtime-ui --all`: pass.
- `git diff --check`: pass (Windows line-ending warnings only).

The environment concerns above remain unchanged: GNU Make and gcc are unavailable, and this Windows/Go worktree requires `-buildvcs=false`; no Make, race-detector, or no-flag VCS-stamped pass is claimed.
