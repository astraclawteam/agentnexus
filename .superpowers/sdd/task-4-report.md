# Task 4 Report: Governed Approval Routing

## Outcome

Implemented deterministic low/medium/high risk classification, immutable sealed-organization routing, explicit AgentAtlas permission checks, atomic approval queue plus audit persistence, strict `POST /v1/approvals/resolve`, OpenAPI contract, migration `000005`, generated sqlc code, and production gateway wiring.

The implementation remains inside Task 4. No Task 5 behavior was added.

## Post-review hardening wave

The first Task 4 commit (`c5e6c35`) was rejected in dual review because browser-supplied change facts were trusted, permission checks could multiply full-graph evaluation by reviewer count, policy/org state could advance between resolution and persistence, and POST resolution lacked durable idempotency. The remediation replaces those trust boundaries rather than patching individual symptoms.

### Verified facts and closed actions RED/GREEN

- RED: new `ClassifyVerifiedRisk` tests failed to compile because verified/unverified facts and closed action baselines did not exist.
- GREEN: risk classification now accepts only `VerifiedChangeFacts`; the production-exported raw `RiskInput/ClassifyRisk` path was removed. Unknown fields/actions and unverified attestations deterministically force high with canonical reasons.
- RED: HMAC tests failed to compile without attestation APIs.
- GREEN: canonical HMAC-SHA256 binds enterprise, actor, org version/unit, exact resource/action, all explicit facts, issued/expiry/nonce, and the hashed Idempotency-Key. Tests mutate actor, enterprise, resource, idempotency hash, and one fact; test expiry, >5-minute lifetime, short/missing secret, and reject verifier behavior.
- RED: secret-file loader tests failed before loader implementation.
- GREEN: `AGENTNEXUS_APPROVAL_FACTS_SECRET_FILE` loads a trimmed >=32-byte deployment secret; absent config injects a safe Reject verifier, while unreadable/short configured secrets fail startup.
- Task 3 vocabulary now includes exact `workflow.publish_low_risk` and `workflow.approve_high_risk` mappings. Unknown/mismatched resource/action cannot produce low.

### Linear permission index RED/GREEN

- Replaced per-candidate `AgentAtlasEvaluator` calls with one immutable snapshot index over only `manager`, `publish_low_risk`, and `approve_high_risk` memberships.
- Parent permission scope covers child target with Task 3 semantics; manager remains only candidate identity and grants no implicit permission.
- A 1,000-manager structural counter test first failed without observation support, then proved exactly one membership pass and at most one selected candidate check. Complexity is O(V+M), bounded by 10k units, 100k memberships/users, and depth 256.

### Enterprise policy and stale-state RED/GREEN

- RED: migration/query contracts failed without enterprise policy schema and queries.
- GREEN: `enterprise_approval_policies` has strict risk/threshold/version checks and monotonic update trigger. Version history provides composite FK evidence; no row maps to safe defaults with explicit policy version 0. Database errors fail closed.
- The PostgreSQL source loads policy, units, relevant memberships, and users in the same read-only repeatable-read snapshot. Handler uses this loaded policy; production no longer injects `DefaultPolicy`.
- Write path uses ReadCommitted and lock order: org publication lock (publisher seed) → idempotency lookup → latest sealed org/policy revalidation → audit lock (separate seed) → latest hash → resolution reservation → optional queue → audit → commit.
- Memory and PostgreSQL tests cover org/policy advancement, direct-low revalidation, queue/audit/commit/random failure rollback, and replay exception for already committed results.

### Idempotency RED/GREEN

- RED: memory tests failed before `RecordResolution`, version state, replay, and conflict APIs existed.
- GREEN: the endpoint requires one canonical `Idempotency-Key` and stores only SHA-256. Durable `approval_resolution_idempotency` records the normalized route, request hash, policy/org versions, queue/audit IDs, and evidence.
- Same key/request replays without new queue/audit; same key/different request returns 409; 20 concurrent same-key memory requests commit once.
- A second RED exposed that handler verified expired facts and loaded a possibly unavailable/newer snapshot before replay. Handler now computes an actor-bound canonical raw request/attestation replay hash and performs `LookupResolution` first. Tests prove expired facts, advanced org state, failing verifier, and unavailable source still replay an already committed route without recording again; conflict still returns 409.

### Database evidence hardening

- Queue rows reject `single_confirmation`; only upward review/admin queue shapes are accepted. Status is closed to pending/approved/rejected/cancelled.
- Policy/version refs, requester/reviewer, target/reviewer snapshot units, reviewer display/manager evidence, and idempotency hashes are constrained. Self-review remains prohibited.
- PL/pgSQL validation rejects null/object/non-string reasons/path items, empty arrays, unknown/duplicate/unsorted reasons, duplicate/non-adjacent paths, wrong first unit, stale/unsealed/non-latest versions, stale policy, invalid reviewer evidence, and high risk without a raise reason.
- Resolution→queue/audit foreign keys are deferred so resolution reservation, optional queue, and audit can be inserted in one transaction and validated at commit.
- SQL contract tests include structural negative checks (including proving the queue route enum segment cannot contain `single_confirmation`). sqlc parsing/generation is the non-live migration syntax gate; live PostgreSQL remains Task 6 when no DSN is available.

### Endpoint and OpenAPI hardening

- Every facts field is required even when false, zero, or empty. Duplicate/null/trailing/unknown/noncanonical data remains rejected.
- Idempotency and attestation headers are single-valued, bounded, and canonical. Requester still comes only from session/CaseTicket actor.
- OpenAPI documents required headers, all required facts/attestation timing fields, policy version, and that AgentAtlas BFF signs server-side while UI users never receive the secret.

## TDD RED/GREEN Evidence

### Risk classification

1. RED: `go test ./internal/approval -count=1`
   - Failed to compile because `RiskInput`, `RiskReason`, and `ClassifyRisk` did not exist.
2. GREEN: added typed risk levels, canonical reason codes, enterprise thresholds/minimum, requested-risk raise-only handling, stable sorted/deduplicated non-nil reasons.
3. RED: `go test ./internal/approval -run TestClassifyRiskForcesHighForGovernedChanges -count=1`
   - Workflow/SOP behavior changed fields remained low.
4. GREEN: workflow/SOP behavior fields now force high with `published_behavior_change`.

Covered forced-high reasons: published workflow/SOP behavior, permission/approval changes, evidence requirements, execution deadlines, and external side effects. Covered enterprise minimum, configured org/user thresholds, override raise/no-lower behavior, and stable reasons.

### Immutable snapshot and upward resolver

1. RED: `go test ./internal/approval -run 'TestResolve' -count=1`
   - Failed to compile because permission, immutable snapshot, route, and resolver APIs did not exist.
2. GREEN: added immutable `OrgSnapshot`, complete graph validation, bounded depth/size, requester exclusion, stable candidate ordering, explicit-permission checks, upward review, and administrator fallback.
3. GREEN verification: `go test ./internal/approval -run 'TestResolve|TestNewOrgSnapshot' -count=1`.

Covered authorized low single confirmation (`auto_publish=false`), unauthorized low upward review, medium/high upward review, multi-level ascent, unconditional self-exclusion, unauthorized manager skipping, stable nearest candidate selection, root/no-reviewer administrator queue, cross-enterprise/stale/missing target, cycle/dangling/duplicate rows, size limits, cancellation, and permission unavailability.

### Migration and sqlc contract

1. RED: `go test ./internal/approval -run 'TestApproval(Migration|Queries)' -count=1`
   - Failed because `000005_governed_approval_routes.sql` and `db/queries/approval.sql` did not exist.
2. GREEN: added empty-table pre-release guard, org-version and snapshot-unit foreign keys, sealed-version trigger, canonical/non-empty checks, self-review prohibition, route enums/shape, JSONB route evidence, hashes, and complete Down migration; added tenant/version-scoped queries with limit+1.
3. RED: migration contract subsequently failed on missing canonical empty-value database checks.
4. GREEN: added canonical/non-empty constraints for requester/resource/action/unit/reviewer/queue values.
5. sqlc generation succeeded twice; SHA256 values for `approval.sql.go` and `models.go` were identical across both runs.

No live PostgreSQL DSN was available. SQL parsing/generation and transaction fakes are covered here; live migration/FK/contention remains the explicitly deferred Task 6 gate.

### Memory and PostgreSQL atomic persistence

1. RED: `go test ./internal/app -run TestMemoryApprovalStore -count=1`
   - Failed to compile because the memory store/stages did not exist.
2. GREEN: memory store now atomically stages queue and audit, audits direct low routes, rolls back injected queue/audit failures, and serializes concurrent hash-chain appends.
3. RED: `go test ./internal/app -run TestPostgresApprovalStore -count=1`
   - Failed to compile because the PostgreSQL transaction/store interfaces did not exist.
4. GREEN: one transaction now executes enterprise advisory lock, latest hash read, conditional queue insert, audit append, and commit in that order. Queue or audit failure rolls back; direct low skips queue but still audits.

Audit records contain canonical SHA-256 input/output evidence hashes and binding metadata, not raw change contents. IDs use `crypto/rand` in production.

### Sealed PostgreSQL source and AgentAtlas adapter

1. RED: `go test ./internal/app -run TestPostgresApprovalSource -count=1`
   - Failed to compile because the PostgreSQL source/transaction interface did not exist.
2. GREEN: source uses read-only repeatable-read, exact latest sealed version, enterprise/version row revalidation, limit+1 checks, and a fixed in-memory snapshot adapter around the Task 3 `AgentAtlasEvaluator`.

Tests prove a `manager` role has no implicit approval permission and only explicit `publish_low_risk`/`approve_high_risk` semantics can allow routing.

### Strict HTTP endpoint, timeout, OpenAPI, and main wiring

1. RED: `go test ./internal/app -run 'TestApproval' -count=1`
   - Failed to compile because the handler/dependency contract did not exist.
2. GREEN: added session-or-CaseTicket actor reuse, body-only risk input, strict JSON/content type, requester override rejection, no-store, non-leaking retryable failures, route resolution, and persistence.
3. RED: approval timeout test blocked because `/v1/approvals/resolve` was not included in the protected deadline path; the test command was terminated after confirming the missing deadline.
4. GREEN: approval path was added to deadline/no-store middleware.
5. RED: oversized body returned 400 instead of explicit 413.
6. GREEN: bounded read now returns 413 above 16 KiB.
7. RED: OpenAPI contract failed because `/v1/approvals/resolve` was absent.
8. GREEN: added operation and strict request schema without requester fields; frozen `ApprovalRoute` remains unchanged.
9. RED: production approval factory test failed because `productionApprovalDependencies` did not exist.
10. GREEN: executable factory returns real PostgreSQL source/store adapters; nil pool fails closed. ServeMux behavior confirms approval, authorization, and browser-session protected routes remain registered together.

Strict HTTP coverage includes single Content-Type, JSON object, unknown keys, duplicate keys, nulls, trailing documents, canonical unique arrays, 16 KiB limit, session actor, CaseTicket actor, no-store, timeout, and candidate/error non-disclosure.

## Final Verification

Run from `services/agentnexus`:

- `go test ./internal/approval ./internal/app ./internal/policy ./db/generated -run 'Approval|Atlas|Authorization' -count=20`
  - PASS: approval, app, and policy; generated package has no tests.
- `go test ./... -count=1`
  - PASS: all packages, including gateway API, app, approval, policy, Task 2/3 packages, e2e, and integration.
- `go vet ./...`
  - PASS.
- `go build -buildvcs=false -o $TEMP/agentnexus-connector-agent.exe ./cmd/connector-agent`
  - PASS.
- `go build -buildvcs=false -o $TEMP/agentnexus-connector-worker.exe ./cmd/connector-worker`
  - PASS.
- `go build -buildvcs=false -o $TEMP/agentnexus-gateway-agent.exe ./cmd/gateway-agent`
  - PASS.
- `go build -buildvcs=false -o $TEMP/agentnexus-gateway-api.exe ./cmd/gateway-api`
  - PASS.
- `git diff --check`
  - PASS; only Git line-ending notices were emitted.

Race testing was not run because `gcc` is not installed (`gcc` command not found). This is an environment limitation, not a passing race claim.

## Security and Correctness Self-Review

- Risk cannot decrease: deterministic rules force high, enterprise minimum and impact thresholds only raise, requested override only applies when higher.
- Low-risk direct route requires explicit requester `publish_low_risk`; it remains user confirmation and never auto-publishes.
- Medium/high and unauthorized low require an explicit authorized reviewer or the exact `enterprise_knowledge_admin` queue.
- Requester is excluded before every candidate permission check; DB also rejects reviewer=requester.
- Manager/admin roles confer no implicit publish/approval permission.
- Every source row and permission request is bound to the same enterprise and exact sealed org version; live org tables are not used for routing.
- Full graph validation rejects stale/missing/cross-tenant/cycle/dangling/duplicate/over-limit input and cancellation fails closed.
- Queue insertion and audit-chain append share one PostgreSQL transaction and enterprise advisory lock. Any queue/audit/commit failure prevents success.
- Direct low route also appends an audit event, but does not create a queue item.
- Migration Down removes trigger/function/constraints/columns in dependency-safe order. Existing untrusted rows abort Up instead of receiving fabricated evidence.
- Responses contain only the selected reviewer or administrator queue, never candidate lists or backend errors.
- Required JSON arrays are non-nil; reviewer/queue optional fields are emitted only for their matching frozen route modes; `auto_publish` is always false.

## Files

- `services/agentnexus/internal/approval/risk.go`
- `services/agentnexus/internal/approval/resolver.go`
- `services/agentnexus/internal/approval/*_test.go`
- `services/agentnexus/internal/app/approval.go`
- `services/agentnexus/internal/app/approval_store.go`
- `services/agentnexus/internal/app/postgres_approval_source.go`
- `services/agentnexus/internal/app/postgres_approval_store.go`
- corresponding `internal/app/*approval*_test.go`
- `services/agentnexus/db/migrations/000005_governed_approval_routes.sql`
- `services/agentnexus/db/queries/approval.sql`
- `services/agentnexus/db/generated/approval.sql.go`
- `services/agentnexus/db/generated/models.go`
- `services/agentnexus/api/openapi/gateway-runtime.yaml`
- `services/agentnexus/internal/app/browser_auth.go`
- `services/agentnexus/internal/app/gateway_api.go`
- `services/agentnexus/cmd/gateway-api/main.go`
- related OpenAPI/main tests
