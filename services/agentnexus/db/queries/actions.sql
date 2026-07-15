-- Durable action queries (GA Task 0F). One logical Action, its one-use grant,
-- the dedup inbox and the immutable execution receipts. Every mutation is
-- serialized under a per-action advisory lock and guarded by the 000010
-- triggers.

-- name: AcquireActionLock :one
-- Per-action advisory lock serializing an action's transitions. Two-int form
-- with two SEPARATE text parameters (approvaltransport C1 precedent):
-- PostgreSQL rejects NUL bytes in text parameters, so tenant and action are
-- never joined into one delimited string. The 'act:' salt domain-separates
-- this lock space from the 'apt:'/'agt:' locks that share the two-int form.
SELECT pg_advisory_xact_lock(
    hashtext('act:' || sqlc.arg(tenant_ref)::text),
    hashtext(sqlc.arg(action_ref)::text)
);

-- name: InsertAction :execrows
INSERT INTO actions (
    tenant_ref, action_ref, status, business_context_ref, capability,
    parameter_hash, idempotency_key, risk_authority, risk_level,
    approval_plan_ref, compensation_ref, compensation_of,
    expected_receipt_schema, postconditions, verification_needs, expires_at,
    audit_ref_id, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $18)
ON CONFLICT (tenant_ref, idempotency_key) DO NOTHING;

-- name: GetAction :one
SELECT tenant_ref, action_ref, status, business_context_ref, capability,
       parameter_hash, idempotency_key, risk_authority, risk_level,
       approval_plan_ref, grant_ref, approval_evidence_ref, receipt_ref,
       compensation_ref, compensation_of, expected_receipt_schema,
       postconditions, verification_needs, expires_at, failure_reason,
       audit_ref_id, created_at, updated_at
FROM actions
WHERE tenant_ref = $1 AND action_ref = $2;

-- name: GetActionByIdempotencyKey :one
SELECT tenant_ref, action_ref, status, business_context_ref, capability,
       parameter_hash, idempotency_key, risk_authority, risk_level,
       approval_plan_ref, grant_ref, approval_evidence_ref, receipt_ref,
       compensation_ref, compensation_of, expected_receipt_schema,
       postconditions, verification_needs, expires_at, failure_reason,
       audit_ref_id, created_at, updated_at
FROM actions
WHERE tenant_ref = $1 AND idempotency_key = $2;

-- name: GrantAction :execrows
UPDATE actions
SET status = 'granted', grant_ref = $3, approval_evidence_ref = $4, updated_at = $5
WHERE tenant_ref = $1 AND action_ref = $2 AND status IN ('requested', 'awaiting_approval');

-- name: DispatchAction :execrows
UPDATE actions
SET status = 'dispatched', updated_at = $3
WHERE tenant_ref = $1 AND action_ref = $2 AND status = 'granted';

-- name: TransitionAction :execrows
UPDATE actions
SET status = $3,
    failure_reason = CASE WHEN $4::text <> '' THEN $4::text ELSE failure_reason END,
    updated_at = $5
WHERE tenant_ref = $1 AND action_ref = $2 AND status = $6;

-- name: CompleteAction :execrows
UPDATE actions
SET status = $3, receipt_ref = $4, updated_at = $5
WHERE tenant_ref = $1 AND action_ref = $2 AND status IN ('executing', 'dispatched', 'reconciling');

-- name: InsertActionGrant :execrows
INSERT INTO action_grants (
    tenant_ref, grant_ref, action_ref, business_context_ref, capability,
    parameter_hash, one_use, issued_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8)
ON CONFLICT (tenant_ref, action_ref) DO NOTHING;

-- name: GetActionGrant :one
SELECT tenant_ref, grant_ref, action_ref, business_context_ref, capability,
       parameter_hash, one_use, issued_at, expires_at, consumed_at
FROM action_grants
WHERE tenant_ref = $1 AND action_ref = $2;

-- name: ConsumeActionGrant :one
-- One-use consumption: stamp consumed_at exactly once. A second consume matches
-- no row (pgx.ErrNoRows); the 000010 guard_action_grant_consume trigger permits
-- precisely this NULL->NOT-NULL update.
UPDATE action_grants
SET consumed_at = $3
WHERE tenant_ref = $1 AND action_ref = $2 AND consumed_at IS NULL
RETURNING grant_ref;

-- name: InsertActionReceipt :execrows
INSERT INTO action_receipts (
    tenant_ref, receipt_ref, action_ref, status, capability, parameter_hash,
    receipt_schema, result, result_hash, issued_at, signature, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_ref, receipt_ref) DO NOTHING;

-- name: GetActionReceipt :one
SELECT tenant_ref, receipt_ref, action_ref, status, capability, parameter_hash,
       receipt_schema, result, result_hash, issued_at, signature, created_at
FROM action_receipts
WHERE tenant_ref = $1 AND receipt_ref = $2;

-- name: InsertActionInbox :execrows
-- Connector-result dedup: a redelivered/duplicate result_id is a no-op.
INSERT INTO action_inbox (tenant_ref, result_id, action_ref, receipt_ref, applied_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_ref, result_id) DO NOTHING;

-- name: ActionResultApplied :one
-- Read-only inbox membership by the connector result_id dedup key: reports
-- whether this exact result was already applied. The actions service consults
-- it to distinguish an idempotent duplicate (already applied -> no-op, no audit)
-- from an out-of-order different receipt (not applied -> rejected, no audit)
-- BEFORE emitting any action.completed audit event.
SELECT EXISTS(
    SELECT 1 FROM action_inbox WHERE tenant_ref = $1 AND result_id = $2
);
