-- Approval transmission queries (GA Task 0E). AgentNexus transmits the
-- caller's signed plan unchanged and validates returned evidence; there is
-- no approver selection, organization walking or queue routing here.

-- name: AcquireApprovalTransmissionLock :one
-- Per-plan advisory lock serializing delivery-attempt, evidence and
-- revocation mutations of one transmission. Two-int form with two SEPARATE
-- text parameters (LockOIDCLoginAttemptScope precedent): PostgreSQL rejects
-- NUL bytes in text parameters, so tenant and plan are never joined into one
-- delimited string. The 'apt:' salt domain-separates this lock space from
-- the OIDC scope locks that share the two-int form.
SELECT pg_advisory_xact_lock(
    hashtext('apt:' || sqlc.arg(tenant_ref)::text),
    hashtext(sqlc.arg(plan_ref))
);

-- name: InsertApprovalTransmission :execrows
INSERT INTO approval_transmissions (
    tenant_ref, plan_ref, plan_hash, authority, business_context_ref,
    capability, parameter_hash, purpose, status, expires_at,
    audit_ref_id, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11, $11)
ON CONFLICT (tenant_ref, plan_ref) DO NOTHING;

-- name: GetApprovalTransmission :one
SELECT tenant_ref, plan_ref, plan_hash, authority, business_context_ref,
       capability, parameter_hash, purpose, status, expires_at,
       delivery_attempts, last_delivery_outcome, last_delivery_reason,
       decision, decided_at, revoked_at, revocation_reason, audit_ref_id,
       created_at, updated_at
FROM approval_transmissions
WHERE tenant_ref = $1 AND plan_ref = $2;

-- name: InsertApprovalDeliveryAttempt :execrows
INSERT INTO approval_delivery_attempts (tenant_ref, plan_ref, attempt, outcome, reason, created_at)
SELECT $1, $2, COALESCE(MAX(attempt), 0) + 1, $3, $4, $5
FROM approval_delivery_attempts
WHERE tenant_ref = $1 AND plan_ref = $2;

-- name: UpdateApprovalTransmissionDelivery :execrows
UPDATE approval_transmissions
SET delivery_attempts = delivery_attempts + 1,
    last_delivery_outcome = $3,
    last_delivery_reason = $4,
    status = CASE WHEN $3 = 'delivered' AND status = 'pending' THEN 'delivered' ELSE status END,
    updated_at = $5
WHERE tenant_ref = $1 AND plan_ref = $2;

-- name: InsertApprovalEvidenceRecord :execrows
INSERT INTO approval_evidence_records (
    tenant_ref, approval_ref, plan_ref, plan_hash, capability, parameter_hash,
    decision, approver_authority, decided_at, evidence_hash, attestation,
    audit_ref_id, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT DO NOTHING;

-- name: GetApprovalEvidenceByRef :one
SELECT tenant_ref, approval_ref, plan_ref, plan_hash, capability, parameter_hash,
       decision, approver_authority, decided_at, evidence_hash, attestation,
       audit_ref_id, consumed_at, created_at
FROM approval_evidence_records
WHERE tenant_ref = $1 AND approval_ref = $2;

-- name: GetApprovalEvidenceByPlan :one
SELECT tenant_ref, approval_ref, plan_ref, plan_hash, capability, parameter_hash,
       decision, approver_authority, decided_at, evidence_hash, attestation,
       audit_ref_id, consumed_at, created_at
FROM approval_evidence_records
WHERE tenant_ref = $1 AND plan_ref = $2;

-- name: UpdateApprovalTransmissionEvidence :execrows
UPDATE approval_transmissions
SET status = 'evidence_recorded',
    decision = $3,
    decided_at = $4,
    updated_at = $5
WHERE tenant_ref = $1 AND plan_ref = $2 AND status IN ('pending', 'delivered');

-- name: InsertApprovalRevocation :execrows
INSERT INTO approval_transmission_revocations (tenant_ref, revocation_id, plan_ref, reason, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT DO NOTHING;

-- name: UpdateApprovalTransmissionRevoked :execrows
UPDATE approval_transmissions
SET status = 'revoked',
    revoked_at = $3,
    revocation_reason = $4,
    updated_at = $3
WHERE tenant_ref = $1 AND plan_ref = $2 AND status <> 'revoked';
