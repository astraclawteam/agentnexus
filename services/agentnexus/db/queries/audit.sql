-- name: AppendAuditEvent :one
INSERT INTO audit_events (
    id,
    enterprise_id,
    case_ticket_id,
    step_grant_id,
    actor_user_id,
    connector_instance_id,
    resource_type,
    resource_id,
    action,
    decision,
    input_hash,
    output_hash,
    evidence_pointer,
    prev_hash,
	event_hash,
	created_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    GREATEST(
        clock_timestamp(),
        COALESCE((SELECT MAX(created_at) + INTERVAL '1 microsecond' FROM audit_events WHERE enterprise_id = $2), clock_timestamp())
    )
)
RETURNING id, enterprise_id, case_ticket_id, step_grant_id, actor_user_id, connector_instance_id, resource_type, resource_id, action, decision, input_hash, output_hash, evidence_pointer, prev_hash, event_hash, created_at, tenant_seq, signature_algorithm, signature_key_id, signature_value, signed_at, status_from, capability, parameter_hash, grant_ref, approval_evidence_ref, receipt_ref, risk_authority, agent_client_ref, agent_release_ref, org_snapshot_ref;

-- AllocateNextTenantSeq returns the next per-tenant monotonic sequence value
-- (starts at 1). It MUST run under the per-enterprise advisory lock
-- (AcquireEnterpriseAuditLock) so concurrent appends serialize and never
-- allocate a duplicate; the partial unique index is the database backstop.
-- name: AllocateNextTenantSeq :one
SELECT (COALESCE(MAX(tenant_seq), 0) + 1)::BIGINT AS next_seq
FROM audit_events
WHERE enterprise_id = $1;

-- AppendSignedAuditEvent appends one SIGNED, tenant-sequenced audit event with
-- its first-class binding refs (GA Task 0G). The created_at monotonicity mirrors
-- AppendAuditEvent; tenant_seq, the ed25519 signature triple, signed_at and the
-- recoverable binding columns are supplied by the signing writer.
-- name: AppendSignedAuditEvent :one
INSERT INTO audit_events (
    id,
    enterprise_id,
    case_ticket_id,
    step_grant_id,
    actor_user_id,
    connector_instance_id,
    resource_type,
    resource_id,
    action,
    decision,
    input_hash,
    output_hash,
    evidence_pointer,
    prev_hash,
    event_hash,
    tenant_seq,
    signature_algorithm,
    signature_key_id,
    signature_value,
    signed_at,
    status_from,
    capability,
    parameter_hash,
    grant_ref,
    approval_evidence_ref,
    receipt_ref,
    risk_authority,
    agent_client_ref,
    agent_release_ref,
    org_snapshot_ref,
    created_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
    $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
    GREATEST(
        clock_timestamp(),
        COALESCE((SELECT MAX(created_at) + INTERVAL '1 microsecond' FROM audit_events WHERE enterprise_id = $2), clock_timestamp())
    )
)
RETURNING id, enterprise_id, case_ticket_id, step_grant_id, actor_user_id, connector_instance_id, resource_type, resource_id, action, decision, input_hash, output_hash, evidence_pointer, prev_hash, event_hash, created_at, tenant_seq, signature_algorithm, signature_key_id, signature_value, signed_at, status_from, capability, parameter_hash, grant_ref, approval_evidence_ref, receipt_ref, risk_authority, agent_client_ref, agent_release_ref, org_snapshot_ref;

-- name: ListAuditEventsForTicket :many
SELECT id, enterprise_id, case_ticket_id, step_grant_id, actor_user_id, connector_instance_id, resource_type, resource_id, action, decision, input_hash, output_hash, evidence_pointer, prev_hash, event_hash, created_at, tenant_seq, signature_algorithm, signature_key_id, signature_value, signed_at, status_from, capability, parameter_hash, grant_ref, approval_evidence_ref, receipt_ref, risk_authority, agent_client_ref, agent_release_ref, org_snapshot_ref
FROM audit_events
WHERE enterprise_id = $1 AND case_ticket_id = $2
ORDER BY created_at ASC;

-- ListSignedAuditEventsForTenant returns the FULL signed per-tenant chain in
-- sequence order (the verify/export read path). Legacy unsigned rows (NULL
-- tenant_seq) are excluded.
-- name: ListSignedAuditEventsForTenant :many
SELECT id, enterprise_id, case_ticket_id, step_grant_id, actor_user_id, connector_instance_id, resource_type, resource_id, action, decision, input_hash, output_hash, evidence_pointer, prev_hash, event_hash, created_at, tenant_seq, signature_algorithm, signature_key_id, signature_value, signed_at, status_from, capability, parameter_hash, grant_ref, approval_evidence_ref, receipt_ref, risk_authority, agent_client_ref, agent_release_ref, org_snapshot_ref
FROM audit_events
WHERE enterprise_id = $1 AND tenant_seq IS NOT NULL
ORDER BY tenant_seq ASC;

-- CountSignedAuditEventsForTenant reports how many signed events a tenant chain
-- holds; a chain read that returns fewer than a persisted checkpoint's last_seq
-- has been truncated.
-- name: CountSignedAuditEventsForTenant :one
SELECT COUNT(*)::BIGINT AS signed_count
FROM audit_events
WHERE enterprise_id = $1 AND tenant_seq IS NOT NULL;

-- name: GetAuditEventByID :one
SELECT * FROM audit_events WHERE enterprise_id=$1 AND id=$2;

-- name: AcquireEnterpriseAuditLock :one
SELECT pg_advisory_xact_lock(hashtextextended($1, 1));

-- name: GetLatestEnterpriseAuditHash :one
SELECT COALESCE((
    SELECT event_hash FROM audit_events
    WHERE enterprise_id = $1
    ORDER BY created_at DESC, id DESC
    LIMIT 1
), '')::TEXT AS event_hash;

-- GetLatestSignedEnterpriseAuditHash returns the head of the SIGNED sub-chain
-- (highest tenant_seq). The signed action-lineage chain links signed->signed so
-- ListSignedAuditEventsForTenant is a self-contained, gap-free verifiable chain
-- independent of interleaved legacy (unsigned) lineage rows. It MUST run under
-- the per-enterprise advisory lock together with AllocateNextTenantSeq.
-- name: GetLatestSignedEnterpriseAuditHash :one
SELECT COALESCE((
    SELECT event_hash FROM audit_events
    WHERE enterprise_id = $1 AND tenant_seq IS NOT NULL
    ORDER BY tenant_seq DESC
    LIMIT 1
), '')::TEXT AS event_hash;

-- name: UpsertAuditSigningKey :one
INSERT INTO audit_signing_keys (key_id, algorithm, public_key)
VALUES ($1, $2, $3)
ON CONFLICT (key_id) DO UPDATE
    SET algorithm = EXCLUDED.algorithm,
        public_key = EXCLUDED.public_key
RETURNING key_id, algorithm, public_key, status, created_at, revoked_at;

-- name: GetAuditSigningKey :one
SELECT key_id, algorithm, public_key, status, created_at, revoked_at
FROM audit_signing_keys
WHERE key_id = $1;

-- name: ListAuditSigningKeys :many
SELECT key_id, algorithm, public_key, status, created_at, revoked_at
FROM audit_signing_keys
ORDER BY key_id ASC;

-- name: RevokeAuditSigningKey :one
UPDATE audit_signing_keys
SET status = 'revoked', revoked_at = $2
WHERE key_id = $1
RETURNING key_id, algorithm, public_key, status, created_at, revoked_at;

-- name: InsertAuditBatchRoot :one
INSERT INTO audit_batch_roots (
    id, enterprise_id, root_hash, first_seq, last_seq, event_count,
    signed_at, signature_algorithm, signature_key_id, signature_value
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id, enterprise_id, root_hash, first_seq, last_seq, event_count, signed_at, signature_algorithm, signature_key_id, signature_value, created_at;

-- name: ListAuditBatchRoots :many
SELECT id, enterprise_id, root_hash, first_seq, last_seq, event_count, signed_at, signature_algorithm, signature_key_id, signature_value, created_at
FROM audit_batch_roots
WHERE enterprise_id = $1
ORDER BY first_seq ASC;

-- GetLatestAuditBatchRoot returns the most recent persisted batch-root
-- checkpoint for a tenant (highest last_seq), or no row when none exists. The
-- truncation check compares the live signed-chain head against last_seq.
-- name: GetLatestAuditBatchRoot :one
SELECT id, enterprise_id, root_hash, first_seq, last_seq, event_count, signed_at, signature_algorithm, signature_key_id, signature_value, created_at
FROM audit_batch_roots
WHERE enterprise_id = $1
ORDER BY last_seq DESC
LIMIT 1;
