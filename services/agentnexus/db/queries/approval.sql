-- name: GetLatestApprovalOrgVersion :one
SELECT version_number
FROM org_versions
WHERE enterprise_id = $1
  AND policy_snapshot_sealed = true
ORDER BY version_number DESC
LIMIT 1;

-- name: GetEnterpriseApprovalPolicy :one
SELECT enterprise_id, minimum_risk, max_low_impacted_users, max_low_impacted_org_units,
       policy_version, updated_at
FROM enterprise_approval_policies
WHERE enterprise_id = $1;

-- name: GetCurrentApprovalPolicyVersion :one
SELECT COALESCE((
    SELECT policy_version FROM enterprise_approval_policies WHERE enterprise_id = $1
), 0)::BIGINT AS policy_version;

-- name: AcquireEnterpriseOrgPublicationLock :one
SELECT pg_advisory_xact_lock(hashtextextended($1, 0));

-- name: ListApprovalOrgUnits :many
SELECT enterprise_id, version_number, org_unit_id, parent_id
FROM org_policy_snapshot_units
WHERE enterprise_id = $1
  AND version_number = $2
ORDER BY org_unit_id
LIMIT 10001;

-- name: ListApprovalMemberships :many
SELECT enterprise_id, version_number, enterprise_user_id, org_unit_id, role
FROM org_policy_snapshot_memberships
WHERE enterprise_id = $1
  AND version_number = $2
  AND role IN ('manager', 'publish_low_risk', 'approve_high_risk')
ORDER BY enterprise_user_id, org_unit_id, role
LIMIT 100001;

-- name: ListApprovalUsers :many
SELECT users.id, users.enterprise_id, users.display_name
FROM enterprise_users AS users
WHERE users.enterprise_id = $1
  AND EXISTS (
      SELECT 1
      FROM org_policy_snapshot_memberships AS memberships
      WHERE memberships.enterprise_id = $1
        AND memberships.version_number = $2
        AND memberships.enterprise_user_id = users.id
        AND memberships.role IN ('manager', 'publish_low_risk', 'approve_high_risk')
  )
ORDER BY users.id
LIMIT 100001;

-- name: InsertApprovalQueueItem :one
INSERT INTO approval_queue_items (
    id, enterprise_id, requester_user_id, resource_type, resource_id, action,
    risk_level, org_unit_id, reviewer_user_id, status, org_version,
    risk_reasons, route_mode, org_path, queue, route_input_hash, route_output_hash, policy_version, policy_version_ref,
    idempotency_key_hash, reviewer_org_unit_id, reviewer_display_name
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10,
    $11, $12, $13, $14, $15, $16, $17, NULLIF($17, 0), $18, $19, $20
)
RETURNING id, enterprise_id, requester_user_id, resource_type, resource_id, action,
    risk_level, org_unit_id, reviewer_user_id, status, created_at, org_version,
    risk_reasons, route_mode, org_path, queue, route_input_hash, route_output_hash, policy_version, policy_version_ref,
    idempotency_key_hash, reviewer_org_unit_id, reviewer_display_name;

-- name: InsertApprovalResolution :execrows
INSERT INTO approval_resolution_idempotency (
    enterprise_id, idempotency_key_hash, request_hash, requester_user_id, org_version, org_unit_id,
    policy_version, policy_version_ref, resource_type, resource_id, action, route_mode, risk_level,
    risk_reasons, reviewer_user_id, reviewer_org_unit_id, reviewer_display_name, org_path, queue, auto_publish,
    queue_item_id, audit_event_id
)
VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($7,0),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,false,$19,$20)
ON CONFLICT (enterprise_id, idempotency_key_hash) DO NOTHING;

-- name: GetApprovalResolution :one
SELECT enterprise_id, idempotency_key_hash, request_hash, requester_user_id, org_version, org_unit_id,
       policy_version, policy_version_ref, resource_type, resource_id, action, route_mode, risk_level,
       risk_reasons, reviewer_user_id, reviewer_org_unit_id, reviewer_display_name, org_path, queue, auto_publish,
       queue_item_id, audit_event_id, created_at
FROM approval_resolution_idempotency
WHERE enterprise_id = $1 AND idempotency_key_hash = $2;
