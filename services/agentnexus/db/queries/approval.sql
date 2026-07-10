-- name: GetLatestApprovalOrgVersion :one
SELECT version_number
FROM org_versions
WHERE enterprise_id = $1
  AND policy_snapshot_sealed = true
ORDER BY version_number DESC
LIMIT 1;

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
  )
ORDER BY users.id
LIMIT 100001;

-- name: InsertApprovalQueueItem :one
INSERT INTO approval_queue_items (
    id, enterprise_id, requester_user_id, resource_type, resource_id, action,
    risk_level, org_unit_id, reviewer_user_id, status, org_version,
    risk_reasons, route_mode, org_path, queue, route_input_hash, route_output_hash
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10,
    $11, $12, $13, $14, $15, $16
)
RETURNING id, enterprise_id, requester_user_id, resource_type, resource_id, action,
    risk_level, org_unit_id, reviewer_user_id, status, created_at, org_version,
    risk_reasons, route_mode, org_path, queue, route_input_hash, route_output_hash;
