-- name: CreateEnterpriseUser :one
INSERT INTO enterprise_users (id, enterprise_id, display_name, email, phone)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, enterprise_id, display_name, email, phone, created_at;

-- name: GetEnterpriseUser :one
SELECT id, enterprise_id, display_name, email, phone, created_at
FROM enterprise_users
WHERE enterprise_id = $1 AND id = $2;

-- name: ListEnterpriseUsers :many
SELECT id, enterprise_id, display_name, email, phone, created_at
FROM enterprise_users
WHERE enterprise_id = $1
ORDER BY created_at DESC;

-- name: CreateOrgUnit :one
INSERT INTO org_units (id, enterprise_id, parent_id, name, unit_type)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, enterprise_id, parent_id, name, unit_type, created_at;

-- name: CreateOrgMembership :one
INSERT INTO org_memberships (enterprise_id, enterprise_user_id, org_unit_id, role)
VALUES ($1, $2, $3, $4)
RETURNING enterprise_id, enterprise_user_id, org_unit_id, role, created_at;

-- name: CreateOrgEventForPolicyPublication :one
INSERT INTO org_events (id, enterprise_id, event_type, source_hash)
VALUES ($1, $2, $3, $4)
RETURNING id, enterprise_id, event_type, source_hash, created_at;

-- name: CreateOrgVersion :one
INSERT INTO org_versions (id, enterprise_id, version_number, source_event_id)
VALUES ($1, $2, $3, $4)
RETURNING id, enterprise_id, version_number, source_event_id, created_at, policy_snapshot_sealed;

-- name: GetLatestAuthorizationOrgVersion :one
SELECT version_number
FROM org_versions
WHERE enterprise_id = $1
  AND policy_snapshot_sealed = true
ORDER BY version_number DESC
LIMIT 1;

-- name: ListAuthorizationOrgUnits :many
SELECT enterprise_id, version_number, org_unit_id, parent_id
FROM org_policy_snapshot_units
WHERE enterprise_id = $1
  AND version_number = $2
ORDER BY org_unit_id
LIMIT 10001;

-- name: ListAuthorizationMemberships :many
SELECT enterprise_id, version_number, enterprise_user_id, org_unit_id, role
FROM org_policy_snapshot_memberships
WHERE enterprise_id = $1
  AND version_number = $2
  AND enterprise_user_id = $3
ORDER BY org_unit_id, role
LIMIT 100001;

-- name: CaptureOrgPolicySnapshotUnits :exec
INSERT INTO org_policy_snapshot_units (enterprise_id, version_number, org_unit_id, parent_id)
SELECT u.enterprise_id, $2, u.id, u.parent_id
FROM org_units AS u
WHERE u.enterprise_id = $1;

-- name: CaptureOrgPolicySnapshotMemberships :exec
INSERT INTO org_policy_snapshot_memberships (
    enterprise_id, version_number, enterprise_user_id, org_unit_id, role
)
SELECT m.enterprise_id, $2, m.enterprise_user_id, m.org_unit_id, m.role
FROM org_memberships AS m
WHERE m.enterprise_id = $1;

-- name: SealOrgPolicySnapshot :one
UPDATE org_versions
SET policy_snapshot_sealed = true
WHERE enterprise_id = $1
  AND version_number = $2
  AND policy_snapshot_sealed = false
RETURNING id, enterprise_id, version_number, source_event_id, created_at, policy_snapshot_sealed;
