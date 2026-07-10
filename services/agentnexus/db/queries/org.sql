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

-- name: CreateOrgVersion :one
INSERT INTO org_versions (id, enterprise_id, version_number, source_event_id)
VALUES ($1, $2, $3, $4)
RETURNING id, enterprise_id, version_number, source_event_id, created_at;

-- name: GetLatestAuthorizationOrgVersion :one
SELECT version_number
FROM org_versions
WHERE enterprise_id = $1
ORDER BY version_number DESC
LIMIT 1;

-- name: ListAuthorizationOrgUnits :many
SELECT id, enterprise_id, parent_id, name, unit_type, created_at
FROM org_units
WHERE enterprise_id = $1
ORDER BY id;

-- name: ListAuthorizationMemberships :many
SELECT m.enterprise_id, m.enterprise_user_id, m.org_unit_id, m.role, m.created_at
FROM org_memberships AS m
JOIN org_units AS u
  ON u.enterprise_id = m.enterprise_id
 AND u.id = m.org_unit_id
WHERE m.enterprise_id = $1
  AND m.enterprise_user_id = $2
  AND u.enterprise_id = $1
ORDER BY m.org_unit_id, m.role;
