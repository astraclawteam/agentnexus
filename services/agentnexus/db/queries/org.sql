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
