-- name: CreateConnectorPackage :one
INSERT INTO connector_packages (id, name, manifest_version)
VALUES ($1, $2, $3)
RETURNING id, name, manifest_version, created_at;

-- name: GetConnectorPackage :one
SELECT id, name, manifest_version, created_at
FROM connector_packages
WHERE id = $1;

-- name: CreateConnectorInstance :one
INSERT INTO connector_instances (id, enterprise_id, connector_package_id, name, status)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, enterprise_id, connector_package_id, name, status, created_at;

-- name: ListConnectorInstances :many
SELECT id, enterprise_id, connector_package_id, name, status, created_at
FROM connector_instances
WHERE enterprise_id = $1
ORDER BY created_at DESC;

-- name: CreateConnectorHealthEvent :one
INSERT INTO connector_health_events (id, enterprise_id, connector_instance_id, status, message)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, enterprise_id, connector_instance_id, status, message, created_at;
