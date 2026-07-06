-- name: CreateEnterprise :one
INSERT INTO enterprises (id, name)
VALUES ($1, $2)
RETURNING id, name, created_at;

-- name: GetEnterprise :one
SELECT id, name, created_at
FROM enterprises
WHERE id = $1;

-- name: ListEnterprises :many
SELECT id, name, created_at
FROM enterprises
ORDER BY created_at DESC;
