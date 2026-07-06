-- name: CreateCaseTicket :one
INSERT INTO case_tickets (id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at;

-- name: GetCaseTicket :one
SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at
FROM case_tickets
WHERE enterprise_id = $1 AND id = $2;

-- name: ListCaseTickets :many
SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at
FROM case_tickets
WHERE enterprise_id = $1
ORDER BY created_at DESC;

-- name: CreateStepGrant :one
INSERT INTO step_grants (id, enterprise_id, case_ticket_id, resource_type, resource_id, action, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, enterprise_id, case_ticket_id, resource_type, resource_id, action, scopes, expires_at, created_at;
