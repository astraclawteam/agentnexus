-- name: CreateCaseTicket :one
INSERT INTO case_tickets (id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, token_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at, token_hash;

-- name: GetCaseTicket :one
SELECT tickets.id, tickets.enterprise_id, tickets.actor_user_id, tickets.request_id,
       tickets.trace_id, tickets.status, tickets.expires_at, tickets.created_at, tickets.token_hash
FROM case_tickets AS tickets
JOIN enterprise_users AS users
  ON users.enterprise_id = tickets.enterprise_id
 AND users.id = tickets.actor_user_id
WHERE tickets.enterprise_id = $1 AND tickets.token_hash = sqlc.arg(token_hash);

-- name: ListCaseTickets :many
SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at, token_hash
FROM case_tickets
WHERE enterprise_id = $1
ORDER BY created_at DESC;

-- name: CreateStepGrant :one
INSERT INTO step_grants (id, enterprise_id, case_ticket_id, resource_type, resource_id, action, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, enterprise_id, case_ticket_id, resource_type, resource_id, action, scopes, expires_at, created_at;
