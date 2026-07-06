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
    event_hash
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING id, enterprise_id, case_ticket_id, step_grant_id, actor_user_id, connector_instance_id, resource_type, resource_id, action, decision, input_hash, output_hash, evidence_pointer, prev_hash, event_hash, created_at;

-- name: ListAuditEventsForTicket :many
SELECT id, enterprise_id, case_ticket_id, step_grant_id, actor_user_id, connector_instance_id, resource_type, resource_id, action, decision, input_hash, output_hash, evidence_pointer, prev_hash, event_hash, created_at
FROM audit_events
WHERE enterprise_id = $1 AND case_ticket_id = $2
ORDER BY created_at ASC;
