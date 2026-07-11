-- name: GetGrantResourceOwner :one
SELECT enterprise_id, resource_type, resource_id, org_version, org_unit_id, updated_at
FROM sensitive_resource_ownerships
WHERE enterprise_id = $1 AND resource_type = $2 AND resource_id = $3;

-- name: GetGrantResourceOwnerForGrant :one
SELECT enterprise_id, resource_type, resource_id, org_version, org_unit_id, updated_at
FROM sensitive_resource_ownerships
WHERE enterprise_id = $1 AND resource_type = $2 AND resource_id = $3;

-- name: GetLatestGrantOrgVersion :one
SELECT version_number
FROM org_versions
WHERE enterprise_id = $1 AND policy_snapshot_sealed = true
ORDER BY version_number DESC LIMIT 1;

-- name: GetActiveCaseTicketForGrant :one
SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at, token_hash
FROM case_tickets
WHERE enterprise_id=$1 AND id=$2 AND actor_user_id=$3 AND status='active' AND expires_at>$4
FOR SHARE;

-- name: InsertStepGrantIssuance :one
INSERT INTO step_grant_issuances (
    enterprise_id, step_grant_id, token_hash, actor_user_id,
    org_version, org_unit_id, audit_event_id, expected_audit_input_hash,
    expected_audit_output_hash, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING enterprise_id, step_grant_id, token_hash, actor_user_id, org_version, org_unit_id, audit_event_id, expected_audit_input_hash, expected_audit_output_hash, created_at;

-- name: GetStepGrantByTokenHash :one
SELECT g.id, g.enterprise_id, g.case_ticket_id, g.resource_type, g.resource_id,
       g.action, g.scopes, g.expires_at, g.created_at,
       i.token_hash, i.actor_user_id, i.org_version, i.org_unit_id
FROM step_grants g
JOIN step_grant_issuances i ON i.enterprise_id=g.enterprise_id AND i.step_grant_id=g.id
WHERE i.enterprise_id = $1 AND i.token_hash = $2;
