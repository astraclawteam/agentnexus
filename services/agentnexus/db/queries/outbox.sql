-- Transactional outbox queries (GA Task 0F). The outbox row is the durable
-- dispatch intent written atomically with the granted->dispatched transition;
-- the recovery pump publishes pending rows exactly once.

-- name: InsertActionOutbox :execrows
INSERT INTO action_outbox (
    tenant_ref, dispatch_ref, action_ref, capability, parameter_hash,
    grant_ref, kind, published, attempts, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, false, 0, $8);

-- name: ListPendingActionOutbox :many
SELECT tenant_ref, dispatch_ref, action_ref, capability, parameter_hash,
       grant_ref, kind, published, attempts, created_at, published_at
FROM action_outbox
WHERE tenant_ref = $1 AND published = false
ORDER BY created_at
LIMIT $2;

-- name: MarkActionOutboxPublished :execrows
UPDATE action_outbox
SET published = true, attempts = attempts + 1, published_at = $3
WHERE tenant_ref = $1 AND dispatch_ref = $2 AND published = false;
