-- Transactional outbox queries (GA Task 0F). The outbox row is the durable
-- dispatch intent written atomically with the granted->dispatched transition;
-- the dispatching request publishes it immediately after that commit and the
-- recovery pump republishes whatever a crash or a transport outage left behind.
--
-- Every DELIVERY path goes through a claim (ClaimActionOutbox /
-- ClaimNextActionOutbox): the row is locked FOR UPDATE SKIP LOCKED and the
-- publish + the outcome write happen inside that one transaction. N gateway
-- replicas therefore never publish the same intent concurrently — a replica
-- that does not win the row lock skips it instead of queueing behind it.
-- ListPendingActionOutbox / ListDeadLetteredActionOutbox take no lock: they are
-- read-only observability and must never be used to drive a publish.

-- name: InsertActionOutbox :execrows
INSERT INTO action_outbox (
    tenant_ref, dispatch_ref, action_ref, capability, parameter_hash,
    grant_ref, kind, published, attempts, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, false, 0, $8);

-- name: ListPendingActionOutbox :many
SELECT tenant_ref, dispatch_ref, action_ref, capability, parameter_hash,
       grant_ref, kind, published, attempts, created_at, published_at,
       next_attempt_at, last_error, dead_lettered_at
FROM action_outbox
WHERE tenant_ref = $1 AND published = false AND dead_lettered_at IS NULL
ORDER BY created_at
LIMIT $2;

-- name: ListDeadLetteredActionOutbox :many
SELECT tenant_ref, dispatch_ref, action_ref, capability, parameter_hash,
       grant_ref, kind, published, attempts, created_at, published_at,
       next_attempt_at, last_error, dead_lettered_at
FROM action_outbox
WHERE tenant_ref = $1 AND dead_lettered_at IS NOT NULL
ORDER BY dead_lettered_at
LIMIT $2;

-- name: ClaimActionOutbox :one
SELECT tenant_ref, dispatch_ref, action_ref, capability, parameter_hash,
       grant_ref, kind, published, attempts, created_at, published_at,
       next_attempt_at, last_error, dead_lettered_at
FROM action_outbox
WHERE tenant_ref = $1 AND dispatch_ref = $2
  AND published = false AND dead_lettered_at IS NULL
FOR UPDATE SKIP LOCKED;

-- name: ClaimNextActionOutbox :one
SELECT tenant_ref, dispatch_ref, action_ref, capability, parameter_hash,
       grant_ref, kind, published, attempts, created_at, published_at,
       next_attempt_at, last_error, dead_lettered_at
FROM action_outbox
WHERE tenant_ref = $1 AND published = false AND dead_lettered_at IS NULL
  AND (next_attempt_at IS NULL OR next_attempt_at <= $2)
ORDER BY created_at
LIMIT 1
FOR UPDATE SKIP LOCKED;

-- name: MarkActionOutboxPublished :execrows
UPDATE action_outbox
SET published = true, attempts = attempts + 1, published_at = $3
WHERE tenant_ref = $1 AND dispatch_ref = $2
  AND published = false AND dead_lettered_at IS NULL;

-- name: RecordActionOutboxAttempt :execrows
UPDATE action_outbox
SET attempts = attempts + 1,
    next_attempt_at = $3,
    last_error = $4,
    dead_lettered_at = $5
WHERE tenant_ref = $1 AND dispatch_ref = $2
  AND published = false AND dead_lettered_at IS NULL;
