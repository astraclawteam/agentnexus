-- name: UpsertAgentClient :one
INSERT INTO agent_clients (tenant_ref, id, publisher, product, origin, enterprise_registered)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_ref, publisher, product) DO UPDATE
    SET origin = EXCLUDED.origin,
        enterprise_registered = EXCLUDED.enterprise_registered
RETURNING tenant_ref, id, publisher, product, origin, enterprise_registered, created_at;

-- name: GetAgentClient :one
SELECT tenant_ref, id, publisher, product, origin, enterprise_registered, created_at
FROM agent_clients
WHERE tenant_ref = $1 AND publisher = $2 AND product = $3;

-- name: GetAgentClientByID :one
SELECT tenant_ref, id, publisher, product, origin, enterprise_registered, created_at
FROM agent_clients
WHERE tenant_ref = $1 AND id = $2;

-- name: GetMaxCertificationRevision :one
SELECT COALESCE(MAX(revision), 0)::BIGINT
FROM agent_certifications
WHERE tenant_ref = $1 AND publisher = $2 AND product = $3;

-- name: InsertAgentCertification :one
INSERT INTO agent_certifications (
    tenant_ref, id, agent_client_id, revision, trust_class, publisher, product, origin,
    version_min, version_max, signing_key_id, signing_key_algorithm, signing_key_public_key,
    release_manifest_digest, capability_ceiling, signed_build_manifest, enterprise_registered,
    certified_decision_provider, issued_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
)
RETURNING tenant_ref, id, agent_client_id, revision, trust_class, publisher, product, origin,
    version_min, version_max, signing_key_id, signing_key_algorithm, signing_key_public_key,
    release_manifest_digest, capability_ceiling, signed_build_manifest, enterprise_registered,
    certified_decision_provider, issued_at, expires_at, created_at;

-- name: ListAgentCertifications :many
SELECT tenant_ref, id, agent_client_id, revision, trust_class, publisher, product, origin,
    version_min, version_max, signing_key_id, signing_key_algorithm, signing_key_public_key,
    release_manifest_digest, capability_ceiling, signed_build_manifest, enterprise_registered,
    certified_decision_provider, issued_at, expires_at, created_at
FROM agent_certifications
WHERE tenant_ref = $1 AND publisher = $2 AND product = $3
ORDER BY revision DESC;

-- name: GetAgentCertificationByID :one
SELECT tenant_ref, id, agent_client_id, revision, trust_class, publisher, product, origin,
    version_min, version_max, signing_key_id, signing_key_algorithm, signing_key_public_key,
    release_manifest_digest, capability_ceiling, signed_build_manifest, enterprise_registered,
    certified_decision_provider, issued_at, expires_at, created_at
FROM agent_certifications
WHERE tenant_ref = $1 AND id = $2;

-- name: LockAgentCertification :one
SELECT id
FROM agent_certifications
WHERE tenant_ref = $1 AND id = $2
FOR UPDATE;

-- name: GetLatestCertificationStatus :one
SELECT tenant_ref, id, certification_id, status, reason, prev_hash, event_hash, seq, created_at
FROM agent_certification_status_changes
WHERE tenant_ref = $1 AND certification_id = $2
ORDER BY seq DESC
LIMIT 1;

-- name: InsertCertificationStatusChange :one
INSERT INTO agent_certification_status_changes (
    tenant_ref, id, certification_id, status, reason, prev_hash, event_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING tenant_ref, id, certification_id, status, reason, prev_hash, event_hash, seq, created_at;
