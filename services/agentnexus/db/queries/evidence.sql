-- name: UpsertEvidenceSourceBinding :one
-- source_version is MONOTONIC: an upsert can never lower it, and reviving a
-- tombstoned binding always bumps PAST the tombstoned version, so handles
-- denied by source deletion can never silently become readable again.
INSERT INTO evidence_source_bindings (
    tenant_ref, id, data_class, source_ref, source_version, access_capability,
    source_capability, resource_type, resource_id, cached_read_allowed, retention_ttl_seconds,
    authority_tier, freshness_bound_seconds
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (tenant_ref, data_class) DO UPDATE
    SET source_ref = EXCLUDED.source_ref,
        source_version = GREATEST(
            EXCLUDED.source_version,
            evidence_source_bindings.source_version
                + CASE WHEN evidence_source_bindings.deleted_at IS NOT NULL THEN 1 ELSE 0 END),
        access_capability = EXCLUDED.access_capability,
        source_capability = EXCLUDED.source_capability,
        resource_type = EXCLUDED.resource_type,
        resource_id = EXCLUDED.resource_id,
        cached_read_allowed = EXCLUDED.cached_read_allowed,
        retention_ttl_seconds = EXCLUDED.retention_ttl_seconds,
        authority_tier = EXCLUDED.authority_tier,
        freshness_bound_seconds = EXCLUDED.freshness_bound_seconds,
        deleted_at = NULL,
        updated_at = now()
RETURNING tenant_ref, id, data_class, source_ref, source_version, access_capability,
    source_capability, resource_type, resource_id, cached_read_allowed, retention_ttl_seconds,
    deleted_at, created_at, updated_at, authority_tier, freshness_bound_seconds;

-- name: GetEvidenceSourceBinding :one
SELECT tenant_ref, id, data_class, source_ref, source_version, access_capability,
    source_capability, resource_type, resource_id, cached_read_allowed, retention_ttl_seconds,
    deleted_at, created_at, updated_at, authority_tier, freshness_bound_seconds
FROM evidence_source_bindings
WHERE tenant_ref = $1 AND data_class = $2;

-- name: BumpEvidenceSourceVersion :one
UPDATE evidence_source_bindings
SET source_version = source_version + 1,
    updated_at = now()
WHERE tenant_ref = $1 AND data_class = $2
RETURNING tenant_ref, id, data_class, source_ref, source_version, access_capability,
    source_capability, resource_type, resource_id, cached_read_allowed, retention_ttl_seconds,
    deleted_at, created_at, updated_at, authority_tier, freshness_bound_seconds;

-- name: MarkEvidenceSourceDeleted :one
UPDATE evidence_source_bindings
SET deleted_at = now(),
    updated_at = now()
WHERE tenant_ref = $1 AND data_class = $2
RETURNING tenant_ref, id, data_class, source_ref, source_version, access_capability,
    source_capability, resource_type, resource_id, cached_read_allowed, retention_ttl_seconds,
    deleted_at, created_at, updated_at, authority_tier, freshness_bound_seconds;

-- name: InsertEvidenceHandle :one
INSERT INTO evidence_handles (
    tenant_ref, id, principal_ref, agent_client_ref, agent_release_ref, org_version,
    data_class, binding_id, source_version, purpose, business_context_ref, content_hash,
    content_bytes, record_count, record_offset, page_limit, object_key, key_ref,
    authorization_ref, lineage, cached_read_allowed, staged_at, expires_at, retention_expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
    $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
)
RETURNING tenant_ref, id, principal_ref, agent_client_ref, agent_release_ref, org_version,
    data_class, binding_id, source_version, purpose, business_context_ref, content_hash,
    content_bytes, record_count, record_offset, page_limit, object_key, key_ref,
    authorization_ref, lineage, cached_read_allowed, staged_at, expires_at, retention_expires_at,
    created_at;

-- name: GetEvidenceHandle :one
SELECT tenant_ref, id, principal_ref, agent_client_ref, agent_release_ref, org_version,
    data_class, binding_id, source_version, purpose, business_context_ref, content_hash,
    content_bytes, record_count, record_offset, page_limit, object_key, key_ref,
    authorization_ref, lineage, cached_read_allowed, staged_at, expires_at, retention_expires_at,
    created_at
FROM evidence_handles
WHERE tenant_ref = $1 AND id = $2;

-- name: InsertEvidenceHandleEvent :one
INSERT INTO evidence_handle_events (tenant_ref, id, evidence_ref, kind, reason)
VALUES ($1, $2, $3, $4, $5)
RETURNING tenant_ref, id, evidence_ref, kind, reason, seq, created_at;

-- name: ListEvidenceHandleEvents :many
SELECT tenant_ref, id, evidence_ref, kind, reason, seq, created_at
FROM evidence_handle_events
WHERE tenant_ref = $1 AND evidence_ref = $2
ORDER BY seq;

-- name: ListEvidenceRetentionExpired :many
SELECT h.tenant_ref, h.id, h.principal_ref, h.agent_client_ref, h.agent_release_ref, h.org_version,
    h.data_class, h.binding_id, h.source_version, h.purpose, h.business_context_ref, h.content_hash,
    h.content_bytes, h.record_count, h.record_offset, h.page_limit, h.object_key, h.key_ref,
    h.authorization_ref, h.lineage, h.cached_read_allowed, h.staged_at, h.expires_at, h.retention_expires_at,
    h.created_at
FROM evidence_handles h
WHERE h.tenant_ref = $1
  AND h.retention_expires_at IS NOT NULL
  AND h.retention_expires_at <= $2
  AND NOT EXISTS (
      SELECT 1 FROM evidence_handle_events e
      WHERE e.tenant_ref = h.tenant_ref
        AND e.evidence_ref = h.id
        AND e.kind = 'content_expired'
  )
ORDER BY h.retention_expires_at, h.id
LIMIT $3;
