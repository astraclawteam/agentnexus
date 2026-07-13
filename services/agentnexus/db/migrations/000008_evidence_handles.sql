-- +goose Up
-- +goose StatementBegin
-- GA Task 0D: semantic evidence reads and opaque handles.
--
-- evidence_source_bindings is the PRIVATE semantic registry: it maps a
-- business-semantic data class to its internal source binding. source_ref is
-- internal-only topology (it may be connector-shaped) and must never cross
-- into public responses, public errors, audit details or log lines.
-- Bindings are administrative rows: source_version advances on
-- InvalidateSourceVersion and deleted_at tombstones a removed source.
CREATE TABLE evidence_source_bindings (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref <> '' AND btrim(tenant_ref) = tenant_ref),
    id TEXT NOT NULL CHECK (id <> '' AND btrim(id) = id),
    data_class TEXT NOT NULL CHECK (data_class <> '' AND btrim(data_class) = data_class),
    -- Internal source locator; control bytes banned (log/hash injection).
    source_ref TEXT NOT NULL CHECK (source_ref <> '' AND source_ref ~ '^[^[:cntrl:]]+$'),
    source_version BIGINT NOT NULL CHECK (source_version > 0),
    -- Business capability evaluated through the neutral capability policy.
    access_capability TEXT NOT NULL CHECK (access_capability <> '' AND btrim(access_capability) = access_capability),
    -- Source-plane classification; a 'connector.' prefix marks the binding as
    -- connector-backed (policy.IsConnectorCapability is the single source of
    -- truth) and requires trust.Context.ConnectorCapabilityAllowed.
    source_capability TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL CHECK (resource_type <> ''),
    resource_id TEXT NOT NULL CHECK (resource_id <> ''),
    -- EXPLICIT cached-read grant: staged (cached) content may be served only
    -- when this is true; the default is deny.
    cached_read_allowed BOOLEAN NOT NULL DEFAULT false,
    -- Optional raw-content retention TTL applied to staged content (0 = none).
    retention_ttl_seconds BIGINT NOT NULL DEFAULT 0 CHECK (retention_ttl_seconds >= 0),
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, id),
    UNIQUE (tenant_ref, data_class)
);

-- evidence_handles is the full server-side binding behind each opaque evd_*
-- handle: tenant, actor, Agent release, org version, source version, purpose,
-- content hash, authorization lineage, TTL and optional raw-content retention
-- TTL. Issued handles are IMMUTABLE; revocation and retention expiry are
-- append-only evidence_handle_events rows.
CREATE TABLE evidence_handles (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref <> '' AND btrim(tenant_ref) = tenant_ref),
    id TEXT NOT NULL CHECK (id ~ '^evd_[A-Za-z0-9_-]{16,128}$'),
    principal_ref TEXT NOT NULL CHECK (principal_ref <> '' AND btrim(principal_ref) = principal_ref),
    agent_client_ref TEXT NOT NULL CHECK (agent_client_ref <> ''),
    agent_release_ref TEXT NOT NULL CHECK (agent_release_ref <> ''),
    org_version BIGINT NOT NULL CHECK (org_version > 0),
    data_class TEXT NOT NULL CHECK (data_class <> ''),
    binding_id TEXT NOT NULL,
    source_version BIGINT NOT NULL CHECK (source_version > 0),
    purpose TEXT NOT NULL CHECK (purpose <> '' AND purpose ~ '^[^[:cntrl:]]+$'),
    business_context_ref TEXT NOT NULL CHECK (business_context_ref ~ '^wc_[A-Za-z0-9_-]{16,128}$'),
    content_hash TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    content_bytes BIGINT NOT NULL CHECK (content_bytes >= 0),
    record_count BIGINT NOT NULL CHECK (record_count >= 0),
    -- Pagination window of this handle over the staged records; continuation
    -- handles carry a non-zero offset.
    record_offset BIGINT NOT NULL DEFAULT 0 CHECK (record_offset >= 0),
    page_limit BIGINT NOT NULL DEFAULT 0 CHECK (page_limit >= 0),
    -- Opaque object-store key of the ENCRYPTED staged content plus the key
    -- provider reference used to seal it (never key material).
    object_key TEXT NOT NULL CHECK (object_key ~ '^[A-Za-z0-9_-]{1,200}$'),
    key_ref TEXT NOT NULL CHECK (key_ref <> ''),
    -- Authorization lineage: the audit-evidence reference of the locate
    -- decision plus the full lineage chain (refs only, never content).
    authorization_ref TEXT NOT NULL CHECK (authorization_ref <> ''),
    lineage JSONB NOT NULL DEFAULT '[]'::jsonb,
    cached_read_allowed BOOLEAN NOT NULL,
    staged_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, id),
    FOREIGN KEY (tenant_ref, binding_id) REFERENCES evidence_source_bindings(tenant_ref, id),
    CONSTRAINT chk_evidence_handle_lifetime CHECK (expires_at > staged_at),
    CONSTRAINT chk_evidence_handle_window CHECK (record_offset <= record_count),
    -- Raw content never outlives the handle: the service defaults the
    -- retention deadline to expires_at and a configured retention TTL may
    -- only SHORTEN it, so every staged blob has a deterministic deletion
    -- deadline (no orphaned ciphertext).
    CONSTRAINT chk_evidence_handle_retention CHECK (retention_expires_at IS NULL OR retention_expires_at <= expires_at)
);

-- Issued handles are immutable: reject UPDATE, DELETE and TRUNCATE.
CREATE FUNCTION guard_evidence_handle_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'evidence handles are immutable';
END; $$;
CREATE TRIGGER guard_evidence_handle_immutable
BEFORE UPDATE OR DELETE ON evidence_handles
FOR EACH ROW EXECUTE FUNCTION guard_evidence_handle_immutable();
CREATE TRIGGER reject_evidence_handle_truncate
BEFORE TRUNCATE ON evidence_handles
FOR EACH STATEMENT EXECUTE FUNCTION guard_evidence_handle_immutable();

-- Append-only handle lifecycle log: ACL revocation and raw-content retention
-- expiry. Reads consult this log and fail CLOSED on any terminal event.
CREATE TABLE evidence_handle_events (
    tenant_ref TEXT NOT NULL,
    id TEXT NOT NULL CHECK (id <> '' AND btrim(id) = id),
    evidence_ref TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('revoked', 'content_expired')),
    -- reason is operator-supplied for revocations; control bytes banned.
    reason TEXT NOT NULL DEFAULT '' CHECK (reason ~ '^[^[:cntrl:]]*$'),
    -- seq is a strictly monotonic insert order; "latest" resolves by seq,
    -- never by the non-monotonic created_at.
    seq BIGINT GENERATED ALWAYS AS IDENTITY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, id),
    FOREIGN KEY (tenant_ref, evidence_ref) REFERENCES evidence_handles(tenant_ref, id)
);

CREATE FUNCTION guard_evidence_handle_event_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'evidence handle events are append-only';
END; $$;
CREATE TRIGGER guard_evidence_handle_event_append_only
BEFORE UPDATE OR DELETE ON evidence_handle_events
FOR EACH ROW EXECUTE FUNCTION guard_evidence_handle_event_append_only();
CREATE TRIGGER reject_evidence_handle_event_truncate
BEFORE TRUNCATE ON evidence_handle_events
FOR EACH STATEMENT EXECUTE FUNCTION guard_evidence_handle_event_append_only();

CREATE INDEX idx_evidence_handles_retention
    ON evidence_handles(tenant_ref, retention_expires_at)
    WHERE retention_expires_at IS NOT NULL;
CREATE INDEX idx_evidence_handle_events_ref
    ON evidence_handle_events(tenant_ref, evidence_ref, seq DESC);

COMMENT ON TABLE evidence_source_bindings IS 'Private semantic registry (GA Task 0D): data class -> internal source binding; source_ref never crosses the public plane.';
COMMENT ON TABLE evidence_handles IS 'Immutable server-side bindings of opaque evd_* evidence handles (GA Task 0D).';
COMMENT ON TABLE evidence_handle_events IS 'Append-only evidence-handle lifecycle log: revoked / content_expired; reads fail closed on terminal events.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS evidence_handle_events;
DROP FUNCTION IF EXISTS guard_evidence_handle_event_append_only();
DROP TABLE IF EXISTS evidence_handles;
DROP FUNCTION IF EXISTS guard_evidence_handle_immutable();
DROP TABLE IF EXISTS evidence_source_bindings;
-- +goose StatementEnd
