-- +goose Up
-- +goose StatementBegin
-- Registered Agent clients. tenant_ref is the opaque verified tenant reference
-- (sdk/go/runtime PrincipalContext.TenantRef), never a caller-supplied field.
CREATE TABLE agent_clients (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref <> '' AND btrim(tenant_ref) = tenant_ref),
    id TEXT NOT NULL CHECK (id <> '' AND btrim(id) = id),
    publisher TEXT NOT NULL CHECK (publisher <> '' AND btrim(publisher) = publisher),
    product TEXT NOT NULL CHECK (product <> '' AND btrim(product) = product),
    origin TEXT NOT NULL DEFAULT '',
    enterprise_registered BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, id),
    UNIQUE (tenant_ref, publisher, product)
);

-- Immutable Agent-client certification revisions. Each revision binds a
-- publisher, product, semantic version range, signing key, signed
-- release-manifest digest, trust class and capability ceiling.
CREATE TABLE agent_certifications (
    tenant_ref TEXT NOT NULL,
    id TEXT NOT NULL CHECK (id <> '' AND btrim(id) = id),
    agent_client_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    trust_class TEXT NOT NULL CHECK (trust_class IN ('first_party_trusted', 'certified_third_party')),
    publisher TEXT NOT NULL,
    product TEXT NOT NULL,
    -- Origin is FROZEN into the immutable revision at certify time so a later
    -- re-registration cannot weaken the AstraClaw/Xiaozhi connector denial.
    origin TEXT NOT NULL DEFAULT '',
    version_min TEXT NOT NULL DEFAULT '',
    version_max TEXT NOT NULL DEFAULT '',
    signing_key_id TEXT NOT NULL CHECK (signing_key_id <> ''),
    signing_key_algorithm TEXT NOT NULL CHECK (signing_key_algorithm = 'ed25519'),
    signing_key_public_key TEXT NOT NULL CHECK (signing_key_public_key <> ''),
    release_manifest_digest TEXT NOT NULL CHECK (release_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    capability_ceiling JSONB NOT NULL DEFAULT '[]'::jsonb,
    signed_build_manifest BOOLEAN NOT NULL,
    enterprise_registered BOOLEAN NOT NULL,
    certified_decision_provider BOOLEAN NOT NULL DEFAULT false,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, id),
    UNIQUE (tenant_ref, publisher, product, revision),
    FOREIGN KEY (tenant_ref, agent_client_id) REFERENCES agent_clients(tenant_ref, id),
    -- Every certification attests a signed build manifest.
    CONSTRAINT chk_agent_certification_signed CHECK (signed_build_manifest),
    -- First-party status additionally requires enterprise registration; a
    -- name-only claim can never persist as first_party_trusted.
    CONSTRAINT chk_agent_certification_first_party
        CHECK (trust_class <> 'first_party_trusted' OR enterprise_registered),
    CONSTRAINT chk_agent_certification_lifetime CHECK (expires_at > issued_at),
    -- At least one version bound must be present. Semantic-version ORDER (min
    -- precedes max) is enforced in Go (CertificationBinding.Validate); a lexical
    -- SQL CHECK cannot compare multi-digit versions correctly, so it is not
    -- attempted here.
    CONSTRAINT chk_agent_certification_version_bound CHECK (version_min <> '' OR version_max <> '')
);

-- Certification revisions are immutable: reject UPDATE, DELETE and TRUNCATE.
CREATE FUNCTION guard_agent_certification_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'agent certification revisions are immutable';
END; $$;
CREATE TRIGGER guard_agent_certification_immutable
BEFORE UPDATE OR DELETE ON agent_certifications
FOR EACH ROW EXECUTE FUNCTION guard_agent_certification_immutable();
CREATE TRIGGER reject_agent_certification_truncate
BEFORE TRUNCATE ON agent_certifications
FOR EACH STATEMENT EXECUTE FUNCTION guard_agent_certification_immutable();

-- Append-only, hash-chained certification status log. Revoke/expire/supersede
-- append new rows and never mutate prior ones.
CREATE TABLE agent_certification_status_changes (
    tenant_ref TEXT NOT NULL,
    id TEXT NOT NULL CHECK (id <> '' AND btrim(id) = id),
    certification_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired', 'superseded')),
    -- reason is caller-supplied for revocations; forbid control bytes (NUL
    -- included) so it can never inject into the hash preimage or logs.
    reason TEXT NOT NULL DEFAULT '' CHECK (reason ~ '^[^[:cntrl:]]*$'),
    prev_hash TEXT NOT NULL DEFAULT '' CHECK (prev_hash = '' OR prev_hash ~ '^[0-9a-f]{64}$'),
    event_hash TEXT NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    -- seq is a strictly monotonic insert order. created_at (now()) is
    -- transaction-start time and is NOT monotonic across concurrent writers, so
    -- "latest" is resolved by seq, never by created_at.
    seq BIGINT GENERATED ALWAYS AS IDENTITY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, id),
    -- The status log is a per-certification hash chain: at most one row may
    -- chain onto any given predecessor (the genesis '' included). This
    -- structurally forbids a fork under concurrent supersede-vs-revoke; a losing
    -- writer hits this constraint, re-reads the tail and retries.
    UNIQUE (tenant_ref, certification_id, prev_hash),
    UNIQUE (tenant_ref, certification_id, event_hash),
    FOREIGN KEY (tenant_ref, certification_id) REFERENCES agent_certifications(tenant_ref, id)
);

CREATE FUNCTION guard_agent_certification_status_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'agent certification status changes are append-only';
END; $$;
CREATE TRIGGER guard_agent_certification_status_append_only
BEFORE UPDATE OR DELETE ON agent_certification_status_changes
FOR EACH ROW EXECUTE FUNCTION guard_agent_certification_status_append_only();
CREATE TRIGGER reject_agent_certification_status_truncate
BEFORE TRUNCATE ON agent_certification_status_changes
FOR EACH STATEMENT EXECUTE FUNCTION guard_agent_certification_status_append_only();

CREATE INDEX idx_agent_certifications_product
    ON agent_certifications(tenant_ref, publisher, product, revision DESC);
CREATE INDEX idx_agent_certification_status_latest
    ON agent_certification_status_changes(tenant_ref, certification_id, seq DESC);

COMMENT ON TABLE agent_clients IS 'Registered Agent clients (GA Task 0C); tenant_ref is the opaque verified tenant reference.';
COMMENT ON TABLE agent_certifications IS 'Immutable Agent-client certification revisions (GA Task 0C).';
COMMENT ON TABLE agent_certification_status_changes IS 'Append-only, hash-chained certification status log: active/revoked/expired/superseded.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS agent_certification_status_changes;
DROP FUNCTION IF EXISTS guard_agent_certification_status_append_only();
DROP TABLE IF EXISTS agent_certifications;
DROP FUNCTION IF EXISTS guard_agent_certification_immutable();
DROP TABLE IF EXISTS agent_clients;
-- +goose StatementEnd
