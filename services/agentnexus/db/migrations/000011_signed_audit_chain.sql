-- 000011_signed_audit_chain.sql (GA Task 0G)
--
-- Signs and independently verifies the audit evidence chain. The existing
-- audit_events chain (000001) is an UNSIGNED per-enterprise SHA-256 hash chain;
-- this migration adds the signing plane ON TOP of it, additively:
--
--   audit_events.tenant_seq   per-tenant monotonic sequence (starts at 1). A
--                             PARTIAL UNIQUE index over (enterprise_id,
--                             tenant_seq) WHERE tenant_seq IS NOT NULL catches
--                             the duplicate-sequence attack at the database
--                             while leaving legacy (unsigned, NULL-seq) rows
--                             untouched. Sequence allocation runs under the
--                             existing per-enterprise advisory lock.
--   audit_events.signature_*  detached ed25519 signature (algorithm/key_id/
--                             value) over the canonical event pre-image, plus
--                             signed_at. Nullable so legacy rows stay unsigned.
--   audit_signing_keys        registered signing public keys and their
--                             append-only lifecycle (active|revoked) for
--                             revoked-key detection by the verifier.
--   audit_batch_roots         signed batch Merkle roots over event hashes, for
--                             the WORM/SIEM offline verification package.
--
-- NUL-safety (the 0E/dsnfix NUL curse): no text parameter ever joins two values
-- with \x00. Sequence allocation locks on enterprise_id alone (single-int
-- advisory lock, like GetLatestEnterpriseAuditHash); signing-key public material
-- is BYTEA, never a NUL-bearing TEXT parameter.
--
-- Migration ordering note: this migration takes number 000011 (reserved by Task
-- 0F's 000010 note) even though 000012 (Task 2 connector products) already
-- exists. On a FRESH database the e2e container and the integration fixtures
-- apply every Up block in SORTED filename order, so 000011 applies before 000012
-- with no conflict (these audit columns/tables are independent of the
-- connector-product tables). Inserting 000011 after 000012 was already applied
-- in a long-lived production database is a goose incremental out-of-order
-- concern for a later deploy/packaging task, NOT for Task 0G; the number is
-- reserved intentionally and must not be renumbered.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE audit_events
    ADD COLUMN tenant_seq BIGINT CHECK (tenant_seq IS NULL OR tenant_seq >= 1),
    ADD COLUMN signature_algorithm TEXT CHECK (signature_algorithm IS NULL OR signature_algorithm = 'ed25519'),
    ADD COLUMN signature_key_id TEXT CHECK (signature_key_id IS NULL OR (signature_key_id <> '' AND btrim(signature_key_id) = signature_key_id)),
    ADD COLUMN signature_value TEXT CHECK (signature_value IS NULL OR signature_value <> ''),
    ADD COLUMN signed_at TIMESTAMPTZ,
    -- GA Task 0G first-class binding refs (recoverable, individually signed):
    -- loaded from the Action record and the verified principal at the
    -- action-transition append site so every binding is inspectable and
    -- independently tamper-evident, not folded non-recoverably into input_hash.
    ADD COLUMN status_from TEXT,
    ADD COLUMN capability TEXT,
    ADD COLUMN parameter_hash TEXT CHECK (parameter_hash IS NULL OR parameter_hash ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN grant_ref TEXT,
    ADD COLUMN approval_evidence_ref TEXT,
    ADD COLUMN receipt_ref TEXT,
    ADD COLUMN risk_authority TEXT,
    ADD COLUMN agent_client_ref TEXT,
    ADD COLUMN agent_release_ref TEXT,
    ADD COLUMN org_snapshot_ref TEXT,
    -- A signed row carries the FULL signature triple and a sequence: the three
    -- signature columns and tenant_seq are all-present or all-absent together.
    ADD CONSTRAINT audit_events_signature_complete CHECK (
        (signature_algorithm IS NULL AND signature_key_id IS NULL AND signature_value IS NULL AND signed_at IS NULL)
        OR
        (signature_algorithm IS NOT NULL AND signature_key_id IS NOT NULL AND signature_value IS NOT NULL AND signed_at IS NOT NULL AND tenant_seq IS NOT NULL)
    );

-- The duplicate-sequence attack is rejected at the database: a second row with
-- the same (enterprise_id, tenant_seq) violates this partial unique index.
-- Legacy NULL-seq rows are excluded, so pre-0G evidence is unaffected.
CREATE UNIQUE INDEX audit_events_tenant_seq_uniq
    ON audit_events (enterprise_id, tenant_seq)
    WHERE tenant_seq IS NOT NULL;

CREATE TABLE audit_signing_keys (
    key_id TEXT PRIMARY KEY CHECK (key_id <> '' AND btrim(key_id) = key_id),
    algorithm TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE TABLE audit_batch_roots (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    root_hash TEXT NOT NULL CHECK (root_hash ~ '^sha256:[0-9a-f]{64}$'),
    first_seq BIGINT NOT NULL CHECK (first_seq >= 1),
    last_seq BIGINT NOT NULL CHECK (last_seq >= first_seq),
    event_count BIGINT NOT NULL CHECK (event_count >= 1),
    signed_at TIMESTAMPTZ NOT NULL,
    signature_algorithm TEXT NOT NULL CHECK (signature_algorithm = 'ed25519'),
    signature_key_id TEXT NOT NULL REFERENCES audit_signing_keys(key_id),
    signature_value TEXT NOT NULL CHECK (signature_value <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (enterprise_id, first_seq, last_seq)
);

CREATE INDEX idx_audit_batch_roots_enterprise ON audit_batch_roots (enterprise_id, first_seq);

-- Batch-root checkpoints are APPEND-ONLY, mirroring the audit_events ledger
-- guard (migration 000005): a signed checkpoint is inserted once and never
-- updated, deleted or truncated. This blocks a DB role from dropping the latest
-- checkpoint or rewriting last_seq to mask truncation; the checkpoint signature
-- (verified before its last_seq is trusted) is the second, independent guard.
CREATE FUNCTION guard_audit_batch_roots_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit batch roots are append-only';
END;
$$;
CREATE TRIGGER guard_audit_batch_roots_append_only
BEFORE UPDATE OR DELETE ON audit_batch_roots
FOR EACH ROW EXECUTE FUNCTION guard_audit_batch_roots_append_only();
CREATE TRIGGER reject_audit_batch_roots_truncate
BEFORE TRUNCATE ON audit_batch_roots
FOR EACH STATEMENT EXECUTE FUNCTION guard_audit_batch_roots_append_only();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS guard_audit_batch_roots_append_only ON audit_batch_roots;
DROP TRIGGER IF EXISTS reject_audit_batch_roots_truncate ON audit_batch_roots;
DROP TABLE IF EXISTS audit_batch_roots;
DROP FUNCTION IF EXISTS guard_audit_batch_roots_append_only();
DROP TABLE IF EXISTS audit_signing_keys;
DROP INDEX IF EXISTS audit_events_tenant_seq_uniq;
ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS audit_events_signature_complete,
    DROP COLUMN IF EXISTS org_snapshot_ref,
    DROP COLUMN IF EXISTS agent_release_ref,
    DROP COLUMN IF EXISTS agent_client_ref,
    DROP COLUMN IF EXISTS risk_authority,
    DROP COLUMN IF EXISTS receipt_ref,
    DROP COLUMN IF EXISTS approval_evidence_ref,
    DROP COLUMN IF EXISTS grant_ref,
    DROP COLUMN IF EXISTS parameter_hash,
    DROP COLUMN IF EXISTS capability,
    DROP COLUMN IF EXISTS status_from,
    DROP COLUMN IF EXISTS signed_at,
    DROP COLUMN IF EXISTS signature_value,
    DROP COLUMN IF EXISTS signature_key_id,
    DROP COLUMN IF EXISTS signature_algorithm,
    DROP COLUMN IF EXISTS tenant_seq;
-- +goose StatementEnd
