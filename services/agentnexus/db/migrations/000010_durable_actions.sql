-- 000010_durable_actions.sql (GA Task 0F)
--
-- The durable controlled-execution plane: the one logical Action, its one-use
-- grant, the transactional outbox (durable dispatch intent), the dedup inbox
-- (connector results applied exactly once) and the execution receipts.
--
--   actions          one logical Action per (tenant, idempotency_key); the
--                    binding columns are immutable and the status only advances
--                    along the frozen allowed edges (guard_action_lifecycle).
--   action_grants    ONE one-use grant per Action; consumed_at is stamped
--                    exactly once (NULL->NOT-NULL) at dispatch.
--   action_outbox    append-only dispatch intent; a row transitions published
--                    false->true exactly once (the recovery pump).
--   action_inbox     connector-result dedup; a redelivered result_id is a no-op.
--   action_receipts  immutable execution receipts (rcp_ handle-addressed).
--
-- Authority boundary: `succeeded` records declared TECHNICAL execution only. No
-- column, trigger or value here asserts a business Outcome, and the public
-- parity test bans the outcome/goal_achieved/graph names from every public
-- surface.
--
-- Migration ordering note: this migration reserves number 000010 (0G reserves
-- 000011) even though 000012 (Task 2 connector products) already exists. On a
-- FRESH database — the e2e container and the integration fixtures apply every
-- migration Up block in SORTED filename order — 000010 applies before 000012
-- with no conflict (these tables are independent of the connector-product
-- tables). Inserting 000010 AFTER 000012 has already been applied in a
-- long-lived production database is a goose incremental out-of-order concern
-- that belongs to a later deploy/packaging task, NOT to Task 0F; the number is
-- reserved intentionally and must not be renumbered.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE actions (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref <> '' AND btrim(tenant_ref) = tenant_ref),
    action_ref TEXT NOT NULL CHECK (action_ref ~ '^act_[A-Za-z0-9_-]{16,128}$'),
    status TEXT NOT NULL CHECK (status IN (
        'requested', 'awaiting_approval', 'granted', 'dispatched', 'executing',
        'succeeded', 'failed', 'result_unknown', 'reconciling', 'compensating',
        'human_takeover'
    )),
    business_context_ref TEXT NOT NULL CHECK (business_context_ref ~ '^wc_[A-Za-z0-9_-]{16,128}$'),
    capability TEXT NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^sha256:[0-9a-f]{64}$'),
    idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 128 AND btrim(idempotency_key) = idempotency_key),
    risk_authority TEXT NOT NULL CHECK (risk_authority <> '' AND btrim(risk_authority) = risk_authority),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    approval_plan_ref TEXT NOT NULL DEFAULT '' CHECK (approval_plan_ref = '' OR approval_plan_ref ~ '^apl_[A-Za-z0-9_-]{16,128}$'),
    grant_ref TEXT NOT NULL DEFAULT '' CHECK (grant_ref = '' OR grant_ref ~ '^grant_[A-Za-z0-9_-]{16,128}$'),
    approval_evidence_ref TEXT NOT NULL DEFAULT '' CHECK (approval_evidence_ref = '' OR approval_evidence_ref ~ '^apv_[A-Za-z0-9_-]{16,128}$'),
    receipt_ref TEXT NOT NULL DEFAULT '' CHECK (receipt_ref = '' OR receipt_ref ~ '^rcp_[A-Za-z0-9_-]{16,128}$'),
    compensation_ref TEXT NOT NULL DEFAULT '' CHECK (compensation_ref = '' OR compensation_ref ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    compensation_of TEXT NOT NULL DEFAULT '' CHECK (compensation_of = '' OR compensation_of ~ '^act_[A-Za-z0-9_-]{16,128}$'),
    expected_receipt_schema TEXT NOT NULL CHECK (expected_receipt_schema <> ''),
    postconditions JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(postconditions) = 'array'),
    verification_needs JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(verification_needs) = 'array'),
    expires_at TIMESTAMPTZ NOT NULL,
    failure_reason TEXT NOT NULL DEFAULT '',
    audit_ref_id TEXT NOT NULL CHECK (audit_ref_id <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, action_ref),
    UNIQUE (tenant_ref, idempotency_key),
    CHECK ((status = 'awaiting_approval') <= (approval_plan_ref <> '')),
    CHECK ((receipt_ref <> '') <= (status IN ('succeeded', 'failed')))
);

CREATE INDEX idx_actions_tenant_status ON actions(tenant_ref, status, updated_at);

CREATE TABLE action_grants (
    tenant_ref TEXT NOT NULL,
    grant_ref TEXT NOT NULL CHECK (grant_ref ~ '^grant_[A-Za-z0-9_-]{16,128}$'),
    action_ref TEXT NOT NULL,
    business_context_ref TEXT NOT NULL CHECK (business_context_ref ~ '^wc_[A-Za-z0-9_-]{16,128}$'),
    capability TEXT NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^sha256:[0-9a-f]{64}$'),
    one_use BOOLEAN NOT NULL DEFAULT true CHECK (one_use = true),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > issued_at),
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_ref, grant_ref),
    UNIQUE (tenant_ref, action_ref),
    FOREIGN KEY (tenant_ref, action_ref) REFERENCES actions(tenant_ref, action_ref)
);

CREATE TABLE action_outbox (
    tenant_ref TEXT NOT NULL,
    dispatch_ref TEXT NOT NULL CHECK (dispatch_ref <> '' AND btrim(dispatch_ref) = dispatch_ref),
    action_ref TEXT NOT NULL,
    capability TEXT NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^sha256:[0-9a-f]{64}$'),
    grant_ref TEXT NOT NULL CHECK (grant_ref ~ '^grant_[A-Za-z0-9_-]{16,128}$'),
    kind TEXT NOT NULL CHECK (kind IN ('execute', 'compensate')),
    published BOOLEAN NOT NULL DEFAULT false,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_ref, dispatch_ref),
    FOREIGN KEY (tenant_ref, action_ref) REFERENCES actions(tenant_ref, action_ref),
    CHECK ((published = false) OR (published_at IS NOT NULL))
);

CREATE INDEX idx_action_outbox_pending ON action_outbox(tenant_ref, created_at) WHERE published = false;

CREATE TABLE action_inbox (
    tenant_ref TEXT NOT NULL,
    result_id TEXT NOT NULL CHECK (result_id <> '' AND btrim(result_id) = result_id),
    action_ref TEXT NOT NULL,
    receipt_ref TEXT NOT NULL DEFAULT '' CHECK (receipt_ref = '' OR receipt_ref ~ '^rcp_[A-Za-z0-9_-]{16,128}$'),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, result_id),
    FOREIGN KEY (tenant_ref, action_ref) REFERENCES actions(tenant_ref, action_ref)
);

CREATE TABLE action_receipts (
    tenant_ref TEXT NOT NULL,
    receipt_ref TEXT NOT NULL CHECK (receipt_ref ~ '^rcp_[A-Za-z0-9_-]{16,128}$'),
    action_ref TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    capability TEXT NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^sha256:[0-9a-f]{64}$'),
    receipt_schema TEXT NOT NULL CHECK (receipt_schema <> ''),
    result JSONB CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    result_hash TEXT NOT NULL DEFAULT '' CHECK (result_hash = '' OR result_hash ~ '^sha256:[0-9a-f]{64}$'),
    issued_at TIMESTAMPTZ NOT NULL,
    signature JSONB CHECK (signature IS NULL OR jsonb_typeof(signature) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, receipt_ref),
    FOREIGN KEY (tenant_ref, action_ref) REFERENCES actions(tenant_ref, action_ref)
);

-- guard_action_lifecycle enforces the frozen state machine at the database
-- boundary (defense in depth with the Go state_machine): the binding columns
-- are immutable, DELETE is rejected, and status advances ONLY along an allowed
-- edge. The allowed-edge table mirrors internal/actions/state_machine.go.
CREATE FUNCTION guard_action_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    allowed TEXT[];
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'actions are immutable evidence and cannot be deleted';
    END IF;
    IF NEW.tenant_ref IS DISTINCT FROM OLD.tenant_ref OR
       NEW.action_ref IS DISTINCT FROM OLD.action_ref OR
       NEW.business_context_ref IS DISTINCT FROM OLD.business_context_ref OR
       NEW.capability IS DISTINCT FROM OLD.capability OR
       NEW.parameter_hash IS DISTINCT FROM OLD.parameter_hash OR
       NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.risk_authority IS DISTINCT FROM OLD.risk_authority OR
       NEW.risk_level IS DISTINCT FROM OLD.risk_level OR
       NEW.approval_plan_ref IS DISTINCT FROM OLD.approval_plan_ref OR
       NEW.compensation_ref IS DISTINCT FROM OLD.compensation_ref OR
       NEW.compensation_of IS DISTINCT FROM OLD.compensation_of OR
       NEW.expected_receipt_schema IS DISTINCT FROM OLD.expected_receipt_schema OR
       NEW.postconditions IS DISTINCT FROM OLD.postconditions OR
       NEW.verification_needs IS DISTINCT FROM OLD.verification_needs OR
       NEW.audit_ref_id IS DISTINCT FROM OLD.audit_ref_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'action binding is immutable';
    END IF;
    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;
    allowed := CASE OLD.status
        WHEN 'requested' THEN ARRAY['awaiting_approval', 'granted', 'failed', 'human_takeover']
        WHEN 'awaiting_approval' THEN ARRAY['granted', 'failed', 'human_takeover']
        WHEN 'granted' THEN ARRAY['dispatched', 'failed', 'human_takeover']
        -- A verified receipt may complete a dispatched action DIRECTLY
        -- (dispatched -> succeeded|failed), mirroring executing -> {succeeded,
        -- failed}: no component in the wired system calls MarkExecuting today,
        -- so ingestRuntimeActionReceipt's documented "reports the execution
        -- result of a dispatched action" path must not be blocked here. Both
        -- edges stay valid for a future connector-host that explicitly reports
        -- pickup before the result.
        WHEN 'dispatched' THEN ARRAY['executing', 'succeeded', 'failed', 'result_unknown', 'compensating', 'human_takeover']
        WHEN 'executing' THEN ARRAY['succeeded', 'failed', 'result_unknown', 'compensating', 'human_takeover']
        WHEN 'result_unknown' THEN ARRAY['reconciling', 'compensating', 'human_takeover']
        WHEN 'reconciling' THEN ARRAY['succeeded', 'failed', 'human_takeover']
        WHEN 'succeeded' THEN ARRAY['compensating', 'human_takeover']
        WHEN 'failed' THEN ARRAY['compensating', 'human_takeover']
        WHEN 'compensating' THEN ARRAY['human_takeover']
        ELSE ARRAY[]::TEXT[]
    END;
    IF NOT (NEW.status = ANY(allowed)) THEN
        RAISE EXCEPTION 'forbidden action transition % -> %', OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END;
$$;

-- guard_action_grant_consume permits exactly ONE legal update: stamping
-- consumed_at NULL->NOT-NULL with every other column unchanged (the one-use
-- consumption). Everything else — a second consume, a binding mutation, a
-- delete — is rejected.
CREATE FUNCTION guard_action_grant_consume() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'action grants are immutable';
    END IF;
    IF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL AND
       ROW(NEW.tenant_ref, NEW.grant_ref, NEW.action_ref, NEW.business_context_ref, NEW.capability, NEW.parameter_hash, NEW.one_use, NEW.issued_at, NEW.expires_at)
       IS NOT DISTINCT FROM
       ROW(OLD.tenant_ref, OLD.grant_ref, OLD.action_ref, OLD.business_context_ref, OLD.capability, OLD.parameter_hash, OLD.one_use, OLD.issued_at, OLD.expires_at)
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'an action grant is one-use: consumed_at is stamped exactly once and never mutated';
END;
$$;

-- guard_action_outbox permits exactly ONE legal update: stamping published
-- false->true (with published_at) and optionally raising attempts, every other
-- column unchanged. The dispatch intent is append-only otherwise.
CREATE FUNCTION guard_action_outbox() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'the action outbox is append-only';
    END IF;
    IF OLD.published = false AND NEW.published = true AND NEW.attempts >= OLD.attempts AND
       ROW(NEW.tenant_ref, NEW.dispatch_ref, NEW.action_ref, NEW.capability, NEW.parameter_hash, NEW.grant_ref, NEW.kind, NEW.created_at)
       IS NOT DISTINCT FROM
       ROW(OLD.tenant_ref, OLD.dispatch_ref, OLD.action_ref, OLD.capability, OLD.parameter_hash, OLD.grant_ref, OLD.kind, OLD.created_at)
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'the action outbox is append-only; a row is published exactly once';
END;
$$;

CREATE FUNCTION guard_action_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'action evidence is append-only';
END;
$$;

CREATE FUNCTION reject_action_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'action evidence truncate is forbidden';
END;
$$;

CREATE TRIGGER guard_action_lifecycle
BEFORE UPDATE OR DELETE ON actions
FOR EACH ROW EXECUTE FUNCTION guard_action_lifecycle();
CREATE TRIGGER reject_actions_truncate
BEFORE TRUNCATE ON actions
FOR EACH STATEMENT EXECUTE FUNCTION reject_action_truncate();
CREATE TRIGGER guard_action_grant_consume
BEFORE UPDATE OR DELETE ON action_grants
FOR EACH ROW EXECUTE FUNCTION guard_action_grant_consume();
CREATE TRIGGER reject_action_grants_truncate
BEFORE TRUNCATE ON action_grants
FOR EACH STATEMENT EXECUTE FUNCTION reject_action_truncate();
CREATE TRIGGER guard_action_outbox
BEFORE UPDATE OR DELETE ON action_outbox
FOR EACH ROW EXECUTE FUNCTION guard_action_outbox();
CREATE TRIGGER reject_action_outbox_truncate
BEFORE TRUNCATE ON action_outbox
FOR EACH STATEMENT EXECUTE FUNCTION reject_action_truncate();
CREATE TRIGGER guard_action_inbox_append_only
BEFORE UPDATE OR DELETE ON action_inbox
FOR EACH ROW EXECUTE FUNCTION guard_action_append_only();
CREATE TRIGGER reject_action_inbox_truncate
BEFORE TRUNCATE ON action_inbox
FOR EACH STATEMENT EXECUTE FUNCTION reject_action_truncate();
CREATE TRIGGER guard_action_receipts_append_only
BEFORE UPDATE OR DELETE ON action_receipts
FOR EACH ROW EXECUTE FUNCTION guard_action_append_only();
CREATE TRIGGER reject_action_receipts_truncate
BEFORE TRUNCATE ON action_receipts
FOR EACH STATEMENT EXECUTE FUNCTION reject_action_truncate();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS action_receipts;
DROP TABLE IF EXISTS action_inbox;
DROP TABLE IF EXISTS action_outbox;
DROP TABLE IF EXISTS action_grants;
DROP TABLE IF EXISTS actions;
DROP FUNCTION IF EXISTS guard_action_lifecycle();
DROP FUNCTION IF EXISTS guard_action_grant_consume();
DROP FUNCTION IF EXISTS guard_action_outbox();
DROP FUNCTION IF EXISTS guard_action_append_only();
DROP FUNCTION IF EXISTS reject_action_truncate();
-- +goose StatementEnd
