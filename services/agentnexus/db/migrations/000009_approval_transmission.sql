-- 000009_approval_transmission.sql (GA Task 0E)
--
-- Locked product boundary: AgentAtlas (or the customer's OA/BPM approval
-- authority) decides business intent, risk and the approval plan; AgentNexus
-- TRANSMITS the caller's signed plan unchanged, validates returned evidence
-- and enforces execution constraints. This migration RETIRES the legacy
-- resolution machinery (governed approval routes, reviewer selection, the
-- enterprise admin queue and the enterprise approval risk policy that only
-- ever fed the resolver) and creates the transmission plane:
--
--   approval_transmissions            one correlation per (tenant, plan_ref)
--   approval_delivery_attempts        append-only channel delivery history
--   approval_evidence_records         ONE validated decision per plan; the
--                                     approval_ref is tenant-unique (replay
--                                     gate) and consumed_at is the Task 0F
--                                     grant-consumption seam (0E never sets it)
--   approval_transmission_revocations append-only revocations
--
-- The audit_events append-only triggers and the
-- uq_audit_events_enterprise_id_id constraint introduced by 000005 guard the
-- LIVE audit ledger and are deliberately left untouched.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    -- The legacy resolution evidence tables are pre-release; refuse to drop
    -- decision evidence silently (mirrors the 000005 pre-release guard).
    IF EXISTS (SELECT 1 FROM approval_resolution_idempotency LIMIT 1) THEN
        RAISE EXCEPTION 'approval_resolution_idempotency contains rows; the approval transmission migration retires an empty pre-release resolver';
    END IF;
    IF EXISTS (SELECT 1 FROM approval_queue_items LIMIT 1) THEN
        RAISE EXCEPTION 'approval_queue_items contains rows; the approval transmission migration retires an empty pre-release resolver';
    END IF;
END;
$$;

DROP TABLE approval_resolution_idempotency;
DROP TABLE approval_queue_items;
DROP TABLE enterprise_approval_policy_versions;
DROP TABLE enterprise_approval_policies;

DROP FUNCTION validate_approval_resolution_links();
DROP FUNCTION reject_approval_evidence_truncate();
DROP FUNCTION guard_approval_queue_evidence();
DROP FUNCTION guard_approval_resolution_evidence();
DROP FUNCTION validate_approval_route_evidence();
DROP FUNCTION validate_direct_requester_permission_evidence();
DROP FUNCTION require_sealed_approval_org_version();
DROP FUNCTION record_enterprise_approval_policy_version();
DROP FUNCTION guard_enterprise_approval_policy_version();
DROP FUNCTION reject_enterprise_approval_policy_truncate();
DROP FUNCTION guard_enterprise_approval_policy_history();

CREATE TABLE approval_transmissions (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref <> '' AND btrim(tenant_ref) = tenant_ref),
    plan_ref TEXT NOT NULL CHECK (plan_ref ~ '^apl_[A-Za-z0-9_-]{16,128}$'),
    plan_hash TEXT NOT NULL CHECK (plan_hash ~ '^sha256:[0-9a-f]{64}$'),
    authority TEXT NOT NULL CHECK (authority <> '' AND btrim(authority) = authority AND lower(authority) <> 'agentnexus'),
    business_context_ref TEXT NOT NULL CHECK (business_context_ref ~ '^wc_[A-Za-z0-9_-]{16,128}$'),
    capability TEXT NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^sha256:[0-9a-f]{64}$'),
    purpose TEXT NOT NULL CHECK (purpose <> ''),
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'evidence_recorded', 'revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    delivery_attempts INTEGER NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0),
    last_delivery_outcome TEXT NOT NULL DEFAULT '' CHECK (last_delivery_outcome IN ('', 'delivered', 'failed')),
    last_delivery_reason TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '' CHECK (decision IN ('', 'approved', 'denied', 'narrowed')),
    decided_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT NOT NULL DEFAULT '',
    audit_ref_id TEXT NOT NULL CHECK (audit_ref_id <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, plan_ref),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK ((decision = '') = (decided_at IS NULL)),
    CHECK (status <> 'evidence_recorded' OR decision <> '')
);

CREATE INDEX idx_approval_transmissions_tenant_status
    ON approval_transmissions(tenant_ref, status, updated_at);

CREATE TABLE approval_delivery_attempts (
    tenant_ref TEXT NOT NULL,
    plan_ref TEXT NOT NULL,
    attempt BIGINT NOT NULL CHECK (attempt > 0),
    outcome TEXT NOT NULL CHECK (outcome IN ('delivered', 'failed')),
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, plan_ref, attempt),
    FOREIGN KEY (tenant_ref, plan_ref) REFERENCES approval_transmissions(tenant_ref, plan_ref)
);

CREATE TABLE approval_evidence_records (
    tenant_ref TEXT NOT NULL,
    approval_ref TEXT NOT NULL CHECK (approval_ref ~ '^apv_[A-Za-z0-9_-]{16,128}$'),
    plan_ref TEXT NOT NULL,
    plan_hash TEXT NOT NULL CHECK (plan_hash ~ '^sha256:[0-9a-f]{64}$'),
    capability TEXT NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^sha256:[0-9a-f]{64}$'),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'denied', 'narrowed')),
    approver_authority TEXT NOT NULL CHECK (approver_authority <> ''),
    decided_at TIMESTAMPTZ NOT NULL,
    evidence_hash TEXT NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
    attestation JSONB NOT NULL CHECK (jsonb_typeof(attestation) = 'object'),
    audit_ref_id TEXT NOT NULL CHECK (audit_ref_id <> ''),
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, approval_ref),
    UNIQUE (tenant_ref, plan_ref),
    FOREIGN KEY (tenant_ref, plan_ref) REFERENCES approval_transmissions(tenant_ref, plan_ref)
);

CREATE TABLE approval_transmission_revocations (
    tenant_ref TEXT NOT NULL,
    revocation_id TEXT NOT NULL CHECK (revocation_id <> ''),
    plan_ref TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_ref, revocation_id),
    UNIQUE (tenant_ref, plan_ref),
    FOREIGN KEY (tenant_ref, plan_ref) REFERENCES approval_transmissions(tenant_ref, plan_ref)
);

CREATE FUNCTION guard_approval_transmission_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    old_rank INTEGER;
    new_rank INTEGER;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'approval transmissions are immutable evidence and cannot be deleted';
    END IF;
    IF NEW.tenant_ref IS DISTINCT FROM OLD.tenant_ref OR
       NEW.plan_ref IS DISTINCT FROM OLD.plan_ref OR
       NEW.plan_hash IS DISTINCT FROM OLD.plan_hash OR
       NEW.authority IS DISTINCT FROM OLD.authority OR
       NEW.business_context_ref IS DISTINCT FROM OLD.business_context_ref OR
       NEW.capability IS DISTINCT FROM OLD.capability OR
       NEW.parameter_hash IS DISTINCT FROM OLD.parameter_hash OR
       NEW.purpose IS DISTINCT FROM OLD.purpose OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
       NEW.audit_ref_id IS DISTINCT FROM OLD.audit_ref_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'approval transmission binding is immutable';
    END IF;
    old_rank := CASE OLD.status WHEN 'pending' THEN 1 WHEN 'delivered' THEN 2 WHEN 'evidence_recorded' THEN 3 WHEN 'revoked' THEN 4 END;
    new_rank := CASE NEW.status WHEN 'pending' THEN 1 WHEN 'delivered' THEN 2 WHEN 'evidence_recorded' THEN 3 WHEN 'revoked' THEN 4 END;
    IF new_rank < old_rank THEN
        RAISE EXCEPTION 'approval transmission status never regresses';
    END IF;
    IF OLD.decision <> '' AND NEW.decision IS DISTINCT FROM OLD.decision THEN
        RAISE EXCEPTION 'a recorded approval decision is immutable';
    END IF;
    IF OLD.decided_at IS NOT NULL AND NEW.decided_at IS DISTINCT FROM OLD.decided_at THEN
        RAISE EXCEPTION 'a recorded approval decision timestamp is immutable';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revocation_reason IS DISTINCT FROM OLD.revocation_reason) THEN
        RAISE EXCEPTION 'a recorded revocation is immutable';
    END IF;
    IF NEW.delivery_attempts < OLD.delivery_attempts THEN
        RAISE EXCEPTION 'delivery attempts never decrease';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_approval_transport_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'approval transmission history is append-only';
END;
$$;

CREATE FUNCTION reject_approval_transport_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'approval transmission evidence truncate is forbidden';
END;
$$;

CREATE FUNCTION guard_approval_evidence_record_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'approval evidence records are immutable';
    END IF;
    -- The single legal update is Task 0F consuming the evidence exactly once.
    IF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL AND
       ROW(NEW.tenant_ref, NEW.approval_ref, NEW.plan_ref, NEW.plan_hash, NEW.capability, NEW.parameter_hash, NEW.decision, NEW.approver_authority, NEW.decided_at, NEW.evidence_hash, NEW.attestation, NEW.audit_ref_id, NEW.created_at)
       IS NOT DISTINCT FROM
       ROW(OLD.tenant_ref, OLD.approval_ref, OLD.plan_ref, OLD.plan_hash, OLD.capability, OLD.parameter_hash, OLD.decision, OLD.approver_authority, OLD.decided_at, OLD.evidence_hash, OLD.attestation, OLD.audit_ref_id, OLD.created_at)
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'approval evidence records are immutable';
END;
$$;

CREATE TRIGGER guard_approval_transmission_lifecycle
BEFORE UPDATE OR DELETE ON approval_transmissions
FOR EACH ROW EXECUTE FUNCTION guard_approval_transmission_lifecycle();
CREATE TRIGGER reject_approval_transmission_truncate
BEFORE TRUNCATE ON approval_transmissions
FOR EACH STATEMENT EXECUTE FUNCTION reject_approval_transport_truncate();
CREATE TRIGGER guard_approval_delivery_attempts_append_only
BEFORE UPDATE OR DELETE ON approval_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION guard_approval_transport_append_only();
CREATE TRIGGER reject_approval_delivery_attempts_truncate
BEFORE TRUNCATE ON approval_delivery_attempts
FOR EACH STATEMENT EXECUTE FUNCTION reject_approval_transport_truncate();
CREATE TRIGGER guard_approval_evidence_record_immutable
BEFORE UPDATE OR DELETE ON approval_evidence_records
FOR EACH ROW EXECUTE FUNCTION guard_approval_evidence_record_immutable();
CREATE TRIGGER reject_approval_evidence_records_truncate
BEFORE TRUNCATE ON approval_evidence_records
FOR EACH STATEMENT EXECUTE FUNCTION reject_approval_transport_truncate();
CREATE TRIGGER guard_approval_revocations_append_only
BEFORE UPDATE OR DELETE ON approval_transmission_revocations
FOR EACH ROW EXECUTE FUNCTION guard_approval_transport_append_only();
CREATE TRIGGER reject_approval_revocations_truncate
BEFORE TRUNCATE ON approval_transmission_revocations
FOR EACH STATEMENT EXECUTE FUNCTION reject_approval_transport_truncate();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS approval_transmission_revocations;
DROP TABLE IF EXISTS approval_evidence_records;
DROP TABLE IF EXISTS approval_delivery_attempts;
DROP TABLE IF EXISTS approval_transmissions;
DROP FUNCTION IF EXISTS guard_approval_evidence_record_immutable();
DROP FUNCTION IF EXISTS reject_approval_transport_truncate();
DROP FUNCTION IF EXISTS guard_approval_transport_append_only();
DROP FUNCTION IF EXISTS guard_approval_transmission_lifecycle();

-- Faithful recreation of the post-000005 legacy resolution state. The
-- audit_events append-only triggers and uq_audit_events_enterprise_id_id
-- were never dropped by the Up migration, so they are not recreated here.
CREATE TABLE enterprise_approval_policies (
    enterprise_id TEXT PRIMARY KEY REFERENCES enterprises(id),
    minimum_risk TEXT NOT NULL CHECK (minimum_risk IN ('low', 'medium', 'high')),
    max_low_impacted_users INTEGER NOT NULL CHECK (max_low_impacted_users >= 0),
    max_low_impacted_org_units INTEGER NOT NULL CHECK (max_low_impacted_org_units >= 0),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE enterprise_approval_policy_versions (
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    minimum_risk TEXT NOT NULL CHECK (minimum_risk IN ('low','medium','high')),
    max_low_impacted_users INTEGER NOT NULL CHECK (max_low_impacted_users >= 0),
    max_low_impacted_org_units INTEGER NOT NULL CHECK (max_low_impacted_org_units >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (enterprise_id, policy_version)
);

CREATE FUNCTION record_enterprise_approval_policy_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO enterprise_approval_policy_versions (
        enterprise_id, policy_version, minimum_risk, max_low_impacted_users,
        max_low_impacted_org_units, created_at
    ) VALUES (NEW.enterprise_id, NEW.policy_version, NEW.minimum_risk,
        NEW.max_low_impacted_users, NEW.max_low_impacted_org_units, NEW.updated_at);
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_enterprise_approval_policy_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
	IF TG_OP = 'DELETE' THEN
		PERFORM pg_advisory_xact_lock(hashtextextended(OLD.enterprise_id, 2));
	ELSE
		PERFORM pg_advisory_xact_lock(hashtextextended(NEW.enterprise_id, 2));
	END IF;
	IF TG_OP = 'DELETE' THEN
		RAISE EXCEPTION 'enterprise approval policies cannot be deleted or truncated';
	END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.enterprise_id IS DISTINCT FROM OLD.enterprise_id OR
        NEW.policy_version <= OLD.policy_version OR
        NEW.updated_at <= OLD.updated_at
    ) THEN
        RAISE EXCEPTION 'enterprise approval policy version and updated_at must increase';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER guard_enterprise_approval_policy_version
BEFORE INSERT OR UPDATE OR DELETE ON enterprise_approval_policies
FOR EACH ROW EXECUTE FUNCTION guard_enterprise_approval_policy_version();

CREATE FUNCTION reject_enterprise_approval_policy_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'enterprise approval policies cannot be deleted or truncated';
END; $$;
CREATE TRIGGER reject_enterprise_approval_policy_truncate
BEFORE TRUNCATE ON enterprise_approval_policies
FOR EACH STATEMENT EXECUTE FUNCTION reject_enterprise_approval_policy_truncate();
CREATE FUNCTION guard_enterprise_approval_policy_history() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'enterprise approval policy history is immutable and cannot be deleted or truncated';
END; $$;
CREATE TRIGGER guard_enterprise_approval_policy_history
BEFORE UPDATE OR DELETE ON enterprise_approval_policy_versions
FOR EACH ROW EXECUTE FUNCTION guard_enterprise_approval_policy_history();
CREATE TRIGGER reject_enterprise_approval_policy_history_truncate
BEFORE TRUNCATE ON enterprise_approval_policy_versions
FOR EACH STATEMENT EXECUTE FUNCTION guard_enterprise_approval_policy_history();
CREATE TRIGGER record_enterprise_approval_policy_version
AFTER INSERT OR UPDATE ON enterprise_approval_policies
FOR EACH ROW EXECUTE FUNCTION record_enterprise_approval_policy_version();

INSERT INTO enterprise_approval_policies (
    enterprise_id, minimum_risk, max_low_impacted_users,
    max_low_impacted_org_units, policy_version
)
SELECT id, 'low', 25, 1, 1 FROM enterprises
ON CONFLICT (enterprise_id) DO NOTHING;

CREATE TABLE approval_queue_items (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL,
    requester_user_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    org_unit_id TEXT NOT NULL,
    reviewer_user_id TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    org_version BIGINT NOT NULL CHECK (org_version > 0),
    risk_reasons JSONB NOT NULL CHECK (jsonb_typeof(risk_reasons) = 'array'),
    route_mode TEXT NOT NULL CHECK (route_mode IN (
        'upward_review', 'enterprise_knowledge_admin_queue'
    )),
    org_path JSONB NOT NULL CHECK (jsonb_typeof(org_path) = 'array' AND jsonb_array_length(org_path) > 0),
    queue TEXT,
    route_input_hash TEXT NOT NULL CHECK (char_length(route_input_hash) = 64 AND route_input_hash ~ '^[0-9a-f]{64}$'),
    route_output_hash TEXT NOT NULL CHECK (char_length(route_output_hash) = 64 AND route_output_hash ~ '^[0-9a-f]{64}$'),
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    policy_version_ref BIGINT NOT NULL,
    idempotency_key_hash TEXT NOT NULL CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
    reviewer_org_unit_id TEXT,
    reviewer_display_name TEXT,
    reviewer_permission TEXT CHECK (reviewer_permission IN ('publish_low_risk','approve_high_risk')),
    reviewer_permission_org_unit_id TEXT,
    FOREIGN KEY (enterprise_id, requester_user_id)
        REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, org_unit_id)
        REFERENCES org_units(enterprise_id, id),
    FOREIGN KEY (enterprise_id, reviewer_user_id)
        REFERENCES enterprise_users(enterprise_id, id),
    CONSTRAINT fk_approval_queue_org_version
        FOREIGN KEY (enterprise_id, org_version)
        REFERENCES org_versions(enterprise_id, version_number),
    CONSTRAINT fk_approval_queue_snapshot_unit
        FOREIGN KEY (enterprise_id, org_version, org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    CONSTRAINT fk_approval_queue_reviewer_snapshot_unit
        FOREIGN KEY (enterprise_id, org_version, reviewer_org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    CONSTRAINT fk_approval_queue_permission_snapshot_unit
        FOREIGN KEY (enterprise_id, org_version, reviewer_permission_org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    CONSTRAINT fk_approval_queue_policy_version
        FOREIGN KEY (enterprise_id, policy_version_ref)
        REFERENCES enterprise_approval_policy_versions(enterprise_id, policy_version),
    CONSTRAINT chk_approval_queue_policy_version_ref CHECK (
        policy_version_ref = policy_version
    ),
    CONSTRAINT chk_approval_queue_no_self_review
        CHECK (reviewer_user_id IS NULL OR reviewer_user_id <> requester_user_id),
    CONSTRAINT chk_approval_queue_canonical_values CHECK (
        enterprise_id <> '' AND btrim(enterprise_id) = enterprise_id AND
        requester_user_id <> '' AND btrim(requester_user_id) = requester_user_id AND
        resource_type <> '' AND btrim(resource_type) = resource_type AND
        resource_id <> '' AND btrim(resource_id) = resource_id AND
        action <> '' AND btrim(action) = action AND
        org_unit_id <> '' AND btrim(org_unit_id) = org_unit_id AND
        (reviewer_user_id IS NULL OR (reviewer_user_id <> '' AND btrim(reviewer_user_id) = reviewer_user_id)) AND
        (queue IS NULL OR (queue <> '' AND btrim(queue) = queue))
    ),
    CONSTRAINT chk_approval_queue_route_shape CHECK (
        (route_mode = 'upward_review' AND reviewer_user_id IS NOT NULL AND reviewer_org_unit_id IS NOT NULL AND reviewer_display_name IS NOT NULL AND reviewer_permission IS NOT NULL AND reviewer_permission_org_unit_id IS NOT NULL AND queue IS NULL) OR
        (route_mode = 'enterprise_knowledge_admin_queue' AND reviewer_user_id IS NULL AND reviewer_org_unit_id IS NULL AND reviewer_display_name IS NULL AND reviewer_permission IS NULL AND reviewer_permission_org_unit_id IS NULL AND queue = 'enterprise_knowledge_admin')
    ),
    CONSTRAINT chk_approval_queue_status CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    CONSTRAINT uq_approval_queue_idempotency UNIQUE (enterprise_id, idempotency_key_hash),
    CONSTRAINT uq_approval_queue_enterprise_id_id UNIQUE (enterprise_id, id)
);

CREATE INDEX idx_approval_queue_items_enterprise_status ON approval_queue_items(enterprise_id, status, created_at);

CREATE TABLE approval_resolution_idempotency (
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    idempotency_key_hash TEXT NOT NULL CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    requester_user_id TEXT NOT NULL,
    org_version BIGINT NOT NULL CHECK (org_version > 0),
    org_unit_id TEXT NOT NULL,
    policy_version BIGINT NOT NULL CHECK (policy_version > 0),
    policy_version_ref BIGINT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL,
    route_mode TEXT NOT NULL CHECK (route_mode IN ('single_confirmation', 'upward_review', 'enterprise_knowledge_admin_queue')),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    risk_reasons JSONB NOT NULL,
    reviewer_user_id TEXT,
    reviewer_org_unit_id TEXT,
    reviewer_display_name TEXT,
    reviewer_permission TEXT CHECK (reviewer_permission IN ('publish_low_risk','approve_high_risk')),
    reviewer_permission_org_unit_id TEXT,
    requester_permission TEXT CHECK (requester_permission = 'publish_low_risk'),
    requester_permission_org_unit_id TEXT,
    org_path JSONB NOT NULL,
    queue TEXT,
    auto_publish BOOLEAN NOT NULL DEFAULT false CHECK (auto_publish = false),
    queue_item_id TEXT,
    audit_event_id TEXT NOT NULL,
    expected_audit_input_hash TEXT NOT NULL CHECK (expected_audit_input_hash ~ '^[0-9a-f]{64}$'),
    expected_audit_output_hash TEXT NOT NULL CHECK (expected_audit_output_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (enterprise_id, idempotency_key_hash),
    UNIQUE (audit_event_id),
    UNIQUE (queue_item_id),
    FOREIGN KEY (enterprise_id, requester_user_id) REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, reviewer_user_id) REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, org_version) REFERENCES org_versions(enterprise_id, version_number),
    FOREIGN KEY (enterprise_id, org_version, org_unit_id) REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, org_version, reviewer_org_unit_id) REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, org_version, reviewer_permission_org_unit_id) REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, org_version, requester_permission_org_unit_id) REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, policy_version_ref) REFERENCES enterprise_approval_policy_versions(enterprise_id, policy_version),
    CHECK (policy_version_ref=policy_version),
    CHECK (reviewer_user_id IS NULL OR reviewer_user_id <> requester_user_id),
    CHECK (
        (route_mode = 'single_confirmation' AND risk_level = 'low' AND reviewer_user_id IS NULL AND reviewer_org_unit_id IS NULL AND reviewer_display_name IS NULL AND reviewer_permission IS NULL AND reviewer_permission_org_unit_id IS NULL AND requester_permission = 'publish_low_risk' AND requester_permission_org_unit_id IS NOT NULL AND queue IS NULL AND queue_item_id IS NULL) OR
        (route_mode = 'upward_review' AND reviewer_user_id IS NOT NULL AND reviewer_org_unit_id IS NOT NULL AND reviewer_display_name IS NOT NULL AND reviewer_permission IS NOT NULL AND reviewer_permission_org_unit_id IS NOT NULL AND requester_permission IS NULL AND requester_permission_org_unit_id IS NULL AND queue IS NULL AND queue_item_id IS NOT NULL) OR
        (route_mode = 'enterprise_knowledge_admin_queue' AND reviewer_user_id IS NULL AND reviewer_org_unit_id IS NULL AND reviewer_display_name IS NULL AND reviewer_permission IS NULL AND reviewer_permission_org_unit_id IS NULL AND requester_permission IS NULL AND requester_permission_org_unit_id IS NULL AND queue = 'enterprise_knowledge_admin' AND queue_item_id IS NOT NULL)
    )
);

ALTER TABLE approval_resolution_idempotency
    ADD CONSTRAINT fk_approval_resolution_queue_item FOREIGN KEY (enterprise_id, queue_item_id)
        REFERENCES approval_queue_items(enterprise_id, id) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT fk_approval_resolution_audit_event FOREIGN KEY (enterprise_id, audit_event_id)
        REFERENCES audit_events(enterprise_id, id) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION require_sealed_approval_org_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM org_versions AS version
        WHERE version.enterprise_id = NEW.enterprise_id
          AND version.version_number = NEW.org_version
          AND version.policy_snapshot_sealed = true
          AND version.version_number = (
              SELECT MAX(latest.version_number) FROM org_versions AS latest
              WHERE latest.enterprise_id = NEW.enterprise_id AND latest.policy_snapshot_sealed = true
          )
    ) THEN
        RAISE EXCEPTION 'approval route requires a sealed organization policy version';
    END IF;
    IF COALESCE((SELECT policy_version FROM enterprise_approval_policies WHERE enterprise_id=NEW.enterprise_id), 0) <> NEW.policy_version THEN
        RAISE EXCEPTION 'approval route policy version is stale';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_approval_route_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    item JSONB;
    previous_unit TEXT;
    current_unit TEXT;
    expected_parent TEXT;
BEGIN
    IF jsonb_typeof(NEW.risk_reasons) <> 'array' OR jsonb_array_length(NEW.risk_reasons) = 0 THEN
        RAISE EXCEPTION 'risk reasons must be a non-empty array';
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(NEW.risk_reasons) LOOP
        IF jsonb_typeof(item) <> 'string' OR (item #>> '{}') NOT IN (
            'published_behavior_change','permission_approval_change','evidence_requirement_change',
            'execution_deadline_change','external_side_effect','enterprise_minimum_risk',
            'impacted_org_scope','impacted_user_scope','requested_risk_override',
            'unverified_change_facts','unknown_changed_field','unknown_action','action_baseline',
            'explicit_review_required','explicit_confirmation_required'
        ) THEN RAISE EXCEPTION 'invalid risk reason'; END IF;
    END LOOP;
    IF (SELECT COUNT(*) FROM jsonb_array_elements_text(NEW.risk_reasons)) <>
       (SELECT COUNT(DISTINCT value) FROM jsonb_array_elements_text(NEW.risk_reasons)) OR
       NEW.risk_reasons <> (SELECT jsonb_agg(value ORDER BY value) FROM jsonb_array_elements_text(NEW.risk_reasons)) THEN
        RAISE EXCEPTION 'risk reasons must be unique and sorted';
    END IF;
    IF jsonb_typeof(NEW.org_path) <> 'array' OR jsonb_array_length(NEW.org_path) = 0 OR NEW.org_path->>0 <> NEW.org_unit_id THEN
        RAISE EXCEPTION 'invalid organization path';
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(NEW.org_path) LOOP
        IF jsonb_typeof(item) <> 'string' OR (item #>> '{}') = '' THEN RAISE EXCEPTION 'invalid organization path item'; END IF;
        current_unit := item #>> '{}';
        IF previous_unit IS NOT NULL THEN
            SELECT parent_id INTO expected_parent FROM org_policy_snapshot_units
            WHERE enterprise_id=NEW.enterprise_id AND version_number=NEW.org_version AND org_unit_id=previous_unit;
            IF expected_parent IS DISTINCT FROM current_unit THEN RAISE EXCEPTION 'non-adjacent organization path'; END IF;
        END IF;
        previous_unit := current_unit;
    END LOOP;
    IF (SELECT COUNT(*) FROM jsonb_array_elements_text(NEW.org_path)) <>
       (SELECT COUNT(DISTINCT value) FROM jsonb_array_elements_text(NEW.org_path)) THEN
        RAISE EXCEPTION 'organization path contains duplicates';
    END IF;
    IF NEW.risk_level = 'high' AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(NEW.risk_reasons) AS reason(value)
        WHERE value NOT IN ('explicit_review_required','explicit_confirmation_required')
    ) THEN RAISE EXCEPTION 'high risk requires a raise reason'; END IF;
    IF NEW.reviewer_user_id IS NOT NULL AND (
        NEW.reviewer_org_unit_id IS DISTINCT FROM (NEW.org_path->>(jsonb_array_length(NEW.org_path)-1)) OR
        NOT EXISTS (SELECT 1 FROM enterprise_users u WHERE u.enterprise_id=NEW.enterprise_id AND u.id=NEW.reviewer_user_id AND u.display_name=NEW.reviewer_display_name) OR
        NOT EXISTS (SELECT 1 FROM org_policy_snapshot_memberships m WHERE m.enterprise_id=NEW.enterprise_id AND m.version_number=NEW.org_version AND m.enterprise_user_id=NEW.reviewer_user_id AND m.org_unit_id=NEW.reviewer_org_unit_id AND m.role='manager')
    ) THEN RAISE EXCEPTION 'invalid reviewer evidence'; END IF;
    IF NEW.reviewer_user_id IS NOT NULL AND (
        NEW.reviewer_permission IS DISTINCT FROM CASE WHEN NEW.risk_level='low' THEN 'publish_low_risk' ELSE 'approve_high_risk' END OR
        NOT EXISTS (SELECT 1 FROM org_policy_snapshot_memberships m WHERE m.enterprise_id=NEW.enterprise_id AND m.version_number=NEW.org_version AND m.enterprise_user_id=NEW.reviewer_user_id AND m.org_unit_id=NEW.reviewer_permission_org_unit_id AND m.role=NEW.reviewer_permission) OR
        NOT EXISTS (
            WITH RECURSIVE ancestors(org_unit_id, parent_id) AS (
                SELECT u.org_unit_id, u.parent_id FROM org_policy_snapshot_units u
                WHERE u.enterprise_id=NEW.enterprise_id AND u.version_number=NEW.org_version AND u.org_unit_id=NEW.org_unit_id
                UNION ALL
                SELECT p.org_unit_id, p.parent_id FROM org_policy_snapshot_units p JOIN ancestors a ON p.org_unit_id=a.parent_id
                WHERE p.enterprise_id=NEW.enterprise_id AND p.version_number=NEW.org_version
            ) SELECT 1 FROM ancestors WHERE org_unit_id=NEW.reviewer_permission_org_unit_id
        )
    ) THEN RAISE EXCEPTION 'invalid reviewer permission evidence'; END IF;
    IF NEW.route_mode='enterprise_knowledge_admin_queue' AND EXISTS (
        SELECT 1 FROM org_policy_snapshot_units u WHERE u.enterprise_id=NEW.enterprise_id AND u.version_number=NEW.org_version AND u.org_unit_id=(NEW.org_path->>(jsonb_array_length(NEW.org_path)-1)) AND u.parent_id IS NOT NULL
    ) THEN RAISE EXCEPTION 'organization admin path must reach root'; END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_direct_requester_permission_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.route_mode='single_confirmation' AND (
        NEW.requester_permission IS DISTINCT FROM 'publish_low_risk' OR
        NOT EXISTS (SELECT 1 FROM org_policy_snapshot_memberships m WHERE m.enterprise_id=NEW.enterprise_id AND m.version_number=NEW.org_version AND m.enterprise_user_id=NEW.requester_user_id AND m.org_unit_id=NEW.requester_permission_org_unit_id AND m.role='publish_low_risk') OR
        NOT EXISTS (
            WITH RECURSIVE ancestors(org_unit_id, parent_id) AS (
                SELECT u.org_unit_id, u.parent_id FROM org_policy_snapshot_units u
                WHERE u.enterprise_id=NEW.enterprise_id AND u.version_number=NEW.org_version AND u.org_unit_id=NEW.org_unit_id
                UNION ALL
                SELECT p.org_unit_id, p.parent_id FROM org_policy_snapshot_units p JOIN ancestors a ON p.org_unit_id=a.parent_id
                WHERE p.enterprise_id=NEW.enterprise_id AND p.version_number=NEW.org_version
            ) SELECT 1 FROM ancestors WHERE org_unit_id=NEW.requester_permission_org_unit_id
        )
    ) THEN RAISE EXCEPTION 'invalid requester permission evidence'; END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_approval_resolution_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'approval resolution evidence is immutable';
END; $$;

CREATE FUNCTION guard_approval_queue_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'approval queue evidence is immutable'; END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND OLD.status='pending' AND NEW.status IN ('approved', 'rejected', 'cancelled') AND
       ROW(NEW.id,NEW.enterprise_id,NEW.requester_user_id,NEW.resource_type,NEW.resource_id,NEW.action,NEW.risk_level,NEW.org_unit_id,NEW.reviewer_user_id,NEW.org_version,NEW.risk_reasons,NEW.route_mode,NEW.org_path,NEW.queue,NEW.route_input_hash,NEW.route_output_hash,NEW.policy_version,NEW.idempotency_key_hash,NEW.reviewer_org_unit_id,NEW.reviewer_display_name,NEW.reviewer_permission,NEW.reviewer_permission_org_unit_id,NEW.created_at)
       IS NOT DISTINCT FROM
       ROW(OLD.id,OLD.enterprise_id,OLD.requester_user_id,OLD.resource_type,OLD.resource_id,OLD.action,OLD.risk_level,OLD.org_unit_id,OLD.reviewer_user_id,OLD.org_version,OLD.risk_reasons,OLD.route_mode,OLD.org_path,OLD.queue,OLD.route_input_hash,OLD.route_output_hash,OLD.policy_version,OLD.idempotency_key_hash,OLD.reviewer_org_unit_id,OLD.reviewer_display_name,OLD.reviewer_permission,OLD.reviewer_permission_org_unit_id,OLD.created_at)
    THEN RETURN NEW; END IF;
    IF NEW.status IS NOT DISTINCT FROM OLD.status AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'approval queue evidence is immutable';
END; $$;

CREATE FUNCTION reject_approval_evidence_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'approval evidence truncate is forbidden'; END; $$;

CREATE FUNCTION validate_approval_resolution_links() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE linked_audit audit_events%ROWTYPE; linked_queue approval_queue_items%ROWTYPE;
BEGIN
    SELECT * INTO linked_audit FROM audit_events WHERE enterprise_id=NEW.enterprise_id AND id=NEW.audit_event_id;
    IF NOT FOUND OR linked_audit.input_hash IS DISTINCT FROM NEW.expected_audit_input_hash OR linked_audit.output_hash IS DISTINCT FROM NEW.expected_audit_output_hash OR linked_audit.actor_user_id IS DISTINCT FROM NEW.requester_user_id OR linked_audit.resource_type IS DISTINCT FROM NEW.resource_type OR linked_audit.resource_id IS DISTINCT FROM NEW.resource_id OR linked_audit.action <> 'approval.route.resolve' OR linked_audit.decision <> NEW.route_mode OR linked_audit.evidence_pointer IS DISTINCT FROM NEW.queue_item_id THEN
        RAISE EXCEPTION 'approval audit evidence mismatch';
    END IF;
    IF NEW.queue_item_id IS NOT NULL THEN
        SELECT * INTO linked_queue FROM approval_queue_items WHERE enterprise_id=NEW.enterprise_id AND id=NEW.queue_item_id;
        IF NOT FOUND OR linked_queue.route_input_hash<>NEW.expected_audit_input_hash OR linked_queue.route_output_hash<>NEW.expected_audit_output_hash OR linked_queue.idempotency_key_hash<>NEW.idempotency_key_hash OR linked_queue.route_mode<>NEW.route_mode THEN RAISE EXCEPTION 'approval queue evidence mismatch'; END IF;
    END IF;
    RETURN NULL;
END; $$;

CREATE TRIGGER require_sealed_approval_org_version
BEFORE INSERT ON approval_queue_items
FOR EACH ROW EXECUTE FUNCTION require_sealed_approval_org_version();
CREATE TRIGGER require_sealed_approval_resolution_org_version
BEFORE INSERT ON approval_resolution_idempotency
FOR EACH ROW EXECUTE FUNCTION require_sealed_approval_org_version();
CREATE TRIGGER validate_approval_queue_route_evidence
BEFORE INSERT ON approval_queue_items
FOR EACH ROW EXECUTE FUNCTION validate_approval_route_evidence();
CREATE TRIGGER validate_approval_resolution_route_evidence
BEFORE INSERT ON approval_resolution_idempotency
FOR EACH ROW EXECUTE FUNCTION validate_approval_route_evidence();
CREATE TRIGGER validate_direct_requester_permission_evidence
BEFORE INSERT ON approval_resolution_idempotency
FOR EACH ROW EXECUTE FUNCTION validate_direct_requester_permission_evidence();
CREATE TRIGGER guard_approval_resolution_evidence
BEFORE UPDATE OR DELETE ON approval_resolution_idempotency FOR EACH ROW EXECUTE FUNCTION guard_approval_resolution_evidence();
CREATE TRIGGER guard_approval_queue_evidence
BEFORE UPDATE OR DELETE ON approval_queue_items FOR EACH ROW EXECUTE FUNCTION guard_approval_queue_evidence();
CREATE TRIGGER reject_approval_resolution_truncate BEFORE TRUNCATE ON approval_resolution_idempotency FOR EACH STATEMENT EXECUTE FUNCTION reject_approval_evidence_truncate();
CREATE TRIGGER reject_approval_queue_truncate BEFORE TRUNCATE ON approval_queue_items FOR EACH STATEMENT EXECUTE FUNCTION reject_approval_evidence_truncate();
CREATE CONSTRAINT TRIGGER validate_approval_resolution_links AFTER INSERT ON approval_resolution_idempotency DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_approval_resolution_links();
-- +goose StatementEnd
