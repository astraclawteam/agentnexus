-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM approval_queue_items LIMIT 1) THEN
        RAISE EXCEPTION 'approval_queue_items contains rows; governed route migration requires an empty pre-release table';
    END IF;
END;
$$;

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
BEFORE UPDATE ON enterprise_approval_policies
FOR EACH ROW EXECUTE FUNCTION guard_enterprise_approval_policy_version();
CREATE TRIGGER record_enterprise_approval_policy_version
AFTER INSERT OR UPDATE ON enterprise_approval_policies
FOR EACH ROW EXECUTE FUNCTION record_enterprise_approval_policy_version();

ALTER TABLE approval_queue_items
    ADD COLUMN org_version BIGINT NOT NULL CHECK (org_version > 0),
    ADD COLUMN risk_reasons JSONB NOT NULL CHECK (jsonb_typeof(risk_reasons) = 'array'),
    ADD COLUMN route_mode TEXT NOT NULL CHECK (route_mode IN (
        'upward_review', 'enterprise_knowledge_admin_queue'
    )),
    ADD COLUMN org_path JSONB NOT NULL CHECK (jsonb_typeof(org_path) = 'array' AND jsonb_array_length(org_path) > 0),
    ADD COLUMN queue TEXT,
    ADD COLUMN route_input_hash TEXT NOT NULL CHECK (char_length(route_input_hash) = 64 AND route_input_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN route_output_hash TEXT NOT NULL CHECK (char_length(route_output_hash) = 64 AND route_output_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN policy_version BIGINT NOT NULL CHECK (policy_version >= 0),
    ADD COLUMN policy_version_ref BIGINT,
    ADD COLUMN idempotency_key_hash TEXT NOT NULL CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN reviewer_org_unit_id TEXT,
    ADD COLUMN reviewer_display_name TEXT,
    ADD CONSTRAINT fk_approval_queue_org_version
        FOREIGN KEY (enterprise_id, org_version)
        REFERENCES org_versions(enterprise_id, version_number),
    ADD CONSTRAINT fk_approval_queue_snapshot_unit
        FOREIGN KEY (enterprise_id, org_version, org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    ADD CONSTRAINT fk_approval_queue_reviewer_snapshot_unit
        FOREIGN KEY (enterprise_id, org_version, reviewer_org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    ADD CONSTRAINT fk_approval_queue_policy_version
        FOREIGN KEY (enterprise_id, policy_version_ref)
        REFERENCES enterprise_approval_policy_versions(enterprise_id, policy_version),
    ADD CONSTRAINT chk_approval_queue_policy_version_ref CHECK (
        (policy_version = 0 AND policy_version_ref IS NULL) OR
        (policy_version > 0 AND policy_version_ref = policy_version)
    ),
    ADD CONSTRAINT chk_approval_queue_no_self_review
        CHECK (reviewer_user_id IS NULL OR reviewer_user_id <> requester_user_id),
    ADD CONSTRAINT chk_approval_queue_canonical_values CHECK (
        enterprise_id <> '' AND btrim(enterprise_id) = enterprise_id AND
        requester_user_id <> '' AND btrim(requester_user_id) = requester_user_id AND
        resource_type <> '' AND btrim(resource_type) = resource_type AND
        resource_id <> '' AND btrim(resource_id) = resource_id AND
        action <> '' AND btrim(action) = action AND
        org_unit_id <> '' AND btrim(org_unit_id) = org_unit_id AND
        (reviewer_user_id IS NULL OR (reviewer_user_id <> '' AND btrim(reviewer_user_id) = reviewer_user_id)) AND
        (queue IS NULL OR (queue <> '' AND btrim(queue) = queue))
    ),
    ADD CONSTRAINT chk_approval_queue_route_shape CHECK (
        (route_mode = 'upward_review' AND reviewer_user_id IS NOT NULL AND reviewer_org_unit_id IS NOT NULL AND reviewer_display_name IS NOT NULL AND queue IS NULL) OR
        (route_mode = 'enterprise_knowledge_admin_queue' AND reviewer_user_id IS NULL AND queue = 'enterprise_knowledge_admin')
    ),
    ADD CONSTRAINT chk_approval_queue_status CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    ADD CONSTRAINT uq_approval_queue_idempotency UNIQUE (enterprise_id, idempotency_key_hash);

CREATE TABLE approval_resolution_idempotency (
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    idempotency_key_hash TEXT NOT NULL CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    requester_user_id TEXT NOT NULL,
    org_version BIGINT NOT NULL CHECK (org_version > 0),
    org_unit_id TEXT NOT NULL,
    policy_version BIGINT NOT NULL CHECK (policy_version >= 0),
    policy_version_ref BIGINT,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL,
    route_mode TEXT NOT NULL CHECK (route_mode IN ('single_confirmation', 'upward_review', 'enterprise_knowledge_admin_queue')),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    risk_reasons JSONB NOT NULL,
    reviewer_user_id TEXT,
    reviewer_org_unit_id TEXT,
    reviewer_display_name TEXT,
    org_path JSONB NOT NULL,
    queue TEXT,
    auto_publish BOOLEAN NOT NULL DEFAULT false CHECK (auto_publish = false),
    queue_item_id TEXT,
    audit_event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (enterprise_id, idempotency_key_hash),
    UNIQUE (audit_event_id),
    UNIQUE (queue_item_id),
    FOREIGN KEY (enterprise_id, requester_user_id) REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, reviewer_user_id) REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, org_version) REFERENCES org_versions(enterprise_id, version_number),
    FOREIGN KEY (enterprise_id, org_version, org_unit_id) REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, org_version, reviewer_org_unit_id) REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, policy_version_ref) REFERENCES enterprise_approval_policy_versions(enterprise_id, policy_version),
    CHECK ((policy_version=0 AND policy_version_ref IS NULL) OR (policy_version>0 AND policy_version_ref=policy_version)),
    CHECK (reviewer_user_id IS NULL OR reviewer_user_id <> requester_user_id),
    CHECK (
        (route_mode = 'single_confirmation' AND risk_level = 'low' AND reviewer_user_id IS NULL AND queue IS NULL AND queue_item_id IS NULL) OR
        (route_mode = 'upward_review' AND reviewer_user_id IS NOT NULL AND reviewer_org_unit_id IS NOT NULL AND reviewer_display_name IS NOT NULL AND queue IS NULL AND queue_item_id IS NOT NULL) OR
        (route_mode = 'enterprise_knowledge_admin_queue' AND reviewer_user_id IS NULL AND queue = 'enterprise_knowledge_admin' AND queue_item_id IS NOT NULL)
    )
);

ALTER TABLE approval_resolution_idempotency
    ADD CONSTRAINT fk_approval_resolution_queue_item FOREIGN KEY (queue_item_id)
        REFERENCES approval_queue_items(id) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT fk_approval_resolution_audit_event FOREIGN KEY (audit_event_id)
        REFERENCES audit_events(id) DEFERRABLE INITIALLY DEFERRED;

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
    RETURN NEW;
END;
$$;

CREATE TRIGGER require_sealed_approval_org_version
BEFORE INSERT OR UPDATE ON approval_queue_items
FOR EACH ROW EXECUTE FUNCTION require_sealed_approval_org_version();
CREATE TRIGGER require_sealed_approval_resolution_org_version
BEFORE INSERT OR UPDATE ON approval_resolution_idempotency
FOR EACH ROW EXECUTE FUNCTION require_sealed_approval_org_version();
CREATE TRIGGER validate_approval_queue_route_evidence
BEFORE INSERT OR UPDATE ON approval_queue_items
FOR EACH ROW EXECUTE FUNCTION validate_approval_route_evidence();
CREATE TRIGGER validate_approval_resolution_route_evidence
BEFORE INSERT OR UPDATE ON approval_resolution_idempotency
FOR EACH ROW EXECUTE FUNCTION validate_approval_route_evidence();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS require_sealed_approval_org_version ON approval_queue_items;
DROP TRIGGER IF EXISTS require_sealed_approval_resolution_org_version ON approval_resolution_idempotency;
DROP TRIGGER IF EXISTS validate_approval_queue_route_evidence ON approval_queue_items;
DROP TRIGGER IF EXISTS validate_approval_resolution_route_evidence ON approval_resolution_idempotency;
DROP FUNCTION IF EXISTS validate_approval_route_evidence();
DROP FUNCTION IF EXISTS require_sealed_approval_org_version();
DROP TABLE IF EXISTS approval_resolution_idempotency;
ALTER TABLE approval_queue_items
    DROP CONSTRAINT IF EXISTS chk_approval_queue_route_shape,
    DROP CONSTRAINT IF EXISTS chk_approval_queue_status,
    DROP CONSTRAINT IF EXISTS uq_approval_queue_idempotency,
    DROP CONSTRAINT IF EXISTS chk_approval_queue_canonical_values,
    DROP CONSTRAINT IF EXISTS chk_approval_queue_no_self_review,
    DROP CONSTRAINT IF EXISTS fk_approval_queue_snapshot_unit,
    DROP CONSTRAINT IF EXISTS fk_approval_queue_reviewer_snapshot_unit,
    DROP CONSTRAINT IF EXISTS fk_approval_queue_org_version,
    DROP CONSTRAINT IF EXISTS fk_approval_queue_policy_version,
    DROP CONSTRAINT IF EXISTS chk_approval_queue_policy_version_ref,
    DROP COLUMN IF EXISTS route_output_hash,
    DROP COLUMN IF EXISTS route_input_hash,
    DROP COLUMN IF EXISTS reviewer_display_name,
    DROP COLUMN IF EXISTS reviewer_org_unit_id,
    DROP COLUMN IF EXISTS idempotency_key_hash,
    DROP COLUMN IF EXISTS policy_version_ref,
    DROP COLUMN IF EXISTS queue,
    DROP COLUMN IF EXISTS org_path,
    DROP COLUMN IF EXISTS route_mode,
    DROP COLUMN IF EXISTS risk_reasons,
    DROP COLUMN IF EXISTS org_version,
    DROP COLUMN IF EXISTS policy_version;
DROP TRIGGER IF EXISTS guard_enterprise_approval_policy_version ON enterprise_approval_policies;
DROP TRIGGER IF EXISTS record_enterprise_approval_policy_version ON enterprise_approval_policies;
DROP FUNCTION IF EXISTS record_enterprise_approval_policy_version();
DROP FUNCTION IF EXISTS guard_enterprise_approval_policy_version();
DROP TABLE IF EXISTS enterprise_approval_policy_versions;
DROP TABLE IF EXISTS enterprise_approval_policies;
-- +goose StatementEnd
