-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM approval_queue_items LIMIT 1) THEN
        RAISE EXCEPTION 'approval_queue_items contains rows; governed route migration requires an empty pre-release table';
    END IF;
END;
$$;

ALTER TABLE approval_queue_items
    ADD COLUMN org_version BIGINT NOT NULL CHECK (org_version > 0),
    ADD COLUMN risk_reasons JSONB NOT NULL CHECK (jsonb_typeof(risk_reasons) = 'array'),
    ADD COLUMN route_mode TEXT NOT NULL CHECK (route_mode IN (
        'single_confirmation', 'upward_review', 'enterprise_knowledge_admin_queue'
    )),
    ADD COLUMN org_path JSONB NOT NULL CHECK (jsonb_typeof(org_path) = 'array' AND jsonb_array_length(org_path) > 0),
    ADD COLUMN queue TEXT,
    ADD COLUMN route_input_hash TEXT NOT NULL CHECK (char_length(route_input_hash) = 64 AND route_input_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN route_output_hash TEXT NOT NULL CHECK (char_length(route_output_hash) = 64 AND route_output_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT fk_approval_queue_org_version
        FOREIGN KEY (enterprise_id, org_version)
        REFERENCES org_versions(enterprise_id, version_number),
    ADD CONSTRAINT fk_approval_queue_snapshot_unit
        FOREIGN KEY (enterprise_id, org_version, org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
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
        (route_mode = 'single_confirmation' AND reviewer_user_id IS NULL AND queue IS NULL) OR
        (route_mode = 'upward_review' AND reviewer_user_id IS NOT NULL AND queue IS NULL) OR
        (route_mode = 'enterprise_knowledge_admin_queue' AND reviewer_user_id IS NULL AND queue = 'enterprise_knowledge_admin')
    );

CREATE FUNCTION require_sealed_approval_org_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM org_versions AS version
        WHERE version.enterprise_id = NEW.enterprise_id
          AND version.version_number = NEW.org_version
          AND version.policy_snapshot_sealed = true
    ) THEN
        RAISE EXCEPTION 'approval route requires a sealed organization policy version';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER require_sealed_approval_org_version
BEFORE INSERT OR UPDATE ON approval_queue_items
FOR EACH ROW EXECUTE FUNCTION require_sealed_approval_org_version();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS require_sealed_approval_org_version ON approval_queue_items;
DROP FUNCTION IF EXISTS require_sealed_approval_org_version();
ALTER TABLE approval_queue_items
    DROP CONSTRAINT IF EXISTS chk_approval_queue_route_shape,
    DROP CONSTRAINT IF EXISTS chk_approval_queue_canonical_values,
    DROP CONSTRAINT IF EXISTS chk_approval_queue_no_self_review,
    DROP CONSTRAINT IF EXISTS fk_approval_queue_snapshot_unit,
    DROP CONSTRAINT IF EXISTS fk_approval_queue_org_version,
    DROP COLUMN IF EXISTS route_output_hash,
    DROP COLUMN IF EXISTS route_input_hash,
    DROP COLUMN IF EXISTS queue,
    DROP COLUMN IF EXISTS org_path,
    DROP COLUMN IF EXISTS route_mode,
    DROP COLUMN IF EXISTS risk_reasons,
    DROP COLUMN IF EXISTS org_version;
-- +goose StatementEnd
