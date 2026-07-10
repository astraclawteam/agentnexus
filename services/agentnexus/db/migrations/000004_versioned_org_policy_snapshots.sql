-- +goose Up
-- +goose StatementBegin
ALTER TABLE org_versions
    ADD COLUMN policy_snapshot_sealed BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE org_policy_snapshot_units (
    enterprise_id TEXT NOT NULL CHECK (enterprise_id <> '' AND btrim(enterprise_id) = enterprise_id),
    version_number BIGINT NOT NULL CHECK (version_number > 0),
    org_unit_id TEXT NOT NULL CHECK (org_unit_id <> '' AND btrim(org_unit_id) = org_unit_id),
    parent_id TEXT CHECK (parent_id IS NULL OR (parent_id <> '' AND btrim(parent_id) = parent_id)),
    PRIMARY KEY (enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, version_number)
        REFERENCES org_versions(enterprise_id, version_number),
    FOREIGN KEY (enterprise_id, version_number, parent_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE org_policy_snapshot_memberships (
    enterprise_id TEXT NOT NULL CHECK (enterprise_id <> '' AND btrim(enterprise_id) = enterprise_id),
    version_number BIGINT NOT NULL CHECK (version_number > 0),
    enterprise_user_id TEXT NOT NULL CHECK (enterprise_user_id <> '' AND btrim(enterprise_user_id) = enterprise_user_id),
    org_unit_id TEXT NOT NULL CHECK (org_unit_id <> '' AND btrim(org_unit_id) = org_unit_id),
    role TEXT NOT NULL CHECK (
        btrim(role) = role AND role IN (
            'member', 'manager', 'admin', 'suggest', 'edit', 'publish_low_risk',
            'approve_high_risk', 'workflow_edit', 'workflow_advanced', 'service_mode'
        )
    ),
    PRIMARY KEY (enterprise_id, version_number, enterprise_user_id, org_unit_id, role),
    FOREIGN KEY (enterprise_id, version_number)
        REFERENCES org_versions(enterprise_id, version_number),
    FOREIGN KEY (enterprise_id, enterprise_user_id)
        REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, version_number, org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id)
);

CREATE INDEX idx_org_policy_snapshot_units_parent
    ON org_policy_snapshot_units(enterprise_id, version_number, parent_id);
CREATE INDEX idx_org_policy_snapshot_memberships_actor
    ON org_policy_snapshot_memberships(enterprise_id, version_number, enterprise_user_id, org_unit_id);

CREATE FUNCTION guard_org_policy_snapshot_row() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') AND NOT EXISTS (
        SELECT 1 FROM org_versions AS v
        WHERE v.enterprise_id = OLD.enterprise_id
          AND v.version_number = OLD.version_number
          AND v.policy_snapshot_sealed = false
    ) THEN
        RAISE EXCEPTION 'policy snapshot is sealed or unpublished';
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') AND NOT EXISTS (
        SELECT 1 FROM org_versions AS v
        WHERE v.enterprise_id = NEW.enterprise_id
          AND v.version_number = NEW.version_number
          AND v.policy_snapshot_sealed = false
    ) THEN
        RAISE EXCEPTION 'policy snapshot is sealed or unpublished';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION reject_org_policy_snapshot_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'policy snapshot truncate is forbidden';
END;
$$;

CREATE FUNCTION guard_org_policy_version_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
	IF TG_OP = 'DELETE' THEN
		IF OLD.policy_snapshot_sealed THEN
			RAISE EXCEPTION 'sealed policy snapshot version cannot be deleted';
		END IF;
		RETURN OLD;
	END IF;
    IF TG_OP = 'INSERT' AND NEW.policy_snapshot_sealed THEN
        RAISE EXCEPTION 'policy snapshot must be inserted unsealed';
    END IF;
	IF TG_OP = 'UPDATE' AND NOT OLD.policy_snapshot_sealed AND NEW.policy_snapshot_sealed AND (
		NEW.id IS DISTINCT FROM OLD.id OR
		NEW.enterprise_id IS DISTINCT FROM OLD.enterprise_id OR
		NEW.version_number IS DISTINCT FROM OLD.version_number OR
		NEW.source_event_id IS DISTINCT FROM OLD.source_event_id OR
		NEW.created_at IS DISTINCT FROM OLD.created_at
	) THEN
		RAISE EXCEPTION 'policy snapshot seal cannot change version identity';
	END IF;
    IF TG_OP = 'UPDATE' AND OLD.policy_snapshot_sealed AND (
        NOT NEW.policy_snapshot_sealed OR
        NEW.id IS DISTINCT FROM OLD.id OR
        NEW.enterprise_id IS DISTINCT FROM OLD.enterprise_id OR
        NEW.version_number IS DISTINCT FROM OLD.version_number OR
        NEW.source_event_id IS DISTINCT FROM OLD.source_event_id OR
        NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION 'sealed policy snapshot cannot be unsealed or changed';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER guard_org_policy_snapshot_units_rows
BEFORE INSERT OR UPDATE OR DELETE ON org_policy_snapshot_units
FOR EACH ROW EXECUTE FUNCTION guard_org_policy_snapshot_row();
CREATE TRIGGER guard_org_policy_snapshot_memberships_rows
BEFORE INSERT OR UPDATE OR DELETE ON org_policy_snapshot_memberships
FOR EACH ROW EXECUTE FUNCTION guard_org_policy_snapshot_row();

CREATE TRIGGER reject_org_policy_snapshot_units_truncate
BEFORE TRUNCATE ON org_policy_snapshot_units
FOR EACH STATEMENT EXECUTE FUNCTION reject_org_policy_snapshot_truncate();
CREATE TRIGGER reject_org_policy_snapshot_memberships_truncate
BEFORE TRUNCATE ON org_policy_snapshot_memberships
FOR EACH STATEMENT EXECUTE FUNCTION reject_org_policy_snapshot_truncate();

CREATE TRIGGER guard_org_policy_version_seal
BEFORE INSERT OR UPDATE OR DELETE ON org_versions
FOR EACH ROW EXECUTE FUNCTION guard_org_policy_version_seal();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS org_policy_snapshot_memberships;
DROP TABLE IF EXISTS org_policy_snapshot_units;
DROP FUNCTION IF EXISTS guard_org_policy_snapshot_row();
DROP FUNCTION IF EXISTS reject_org_policy_snapshot_truncate();
DROP TRIGGER IF EXISTS guard_org_policy_version_seal ON org_versions;
DROP FUNCTION IF EXISTS guard_org_policy_version_seal();
ALTER TABLE org_versions DROP COLUMN IF EXISTS policy_snapshot_sealed;
-- +goose StatementEnd
