-- +goose Up
-- +goose StatementBegin
LOCK TABLE org_versions, org_units, org_memberships IN SHARE ROW EXCLUSIVE MODE;

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

CREATE FUNCTION reject_org_policy_snapshot_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'organization policy snapshots are immutable';
END;
$$;

CREATE TRIGGER reject_org_policy_snapshot_units_mutation
BEFORE UPDATE OR DELETE ON org_policy_snapshot_units
FOR EACH ROW EXECUTE FUNCTION reject_org_policy_snapshot_mutation();

CREATE TRIGGER reject_org_policy_snapshot_memberships_mutation
BEFORE UPDATE OR DELETE ON org_policy_snapshot_memberships
FOR EACH ROW EXECUTE FUNCTION reject_org_policy_snapshot_mutation();

WITH latest AS (
    SELECT DISTINCT ON (enterprise_id) enterprise_id, version_number
    FROM org_versions
    ORDER BY enterprise_id, version_number DESC
)
INSERT INTO org_policy_snapshot_units (enterprise_id, version_number, org_unit_id, parent_id)
SELECT u.enterprise_id, latest.version_number, u.id, u.parent_id
FROM latest
JOIN org_units AS u ON u.enterprise_id = latest.enterprise_id;

WITH latest AS (
    SELECT DISTINCT ON (enterprise_id) enterprise_id, version_number
    FROM org_versions
    ORDER BY enterprise_id, version_number DESC
)
INSERT INTO org_policy_snapshot_memberships (
    enterprise_id, version_number, enterprise_user_id, org_unit_id, role
)
SELECT m.enterprise_id, latest.version_number, m.enterprise_user_id, m.org_unit_id, m.role
FROM latest
JOIN org_memberships AS m ON m.enterprise_id = latest.enterprise_id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS org_policy_snapshot_memberships;
DROP TABLE IF EXISTS org_policy_snapshot_units;
DROP FUNCTION IF EXISTS reject_org_policy_snapshot_mutation();
-- +goose StatementEnd
