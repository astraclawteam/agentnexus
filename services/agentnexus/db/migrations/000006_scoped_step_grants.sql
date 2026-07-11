-- +goose Up
-- +goose StatementBegin
ALTER TABLE case_tickets ADD COLUMN token_hash TEXT;
-- Pre-hash CaseTickets used their database id as the bearer. They are deliberately
-- revoked instead of being silently admitted to the new domain-separated format.
UPDATE case_tickets SET
    status='revoked',
    expires_at=LEAST(expires_at, clock_timestamp()),
    token_hash=encode(sha256(convert_to(
        'agentnexus:invalidated-legacy-case-ticket:v1:' || enterprise_id || ':' || id,
        'UTF8'
    )),'hex')
WHERE token_hash IS NULL;
ALTER TABLE case_tickets ALTER COLUMN token_hash SET NOT NULL;
ALTER TABLE case_tickets ADD CONSTRAINT chk_case_ticket_token_hash CHECK (token_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE case_tickets ADD CONSTRAINT uq_case_ticket_token_hash UNIQUE (enterprise_id, token_hash);
ALTER TABLE step_grants ADD CONSTRAINT uq_step_grants_enterprise_id_id UNIQUE (enterprise_id, id);
ALTER TABLE case_tickets ADD CONSTRAINT uq_case_tickets_enterprise_id_id UNIQUE (enterprise_id, id);
ALTER TABLE step_grants ADD CONSTRAINT fk_step_grants_enterprise_ticket
    FOREIGN KEY (enterprise_id, case_ticket_id) REFERENCES case_tickets(enterprise_id, id);

CREATE TABLE sensitive_resource_ownerships (
    enterprise_id TEXT NOT NULL,
    resource_type TEXT NOT NULL CHECK (resource_type = 'dream_evidence'),
    resource_id TEXT NOT NULL CHECK (resource_id <> '' AND btrim(resource_id) = resource_id),
    org_version BIGINT NOT NULL CHECK (org_version > 0),
    org_unit_id TEXT NOT NULL CHECK (org_unit_id <> '' AND btrim(org_unit_id) = org_unit_id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (enterprise_id, resource_type, resource_id),
    FOREIGN KEY (enterprise_id, org_version, org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id)
);

CREATE FUNCTION serialize_sensitive_resource_ownership() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE enterprise TEXT; version BIGINT;
BEGIN
    enterprise := CASE WHEN TG_OP='DELETE' THEN OLD.enterprise_id ELSE NEW.enterprise_id END;
    PERFORM pg_advisory_xact_lock(hashtextextended(enterprise, 0));
    IF TG_OP <> 'DELETE' THEN
        SELECT MAX(v.version_number) INTO version FROM org_versions v
        WHERE v.enterprise_id=NEW.enterprise_id AND v.policy_snapshot_sealed=true;
        IF version IS DISTINCT FROM NEW.org_version THEN RAISE EXCEPTION 'sensitive resource ownership requires latest sealed organization version'; END IF;
    END IF;
    RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END; $$;
CREATE TRIGGER serialize_sensitive_resource_ownership
BEFORE INSERT OR UPDATE OR DELETE ON sensitive_resource_ownerships
FOR EACH ROW EXECUTE FUNCTION serialize_sensitive_resource_ownership();

CREATE TABLE step_grant_issuances (
    enterprise_id TEXT NOT NULL,
    step_grant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    actor_user_id TEXT NOT NULL,
    org_version BIGINT NOT NULL CHECK (org_version > 0),
    org_unit_id TEXT NOT NULL,
    audit_event_id TEXT NOT NULL,
    expected_audit_input_hash TEXT NOT NULL CHECK (expected_audit_input_hash ~ '^[0-9a-f]{64}$'),
    expected_audit_output_hash TEXT NOT NULL CHECK (expected_audit_output_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (enterprise_id, step_grant_id),
    UNIQUE (enterprise_id, token_hash),
    FOREIGN KEY (enterprise_id, step_grant_id)
        REFERENCES step_grants(enterprise_id, id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (enterprise_id, actor_user_id)
        REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, org_version, org_unit_id)
        REFERENCES org_policy_snapshot_units(enterprise_id, version_number, org_unit_id),
    FOREIGN KEY (enterprise_id, audit_event_id)
        REFERENCES audit_events(enterprise_id, id) DEFERRABLE INITIALLY DEFERRED
);

COMMENT ON COLUMN case_tickets.token_hash IS 'SHA-256(agentnexus:case-ticket:v1: || opaque credential); legacy ids are revoked';
COMMENT ON COLUMN step_grant_issuances.token_hash IS 'SHA-256(agentnexus:step-grant:v1: || opaque credential)';

CREATE INDEX idx_step_grants_enterprise_expiry
    ON step_grants(enterprise_id, expires_at);

CREATE FUNCTION guard_step_grant_issuance_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'step grant issuance evidence is immutable';
END; $$;
CREATE TRIGGER guard_step_grant_issuance_evidence
BEFORE UPDATE OR DELETE ON step_grant_issuances
FOR EACH ROW EXECUTE FUNCTION guard_step_grant_issuance_evidence();
CREATE TRIGGER reject_step_grant_issuance_truncate
BEFORE TRUNCATE ON step_grant_issuances
FOR EACH STATEMENT EXECUTE FUNCTION guard_step_grant_issuance_evidence();

CREATE FUNCTION guard_governed_step_grant_scope() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    IF EXISTS (SELECT 1 FROM step_grant_issuances i WHERE i.enterprise_id=OLD.enterprise_id AND i.step_grant_id=OLD.id) THEN
        RAISE EXCEPTION 'step grant scope is immutable';
    END IF;
    RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END; $$;
CREATE TRIGGER guard_governed_step_grant_scope
BEFORE UPDATE OR DELETE ON step_grants
FOR EACH ROW EXECUTE FUNCTION guard_governed_step_grant_scope();

CREATE FUNCTION validate_step_grant_issuance() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE grant_row step_grants%ROWTYPE; audit_row audit_events%ROWTYPE;
BEGIN
    SELECT * INTO grant_row FROM step_grants WHERE enterprise_id=NEW.enterprise_id AND id=NEW.step_grant_id;
    IF NOT FOUND OR grant_row.resource_type <> 'dream_evidence' OR grant_row.action <> 'read' OR
       grant_row.scopes <> '["dream:evidence:read"]'::jsonb OR grant_row.expires_at > grant_row.created_at + INTERVAL '5 minutes' OR
       grant_row.expires_at <= grant_row.created_at OR grant_row.expires_at > (SELECT t.expires_at FROM case_tickets t WHERE t.enterprise_id=grant_row.enterprise_id AND t.id=grant_row.case_ticket_id) THEN
        RAISE EXCEPTION 'invalid exact step grant scope';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM org_versions v WHERE v.enterprise_id=NEW.enterprise_id AND v.version_number=NEW.org_version AND v.policy_snapshot_sealed=true AND v.version_number=(SELECT MAX(v2.version_number) FROM org_versions v2 WHERE v2.enterprise_id=NEW.enterprise_id AND v2.policy_snapshot_sealed=true)) THEN
        RAISE EXCEPTION 'step grant organization version is stale';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM sensitive_resource_ownerships o WHERE o.enterprise_id=NEW.enterprise_id AND o.resource_type=grant_row.resource_type AND o.resource_id=grant_row.resource_id AND o.org_version=NEW.org_version AND o.org_unit_id=NEW.org_unit_id) THEN
        RAISE EXCEPTION 'step grant resource ownership is stale';
    END IF;
    SELECT * INTO audit_row FROM audit_events WHERE enterprise_id=NEW.enterprise_id AND id=NEW.audit_event_id;
    IF NOT FOUND OR audit_row.step_grant_id IS DISTINCT FROM NEW.step_grant_id OR audit_row.case_ticket_id IS DISTINCT FROM grant_row.case_ticket_id OR audit_row.actor_user_id IS DISTINCT FROM NEW.actor_user_id OR audit_row.resource_type IS DISTINCT FROM grant_row.resource_type OR audit_row.resource_id IS DISTINCT FROM grant_row.resource_id OR audit_row.action <> 'step_grant.issue' OR audit_row.decision <> 'allow' OR audit_row.evidence_pointer IS DISTINCT FROM NEW.step_grant_id OR audit_row.input_hash IS DISTINCT FROM NEW.expected_audit_input_hash OR audit_row.output_hash IS DISTINCT FROM NEW.expected_audit_output_hash THEN
        RAISE EXCEPTION 'step grant audit evidence mismatch';
    END IF;
    RETURN NULL;
END; $$;
CREATE CONSTRAINT TRIGGER validate_step_grant_issuance
AFTER INSERT ON step_grant_issuances DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_step_grant_issuance();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS validate_step_grant_issuance ON step_grant_issuances;
DROP TRIGGER IF EXISTS guard_governed_step_grant_scope ON step_grants;
DROP TRIGGER IF EXISTS guard_step_grant_issuance_evidence ON step_grant_issuances;
DROP TRIGGER IF EXISTS reject_step_grant_issuance_truncate ON step_grant_issuances;
DROP TRIGGER IF EXISTS serialize_sensitive_resource_ownership ON sensitive_resource_ownerships;
DROP FUNCTION IF EXISTS validate_step_grant_issuance();
DROP FUNCTION IF EXISTS guard_governed_step_grant_scope();
DROP FUNCTION IF EXISTS guard_step_grant_issuance_evidence();
DROP FUNCTION IF EXISTS serialize_sensitive_resource_ownership();
DROP INDEX IF EXISTS idx_step_grants_enterprise_expiry;
DROP TABLE IF EXISTS step_grant_issuances;
DROP TABLE IF EXISTS sensitive_resource_ownerships;
ALTER TABLE step_grants DROP CONSTRAINT IF EXISTS fk_step_grants_enterprise_ticket;
ALTER TABLE step_grants DROP CONSTRAINT IF EXISTS uq_step_grants_enterprise_id_id;
ALTER TABLE case_tickets DROP CONSTRAINT IF EXISTS uq_case_tickets_enterprise_id_id;
ALTER TABLE case_tickets DROP CONSTRAINT IF EXISTS uq_case_ticket_token_hash;
ALTER TABLE case_tickets DROP CONSTRAINT IF EXISTS chk_case_ticket_token_hash;
ALTER TABLE case_tickets DROP COLUMN IF EXISTS token_hash;
-- +goose StatementEnd
