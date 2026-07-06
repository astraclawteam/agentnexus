-- +goose Up
-- +goose StatementBegin
CREATE TABLE enterprises (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE enterprise_users (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    display_name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE external_identities (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    enterprise_user_id TEXT NOT NULL REFERENCES enterprise_users(id),
    provider TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (enterprise_id, provider, external_subject)
);

CREATE TABLE org_units (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    parent_id TEXT REFERENCES org_units(id),
    name TEXT NOT NULL,
    unit_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_memberships (
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    enterprise_user_id TEXT NOT NULL REFERENCES enterprise_users(id),
    org_unit_id TEXT NOT NULL REFERENCES org_units(id),
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (enterprise_id, enterprise_user_id, org_unit_id, role)
);

CREATE TABLE org_events (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_versions (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    version_number BIGINT NOT NULL,
    source_event_id TEXT REFERENCES org_events(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (enterprise_id, version_number)
);

CREATE TABLE task_runs (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    actor_user_id TEXT NOT NULL REFERENCES enterprise_users(id),
    request_id TEXT NOT NULL,
    trace_id TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE task_steps (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    task_run_id TEXT NOT NULL REFERENCES task_runs(id),
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    input_hash TEXT,
    output_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    task_run_id TEXT REFERENCES task_runs(id),
    uri TEXT NOT NULL,
    content_type TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE confirmation_checkpoints (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    task_run_id TEXT NOT NULL REFERENCES task_runs(id),
    task_step_id TEXT REFERENCES task_steps(id),
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE connector_packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    manifest_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE connector_instances (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    connector_package_id TEXT NOT NULL REFERENCES connector_packages(id),
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE connector_instance_versions (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    connector_instance_id TEXT NOT NULL REFERENCES connector_instances(id),
    version_number BIGINT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (connector_instance_id, version_number)
);

CREATE TABLE connector_health_events (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    connector_instance_id TEXT NOT NULL REFERENCES connector_instances(id),
    status TEXT NOT NULL,
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE case_tickets (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    actor_user_id TEXT NOT NULL REFERENCES enterprise_users(id),
    request_id TEXT NOT NULL,
    trace_id TEXT,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE step_grants (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    case_ticket_id TEXT NOT NULL REFERENCES case_tickets(id),
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE external_receipt_requests (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    case_ticket_id TEXT REFERENCES case_tickets(id),
    step_grant_id TEXT REFERENCES step_grants(id),
    receipt_target TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE external_receipts (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    external_receipt_request_id TEXT NOT NULL REFERENCES external_receipt_requests(id),
    result TEXT NOT NULL,
    evidence_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    case_ticket_id TEXT REFERENCES case_tickets(id),
    step_grant_id TEXT REFERENCES step_grants(id),
    actor_user_id TEXT,
    connector_instance_id TEXT,
    resource_type TEXT,
    resource_id TEXT,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    input_hash TEXT,
    output_hash TEXT,
    evidence_pointer TEXT,
    prev_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_hash_heads (
    enterprise_id TEXT PRIMARY KEY REFERENCES enterprises(id),
    event_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_enterprise_users_enterprise ON enterprise_users(enterprise_id);
CREATE INDEX idx_org_units_enterprise ON org_units(enterprise_id);
CREATE INDEX idx_task_runs_enterprise ON task_runs(enterprise_id);
CREATE INDEX idx_case_tickets_enterprise ON case_tickets(enterprise_id);
CREATE INDEX idx_audit_events_ticket ON audit_events(case_ticket_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_hash_heads;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS external_receipts;
DROP TABLE IF EXISTS external_receipt_requests;
DROP TABLE IF EXISTS step_grants;
DROP TABLE IF EXISTS case_tickets;
DROP TABLE IF EXISTS connector_health_events;
DROP TABLE IF EXISTS connector_instance_versions;
DROP TABLE IF EXISTS connector_instances;
DROP TABLE IF EXISTS connector_packages;
DROP TABLE IF EXISTS confirmation_checkpoints;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS task_steps;
DROP TABLE IF EXISTS task_runs;
DROP TABLE IF EXISTS org_versions;
DROP TABLE IF EXISTS org_events;
DROP TABLE IF EXISTS org_memberships;
DROP TABLE IF EXISTS org_units;
DROP TABLE IF EXISTS external_identities;
DROP TABLE IF EXISTS enterprise_users;
DROP TABLE IF EXISTS enterprises;
-- +goose StatementEnd
