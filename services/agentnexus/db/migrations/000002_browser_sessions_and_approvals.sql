-- +goose Up
-- +goose StatementBegin
ALTER TABLE enterprise_users
    ADD CONSTRAINT uq_enterprise_users_enterprise_id_id UNIQUE (enterprise_id, id);

ALTER TABLE org_units
    ADD CONSTRAINT uq_org_units_enterprise_id_id UNIQUE (enterprise_id, id);

ALTER TABLE org_memberships
    ADD CONSTRAINT fk_org_memberships_enterprise_user
    FOREIGN KEY (enterprise_id, enterprise_user_id) REFERENCES enterprise_users(enterprise_id, id),
    ADD CONSTRAINT fk_org_memberships_enterprise_unit
    FOREIGN KEY (enterprise_id, org_unit_id) REFERENCES org_units(enterprise_id, id);

CREATE TABLE browser_sessions (
    id_hash TEXT PRIMARY KEY CHECK (char_length(id_hash) = 64 AND id_hash ~ '^[0-9a-f]{64}$'),
    enterprise_id TEXT NOT NULL,
    enterprise_user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent_hash TEXT NOT NULL CHECK (char_length(user_agent_hash) = 64 AND user_agent_hash ~ '^[0-9a-f]{64}$'),
    FOREIGN KEY (enterprise_id, enterprise_user_id)
        REFERENCES enterprise_users(enterprise_id, id),
    CHECK (idle_expires_at <= absolute_expires_at)
);

CREATE TABLE oauth_authorization_codes (
    code_hash TEXT PRIMARY KEY CHECK (char_length(code_hash) = 64 AND code_hash ~ '^[0-9a-f]{64}$'),
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    enterprise_id TEXT NOT NULL,
    enterprise_user_id TEXT NOT NULL,
    code_challenge TEXT NOT NULL CHECK (char_length(code_challenge) = 43 AND code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    nonce TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (enterprise_id, enterprise_user_id)
        REFERENCES enterprise_users(enterprise_id, id)
);

CREATE TABLE oidc_login_attempts (
    state_hash TEXT PRIMARY KEY CHECK (char_length(state_hash) = 64 AND state_hash ~ '^[0-9a-f]{64}$'),
    binding_hash TEXT NOT NULL CHECK (char_length(binding_hash) = 64 AND binding_hash ~ '^[0-9a-f]{64}$'),
    browser_id_hash TEXT NOT NULL CHECK (char_length(browser_id_hash) = 64 AND browser_id_hash ~ '^[0-9a-f]{64}$'),
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    console_state TEXT NOT NULL,
    console_nonce TEXT NOT NULL,
    code_challenge TEXT NOT NULL CHECK (char_length(code_challenge) = 43 AND code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    upstream_nonce TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '5 minutes')
);

CREATE TABLE oidc_authorize_rate_limits (
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    client_id TEXT NOT NULL,
    source_hash TEXT NOT NULL CHECK (char_length(source_hash) = 64 AND source_hash ~ '^[0-9a-f]{64}$'),
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL CHECK (request_count > 0),
    PRIMARY KEY (enterprise_id, client_id, source_hash, window_start)
);

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
    FOREIGN KEY (enterprise_id, requester_user_id)
        REFERENCES enterprise_users(enterprise_id, id),
    FOREIGN KEY (enterprise_id, org_unit_id)
        REFERENCES org_units(enterprise_id, id),
    FOREIGN KEY (enterprise_id, reviewer_user_id)
        REFERENCES enterprise_users(enterprise_id, id)
);

CREATE INDEX idx_browser_sessions_user ON browser_sessions(enterprise_id, enterprise_user_id);
CREATE INDEX idx_browser_sessions_expiry ON browser_sessions(idle_expires_at, absolute_expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_oauth_authorization_codes_expiry ON oauth_authorization_codes(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX idx_oidc_login_attempts_expiry ON oidc_login_attempts(expires_at);
CREATE INDEX idx_oidc_login_attempts_scope_browser ON oidc_login_attempts(enterprise_id, client_id, browser_id_hash, expires_at);
CREATE INDEX idx_oidc_authorize_rate_limits_window ON oidc_authorize_rate_limits(window_start);
CREATE INDEX idx_audit_events_enterprise_chain ON audit_events(enterprise_id, created_at DESC, id DESC);
CREATE INDEX idx_approval_queue_items_enterprise_status ON approval_queue_items(enterprise_id, status, created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS approval_queue_items;
DROP TABLE IF EXISTS oidc_authorize_rate_limits;
DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS oidc_login_attempts;
DROP TABLE IF EXISTS browser_sessions;
DROP INDEX IF EXISTS idx_audit_events_enterprise_chain;
ALTER TABLE org_memberships DROP CONSTRAINT IF EXISTS fk_org_memberships_enterprise_unit;
ALTER TABLE org_memberships DROP CONSTRAINT IF EXISTS fk_org_memberships_enterprise_user;
ALTER TABLE org_units DROP CONSTRAINT IF EXISTS uq_org_units_enterprise_id_id;
ALTER TABLE enterprise_users DROP CONSTRAINT IF EXISTS uq_enterprise_users_enterprise_id_id;
-- +goose StatementEnd
