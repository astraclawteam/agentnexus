-- +goose Up
-- +goose StatementBegin
ALTER TABLE enterprise_users
    ADD CONSTRAINT uq_enterprise_users_enterprise_id_id UNIQUE (enterprise_id, id);

ALTER TABLE org_units
    ADD CONSTRAINT uq_org_units_enterprise_id_id UNIQUE (enterprise_id, id);

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
CREATE INDEX idx_approval_queue_items_enterprise_status ON approval_queue_items(enterprise_id, status, created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS approval_queue_items;
DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS browser_sessions;
ALTER TABLE org_units DROP CONSTRAINT IF EXISTS uq_org_units_enterprise_id_id;
ALTER TABLE enterprise_users DROP CONSTRAINT IF EXISTS uq_enterprise_users_enterprise_id_id;
-- +goose StatementEnd
