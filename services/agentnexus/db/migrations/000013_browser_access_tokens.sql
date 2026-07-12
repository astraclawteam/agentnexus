-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth_authorization_codes
    ADD COLUMN browser_session_id_hash TEXT REFERENCES browser_sessions(id_hash);
DELETE FROM oauth_authorization_codes;
ALTER TABLE oauth_authorization_codes
    ALTER COLUMN browser_session_id_hash SET NOT NULL;

CREATE TABLE browser_access_tokens (
    token_hash TEXT PRIMARY KEY CHECK (char_length(token_hash) = 64 AND token_hash ~ '^[0-9a-f]{64}$'),
    browser_session_id_hash TEXT NOT NULL REFERENCES browser_sessions(id_hash) ON DELETE CASCADE,
    enterprise_id TEXT NOT NULL,
    enterprise_user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at),
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (enterprise_id, enterprise_user_id)
        REFERENCES enterprise_users(enterprise_id, id)
);

CREATE INDEX idx_browser_access_tokens_session
    ON browser_access_tokens(browser_session_id_hash);
CREATE INDEX idx_browser_access_tokens_expiry
    ON browser_access_tokens(expires_at) WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS browser_access_tokens;
ALTER TABLE oauth_authorization_codes DROP COLUMN IF EXISTS browser_session_id_hash;
-- +goose StatementEnd
