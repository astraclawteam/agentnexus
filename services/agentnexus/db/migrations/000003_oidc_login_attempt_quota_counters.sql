-- +goose Up
-- +goose StatementBegin
LOCK TABLE oidc_login_attempts IN ACCESS EXCLUSIVE MODE;

UPDATE oidc_login_attempts
SET created_at = date_trunc('second', created_at),
    expires_at = date_trunc('second', expires_at);

ALTER TABLE oidc_login_attempts
    ADD CONSTRAINT ck_oidc_login_attempts_second_aligned
    CHECK (created_at = date_trunc('second', created_at) AND expires_at = date_trunc('second', expires_at));

CREATE TABLE oidc_login_attempt_scope_counters (
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    client_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at = date_trunc('second', expires_at)),
    active_count BIGINT NOT NULL CHECK (active_count >= 0),
    PRIMARY KEY (enterprise_id, client_id, expires_at)
);

CREATE TABLE oidc_login_attempt_browser_counters (
    enterprise_id TEXT NOT NULL REFERENCES enterprises(id),
    client_id TEXT NOT NULL,
    browser_id_hash TEXT NOT NULL CHECK (char_length(browser_id_hash) = 64 AND browser_id_hash ~ '^[0-9a-f]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at = date_trunc('second', expires_at)),
    active_count BIGINT NOT NULL CHECK (active_count >= 0),
    PRIMARY KEY (enterprise_id, client_id, browser_id_hash, expires_at)
);

INSERT INTO oidc_login_attempt_scope_counters (
    enterprise_id, client_id, expires_at, active_count
)
SELECT enterprise_id, client_id, expires_at, COUNT(*)::BIGINT
FROM oidc_login_attempts
GROUP BY enterprise_id, client_id, expires_at;

INSERT INTO oidc_login_attempt_browser_counters (
    enterprise_id, client_id, browser_id_hash, expires_at, active_count
)
SELECT enterprise_id, client_id, browser_id_hash, expires_at, COUNT(*)::BIGINT
FROM oidc_login_attempts
GROUP BY enterprise_id, client_id, browser_id_hash, expires_at;

CREATE INDEX idx_oidc_login_attempts_scope_expiry
    ON oidc_login_attempts(enterprise_id, client_id, expires_at);
CREATE INDEX idx_oidc_login_attempt_browser_counters_scope_expiry
    ON oidc_login_attempt_browser_counters(enterprise_id, client_id, expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_oidc_login_attempt_browser_counters_scope_expiry;
DROP INDEX IF EXISTS idx_oidc_login_attempts_scope_expiry;
DROP TABLE IF EXISTS oidc_login_attempt_browser_counters;
DROP TABLE IF EXISTS oidc_login_attempt_scope_counters;
ALTER TABLE oidc_login_attempts
    DROP CONSTRAINT IF EXISTS ck_oidc_login_attempts_second_aligned;
-- +goose StatementEnd
