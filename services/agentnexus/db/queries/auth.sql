-- name: EnterpriseUserBindingExists :one
SELECT EXISTS (
    SELECT 1 FROM enterprise_users
    WHERE enterprise_id = $1 AND id = $2
);

-- name: CreateBrowserSession :one
INSERT INTO browser_sessions (
    id_hash, enterprise_id, enterprise_user_id, created_at, last_seen_at,
    idle_expires_at, absolute_expires_at, user_agent_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id_hash, enterprise_id, enterprise_user_id, created_at, last_seen_at,
          idle_expires_at, absolute_expires_at, revoked_at, user_agent_hash;

-- name: GetBrowserSessionForUpdate :one
SELECT id_hash, enterprise_id, enterprise_user_id, created_at, last_seen_at,
       idle_expires_at, absolute_expires_at, revoked_at, user_agent_hash
FROM browser_sessions
WHERE id_hash = $1
FOR UPDATE;

-- name: SlideBrowserSession :one
UPDATE browser_sessions
SET last_seen_at = $2, idle_expires_at = $3
WHERE id_hash = $1 AND revoked_at IS NULL
RETURNING id_hash, enterprise_id, enterprise_user_id, created_at, last_seen_at,
          idle_expires_at, absolute_expires_at, revoked_at, user_agent_hash;

-- name: RevokeBrowserSession :execrows
UPDATE browser_sessions
SET revoked_at = COALESCE(revoked_at, $2)
WHERE id_hash = $1;

-- name: RevokeAndGetBrowserSession :one
UPDATE browser_sessions
SET revoked_at = $2
WHERE id_hash = $1 AND revoked_at IS NULL
  AND idle_expires_at > $2 AND absolute_expires_at > $2
RETURNING id_hash, enterprise_id, enterprise_user_id, created_at, last_seen_at,
          idle_expires_at, absolute_expires_at, revoked_at, user_agent_hash;

-- name: CreateAuthorizationCode :one
INSERT INTO oauth_authorization_codes (
    code_hash, client_id, redirect_uri, enterprise_id, enterprise_user_id,
    code_challenge, nonce, created_at, expires_at, browser_session_id_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING code_hash, client_id, redirect_uri, enterprise_id, enterprise_user_id,
          code_challenge, nonce, created_at, expires_at, consumed_at, browser_session_id_hash;

-- name: GetAuthorizationCodeForUpdate :one
SELECT code_hash, client_id, redirect_uri, enterprise_id, enterprise_user_id,
       code_challenge, nonce, created_at, expires_at, consumed_at, browser_session_id_hash
FROM oauth_authorization_codes
WHERE code_hash = $1
FOR UPDATE;

-- name: ConsumeAuthorizationCode :execrows
UPDATE oauth_authorization_codes
SET consumed_at = $2
WHERE code_hash = $1 AND consumed_at IS NULL;

-- name: CreateBrowserAccessToken :one
INSERT INTO browser_access_tokens (
    token_hash, browser_session_id_hash, enterprise_id, enterprise_user_id,
    client_id, audience, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING token_hash, browser_session_id_hash, enterprise_id, enterprise_user_id,
          client_id, audience, created_at, expires_at, revoked_at;

-- name: GetActiveBrowserAccessToken :one
SELECT t.token_hash, t.browser_session_id_hash, t.enterprise_id, t.enterprise_user_id,
       t.client_id, t.audience, t.created_at, t.expires_at, t.revoked_at,
       s.created_at AS session_created_at, s.last_seen_at AS session_last_seen_at,
       s.idle_expires_at AS session_idle_expires_at, s.absolute_expires_at AS session_absolute_expires_at
FROM browser_access_tokens AS t
JOIN browser_sessions AS s ON s.id_hash = t.browser_session_id_hash
WHERE t.token_hash = sqlc.arg(token_hash)
  AND t.client_id = sqlc.arg(client_id)
  AND t.audience = sqlc.arg(audience)
  AND t.revoked_at IS NULL
  AND s.revoked_at IS NULL
  AND t.expires_at > sqlc.arg(now)
  AND s.idle_expires_at > sqlc.arg(now)
  AND s.absolute_expires_at > sqlc.arg(now);

-- name: RevokeAndGetBrowserSessionByAccessToken :one
UPDATE browser_sessions AS s
SET revoked_at = COALESCE(s.revoked_at, sqlc.arg(revoked_at))
FROM browser_access_tokens AS t
WHERE t.token_hash = sqlc.arg(token_hash)
  AND t.browser_session_id_hash = s.id_hash
  AND t.client_id = sqlc.arg(client_id)
  AND t.audience = sqlc.arg(audience)
  AND t.revoked_at IS NULL
  AND t.expires_at > sqlc.arg(revoked_at)
  AND (s.revoked_at IS NOT NULL OR (
      s.idle_expires_at > sqlc.arg(revoked_at)
      AND s.absolute_expires_at > sqlc.arg(revoked_at)
  ))
RETURNING s.id_hash, s.enterprise_id, s.enterprise_user_id, s.created_at, s.last_seen_at,
          s.idle_expires_at, s.absolute_expires_at, s.revoked_at, s.user_agent_hash;

-- name: LockOIDCLoginAttemptScope :one
SELECT pg_advisory_xact_lock(
    hashtext(sqlc.arg(enterprise_id)),
    hashtext(sqlc.arg(client_id))
);

-- name: DeleteExpiredOIDCLoginAttemptsBatch :execrows
WITH expired AS (
    SELECT state_hash
    FROM oidc_login_attempts AS candidates
    WHERE candidates.enterprise_id = sqlc.arg(enterprise_id)
      AND candidates.client_id = sqlc.arg(client_id)
      AND candidates.expires_at <= sqlc.arg(now)
    ORDER BY candidates.expires_at
    LIMIT 256
)
DELETE FROM oidc_login_attempts AS attempts
USING expired
WHERE attempts.state_hash = expired.state_hash;

-- name: DeleteExpiredOIDCLoginAttemptScopeCountersBatch :execrows
WITH expired AS (
    SELECT enterprise_id, client_id, expires_at
    FROM oidc_login_attempt_scope_counters AS candidates
    WHERE candidates.enterprise_id = sqlc.arg(enterprise_id)
      AND candidates.client_id = sqlc.arg(client_id)
      AND candidates.expires_at <= sqlc.arg(now)
    ORDER BY candidates.expires_at
    LIMIT 256
)
DELETE FROM oidc_login_attempt_scope_counters AS counters
USING expired
WHERE counters.enterprise_id = expired.enterprise_id
  AND counters.client_id = expired.client_id
  AND counters.expires_at = expired.expires_at;

-- name: DeleteExpiredOIDCLoginAttemptBrowserCountersBatch :execrows
WITH expired AS (
    SELECT enterprise_id, client_id, browser_id_hash, expires_at
    FROM oidc_login_attempt_browser_counters AS candidates
    WHERE candidates.enterprise_id = sqlc.arg(enterprise_id)
      AND candidates.client_id = sqlc.arg(client_id)
      AND candidates.expires_at <= sqlc.arg(now)
    ORDER BY candidates.expires_at
    LIMIT 256
)
DELETE FROM oidc_login_attempt_browser_counters AS counters
USING expired
WHERE counters.enterprise_id = expired.enterprise_id
  AND counters.client_id = expired.client_id
  AND counters.browser_id_hash = expired.browser_id_hash
  AND counters.expires_at = expired.expires_at;

-- name: SumActiveOIDCLoginAttemptScope :one
SELECT COALESCE(SUM(active_count), 0)::BIGINT
FROM oidc_login_attempt_scope_counters
WHERE enterprise_id = sqlc.arg(enterprise_id)
  AND client_id = sqlc.arg(client_id)
  AND expires_at > sqlc.arg(now);

-- name: SumActiveOIDCLoginAttemptBrowser :one
SELECT COALESCE(SUM(active_count), 0)::BIGINT
FROM oidc_login_attempt_browser_counters
WHERE enterprise_id = sqlc.arg(enterprise_id)
  AND client_id = sqlc.arg(client_id)
  AND browser_id_hash = sqlc.arg(browser_id_hash)
  AND expires_at > sqlc.arg(now);

-- name: IncrementOIDCLoginAttemptScopeCounter :exec
INSERT INTO oidc_login_attempt_scope_counters (
    enterprise_id, client_id, expires_at, active_count
) VALUES (
    sqlc.arg(enterprise_id), sqlc.arg(client_id), sqlc.arg(expires_at), 1
)
ON CONFLICT (enterprise_id, client_id, expires_at)
DO UPDATE SET active_count = oidc_login_attempt_scope_counters.active_count + 1;

-- name: IncrementOIDCLoginAttemptBrowserCounter :exec
INSERT INTO oidc_login_attempt_browser_counters (
    enterprise_id, client_id, browser_id_hash, expires_at, active_count
) VALUES (
    sqlc.arg(enterprise_id), sqlc.arg(client_id), sqlc.arg(browser_id_hash), sqlc.arg(expires_at), 1
)
ON CONFLICT (enterprise_id, client_id, browser_id_hash, expires_at)
DO UPDATE SET active_count = oidc_login_attempt_browser_counters.active_count + 1;

-- name: DecrementOIDCLoginAttemptScopeCounter :execrows
UPDATE oidc_login_attempt_scope_counters
SET active_count = active_count - 1
WHERE enterprise_id = sqlc.arg(enterprise_id)
  AND client_id = sqlc.arg(client_id)
  AND expires_at = sqlc.arg(expires_at)
  AND active_count > 0;

-- name: DecrementOIDCLoginAttemptBrowserCounter :execrows
UPDATE oidc_login_attempt_browser_counters
SET active_count = active_count - 1
WHERE enterprise_id = sqlc.arg(enterprise_id)
  AND client_id = sqlc.arg(client_id)
  AND browser_id_hash = sqlc.arg(browser_id_hash)
  AND expires_at = sqlc.arg(expires_at)
  AND active_count > 0;

-- name: CreateOIDCLoginAttempt :one
INSERT INTO oidc_login_attempts (
    state_hash, binding_hash, browser_id_hash, enterprise_id, client_id, redirect_uri, console_state, console_nonce,
    code_challenge, upstream_nonce, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING state_hash, binding_hash, browser_id_hash, enterprise_id, client_id, redirect_uri, console_state, console_nonce,
          code_challenge, upstream_nonce, created_at, expires_at;

-- name: GetOIDCLoginAttemptForUpdate :one
SELECT state_hash, binding_hash, browser_id_hash, enterprise_id, client_id, redirect_uri, console_state, console_nonce,
       code_challenge, upstream_nonce, created_at, expires_at
FROM oidc_login_attempts
WHERE state_hash = $1
FOR UPDATE;

-- name: GetOIDCLoginAttemptScope :one
SELECT enterprise_id, client_id
FROM oidc_login_attempts
WHERE state_hash = $1;

-- name: DeleteOIDCLoginAttempt :execrows
DELETE FROM oidc_login_attempts WHERE state_hash = $1;

-- name: DeleteExpiredOIDCAuthorizeRateLimits :exec
WITH expired AS (
    SELECT enterprise_id, client_id, source_hash, window_start
    FROM oidc_authorize_rate_limits AS candidates
    WHERE candidates.window_start < $1
    ORDER BY candidates.window_start
    LIMIT 256
)
DELETE FROM oidc_authorize_rate_limits AS limits
USING expired
WHERE limits.enterprise_id = expired.enterprise_id
  AND limits.client_id = expired.client_id
  AND limits.source_hash = expired.source_hash
  AND limits.window_start = expired.window_start;

-- name: ConsumeOIDCAuthorizeRateLimit :one
INSERT INTO oidc_authorize_rate_limits (
    enterprise_id, client_id, source_hash, window_start, request_count
) VALUES (
    sqlc.arg(enterprise_id), sqlc.arg(client_id), sqlc.arg(source_hash), sqlc.arg(window_start), 1
)
ON CONFLICT (enterprise_id, client_id, source_hash, window_start)
DO UPDATE SET request_count = oidc_authorize_rate_limits.request_count + 1
WHERE oidc_authorize_rate_limits.request_count < sqlc.arg(request_limit)
RETURNING request_count;

-- name: ResolveExternalIdentity :one
SELECT enterprise_id, enterprise_user_id
FROM external_identities
WHERE enterprise_id = $1 AND provider = $2 AND external_subject = $3;

-- name: GetBrowserProfile :one
SELECT u.display_name, published.version_number AS org_version
FROM enterprise_users AS u
JOIN LATERAL (
    SELECT v.version_number
    FROM org_versions AS v
    WHERE v.enterprise_id = u.enterprise_id
      AND v.policy_snapshot_sealed = true
    ORDER BY v.version_number DESC
    LIMIT 1
) AS published ON true
WHERE u.enterprise_id = $1 AND u.id = $2;

-- name: ListBrowserProfileOrgUnits :many
SELECT m.enterprise_id, m.version_number, m.enterprise_user_id, m.org_unit_id, m.role
FROM org_policy_snapshot_memberships AS m
JOIN org_versions AS v
  ON v.enterprise_id = m.enterprise_id
 AND v.version_number = m.version_number
 AND v.policy_snapshot_sealed = true
WHERE m.enterprise_id = $1
  AND m.enterprise_user_id = $2
  AND m.version_number = $3
ORDER BY m.org_unit_id
LIMIT 100001;
