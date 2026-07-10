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
    code_challenge, nonce, created_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING code_hash, client_id, redirect_uri, enterprise_id, enterprise_user_id,
          code_challenge, nonce, created_at, expires_at, consumed_at;

-- name: GetAuthorizationCodeForUpdate :one
SELECT code_hash, client_id, redirect_uri, enterprise_id, enterprise_user_id,
       code_challenge, nonce, created_at, expires_at, consumed_at
FROM oauth_authorization_codes
WHERE code_hash = $1
FOR UPDATE;

-- name: ConsumeAuthorizationCode :execrows
UPDATE oauth_authorization_codes
SET consumed_at = $2
WHERE code_hash = $1 AND consumed_at IS NULL;

-- name: LockOIDCLoginAttemptScope :one
SELECT pg_advisory_xact_lock(
    hashtext(sqlc.arg(enterprise_id)),
    hashtext(sqlc.arg(client_id))
);

-- name: DeleteExpiredOIDCLoginAttempts :exec
DELETE FROM oidc_login_attempts WHERE expires_at <= $1;

-- name: CountOIDCLoginAttemptsGlobal :one
SELECT COUNT(*)
FROM oidc_login_attempts
WHERE enterprise_id = $1 AND client_id = $2 AND expires_at > $3;

-- name: CountOIDCLoginAttemptsForBrowser :one
SELECT COUNT(*)
FROM oidc_login_attempts
WHERE enterprise_id = $1 AND client_id = $2 AND browser_id_hash = $3 AND expires_at > $4;

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

-- name: DeleteOIDCLoginAttempt :execrows
DELETE FROM oidc_login_attempts WHERE state_hash = $1;

-- name: ResolveExternalIdentity :one
SELECT enterprise_id, enterprise_user_id
FROM external_identities
WHERE enterprise_id = $1 AND provider = $2 AND external_subject = $3;

-- name: GetBrowserProfile :one
SELECT u.display_name,
       COALESCE((SELECT MAX(v.version_number) FROM org_versions AS v WHERE v.enterprise_id = u.enterprise_id), 0)::BIGINT AS org_version
FROM enterprise_users AS u
WHERE u.enterprise_id = $1 AND u.id = $2;

-- name: ListBrowserProfileOrgUnits :many
SELECT m.org_unit_id
FROM org_memberships AS m
JOIN org_units AS u ON u.enterprise_id = m.enterprise_id AND u.id = m.org_unit_id
WHERE m.enterprise_id = $1 AND m.enterprise_user_id = $2
ORDER BY m.org_unit_id;
