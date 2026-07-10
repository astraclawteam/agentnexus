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

-- name: CreateOIDCLoginAttempt :one
INSERT INTO oidc_login_attempts (
    state_hash, enterprise_id, client_id, redirect_uri, console_state, console_nonce,
    code_challenge, upstream_nonce, created_at, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING state_hash, enterprise_id, client_id, redirect_uri, console_state, console_nonce,
          code_challenge, upstream_nonce, created_at, expires_at;

-- name: ConsumeOIDCLoginAttempt :one
DELETE FROM oidc_login_attempts
WHERE state_hash = $1 AND expires_at > $2
RETURNING state_hash, enterprise_id, client_id, redirect_uri, console_state, console_nonce,
          code_challenge, upstream_nonce, created_at, expires_at;

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
SELECT org_unit_id
FROM org_memberships
WHERE enterprise_id = $1 AND enterprise_user_id = $2
ORDER BY org_unit_id;
