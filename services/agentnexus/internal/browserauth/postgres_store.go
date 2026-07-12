package browserauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) EnterpriseUserBindingExists(ctx context.Context, enterpriseID, userID string) (bool, error) {
	if s == nil || s.pool == nil {
		return false, errStoreUnavailable
	}
	return db.New(s.pool).EnterpriseUserBindingExists(ctx, db.EnterpriseUserBindingExistsParams{EnterpriseID: enterpriseID, ID: userID})
}

func (s *PostgresStore) CreateSession(ctx context.Context, session storedSession) error {
	if s == nil || s.pool == nil {
		return errStoreUnavailable
	}
	_, err := db.New(s.pool).CreateBrowserSession(ctx, db.CreateBrowserSessionParams{
		IDHash: session.IDHash, EnterpriseID: session.EnterpriseID, EnterpriseUserID: session.UserID,
		CreatedAt: timestamp(session.CreatedAt), LastSeenAt: timestamp(session.LastSeenAt),
		IdleExpiresAt: timestamp(session.IdleExpiresAt), AbsoluteExpiresAt: timestamp(session.AbsoluteExpiresAt),
		UserAgentHash: session.UserAgentHash,
	})
	return err
}

func (s *PostgresStore) UseSession(ctx context.Context, idHash string, now time.Time, idleTimeout time.Duration) (storedSession, error) {
	if s == nil || s.pool == nil {
		return storedSession{}, errStoreUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return storedSession{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := db.New(tx)
	record, err := queries.GetBrowserSessionForUpdate(ctx, idHash)
	if err != nil {
		return storedSession{}, mapPostgresNotFound(err)
	}
	if record.RevokedAt.Valid || !now.Before(record.IdleExpiresAt.Time) || !now.Before(record.AbsoluteExpiresAt.Time) {
		return storedSession{}, errNotFound
	}
	updated, err := queries.SlideBrowserSession(ctx, db.SlideBrowserSessionParams{IDHash: idHash, LastSeenAt: timestamp(now), IdleExpiresAt: timestamp(minTime(now.Add(idleTimeout), record.AbsoluteExpiresAt.Time))})
	if err != nil {
		return storedSession{}, mapPostgresNotFound(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return storedSession{}, err
	}
	return storedSessionFromDB(updated), nil
}

func (s *PostgresStore) RevokeSession(ctx context.Context, idHash string, now time.Time) error {
	if s == nil || s.pool == nil {
		return errStoreUnavailable
	}
	rows, err := db.New(s.pool).RevokeBrowserSession(ctx, db.RevokeBrowserSessionParams{IDHash: idHash, RevokedAt: timestamp(now)})
	if err != nil {
		return err
	}
	if rows != 1 {
		return errNotFound
	}
	return nil
}

func (s *PostgresStore) RevokeAndGetSession(ctx context.Context, idHash string, now time.Time) (storedSession, error) {
	if s == nil || s.pool == nil {
		return storedSession{}, errStoreUnavailable
	}
	record, err := db.New(s.pool).RevokeAndGetBrowserSession(ctx, db.RevokeAndGetBrowserSessionParams{IDHash: idHash, RevokedAt: timestamp(now)})
	if err != nil {
		return storedSession{}, mapPostgresNotFound(err)
	}
	return storedSessionFromDB(record), nil
}

func (s *PostgresStore) CreateAuthorizationCode(ctx context.Context, code storedAuthorizationCode) error {
	if s == nil || s.pool == nil {
		return errStoreUnavailable
	}
	_, err := db.New(s.pool).CreateAuthorizationCode(ctx, db.CreateAuthorizationCodeParams{
		CodeHash: code.CodeHash, ClientID: code.ClientID, RedirectUri: code.RedirectURI,
		EnterpriseID: code.EnterpriseID, EnterpriseUserID: code.UserID, CodeChallenge: code.CodeChallenge,
		Nonce: code.Nonce, CreatedAt: timestamp(code.CreatedAt), ExpiresAt: timestamp(code.ExpiresAt), BrowserSessionIDHash: code.BrowserSessionIDHash,
	})
	return err
}

func (s *PostgresStore) CreateLoginAttempt(ctx context.Context, attempt storedLoginAttempt, limits LoginAttemptLimits) error {
	if s == nil || s.pool == nil {
		return errStoreUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := db.New(tx)
	if _, err := queries.LockOIDCLoginAttemptScope(ctx, db.LockOIDCLoginAttemptScopeParams{EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID}); err != nil {
		return err
	}
	cleanup := db.DeleteExpiredOIDCLoginAttemptsBatchParams{EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID, Now: timestamp(attempt.CreatedAt)}
	if _, err := queries.DeleteExpiredOIDCLoginAttemptsBatch(ctx, cleanup); err != nil {
		return err
	}
	if _, err := queries.DeleteExpiredOIDCLoginAttemptScopeCountersBatch(ctx, db.DeleteExpiredOIDCLoginAttemptScopeCountersBatchParams(cleanup)); err != nil {
		return err
	}
	if _, err := queries.DeleteExpiredOIDCLoginAttemptBrowserCountersBatch(ctx, db.DeleteExpiredOIDCLoginAttemptBrowserCountersBatchParams(cleanup)); err != nil {
		return err
	}
	globalCount, err := queries.SumActiveOIDCLoginAttemptScope(ctx, db.SumActiveOIDCLoginAttemptScopeParams{EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID, Now: timestamp(attempt.CreatedAt)})
	if err != nil {
		return err
	}
	if globalCount >= int64(limits.Global) {
		return errLoginAttemptLimited
	}
	browserCount, err := queries.SumActiveOIDCLoginAttemptBrowser(ctx, db.SumActiveOIDCLoginAttemptBrowserParams{EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID, BrowserIDHash: attempt.BrowserIDHash, Now: timestamp(attempt.CreatedAt)})
	if err != nil {
		return err
	}
	if browserCount >= int64(limits.PerBrowser) {
		return errLoginAttemptLimited
	}
	if err := queries.IncrementOIDCLoginAttemptScopeCounter(ctx, db.IncrementOIDCLoginAttemptScopeCounterParams{EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID, ExpiresAt: timestamp(attempt.ExpiresAt)}); err != nil {
		return err
	}
	if err := queries.IncrementOIDCLoginAttemptBrowserCounter(ctx, db.IncrementOIDCLoginAttemptBrowserCounterParams{EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID, BrowserIDHash: attempt.BrowserIDHash, ExpiresAt: timestamp(attempt.ExpiresAt)}); err != nil {
		return err
	}
	if _, err := queries.CreateOIDCLoginAttempt(ctx, db.CreateOIDCLoginAttemptParams{
		StateHash: attempt.StateHash, BindingHash: attempt.BindingHash, BrowserIDHash: attempt.BrowserIDHash, EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID,
		RedirectUri: attempt.RedirectURI, ConsoleState: attempt.ConsoleState, ConsoleNonce: attempt.ConsoleNonce,
		CodeChallenge: attempt.CodeChallenge, UpstreamNonce: attempt.UpstreamNonce,
		CreatedAt: timestamp(attempt.CreatedAt), ExpiresAt: timestamp(attempt.ExpiresAt),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ConsumeLoginAttempt(ctx context.Context, stateHash, bindingHash string, now time.Time) (storedLoginAttempt, error) {
	if s == nil || s.pool == nil {
		return storedLoginAttempt{}, errStoreUnavailable
	}
	scope, err := db.New(s.pool).GetOIDCLoginAttemptScope(ctx, stateHash)
	if err != nil {
		return storedLoginAttempt{}, mapPostgresNotFound(err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return storedLoginAttempt{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := db.New(tx)
	if _, err := queries.LockOIDCLoginAttemptScope(ctx, db.LockOIDCLoginAttemptScopeParams{EnterpriseID: scope.EnterpriseID, ClientID: scope.ClientID}); err != nil {
		return storedLoginAttempt{}, err
	}
	record, err := queries.GetOIDCLoginAttemptForUpdate(ctx, stateHash)
	if err != nil {
		return storedLoginAttempt{}, mapPostgresNotFound(err)
	}
	if record.EnterpriseID != scope.EnterpriseID || record.ClientID != scope.ClientID {
		return storedLoginAttempt{}, errStoreInvariant
	}
	if !now.Before(record.ExpiresAt.Time) {
		if _, err := queries.DeleteOIDCLoginAttempt(ctx, stateHash); err != nil {
			return storedLoginAttempt{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return storedLoginAttempt{}, err
		}
		return storedLoginAttempt{}, errNotFound
	}
	if len(record.BindingHash) != len(bindingHash) || subtle.ConstantTimeCompare([]byte(record.BindingHash), []byte(bindingHash)) != 1 {
		return storedLoginAttempt{}, errNotFound
	}
	scopeRows, err := queries.DecrementOIDCLoginAttemptScopeCounter(ctx, db.DecrementOIDCLoginAttemptScopeCounterParams{EnterpriseID: record.EnterpriseID, ClientID: record.ClientID, ExpiresAt: record.ExpiresAt})
	if err != nil {
		return storedLoginAttempt{}, err
	}
	if scopeRows != 1 {
		return storedLoginAttempt{}, errStoreInvariant
	}
	browserRows, err := queries.DecrementOIDCLoginAttemptBrowserCounter(ctx, db.DecrementOIDCLoginAttemptBrowserCounterParams{EnterpriseID: record.EnterpriseID, ClientID: record.ClientID, BrowserIDHash: record.BrowserIDHash, ExpiresAt: record.ExpiresAt})
	if err != nil {
		return storedLoginAttempt{}, err
	}
	if browserRows != 1 {
		return storedLoginAttempt{}, errStoreInvariant
	}
	rows, err := queries.DeleteOIDCLoginAttempt(ctx, stateHash)
	if err != nil {
		return storedLoginAttempt{}, err
	}
	if rows != 1 {
		return storedLoginAttempt{}, errNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return storedLoginAttempt{}, err
	}
	return storedLoginAttempt{StateHash: record.StateHash, BindingHash: record.BindingHash, BrowserIDHash: record.BrowserIDHash, LoginAttempt: LoginAttempt{
		EnterpriseID: record.EnterpriseID, ClientID: record.ClientID, RedirectURI: record.RedirectUri,
		ConsoleState: record.ConsoleState, ConsoleNonce: record.ConsoleNonce, CodeChallenge: record.CodeChallenge,
		UpstreamNonce: record.UpstreamNonce, CreatedAt: record.CreatedAt.Time, ExpiresAt: record.ExpiresAt.Time,
	}}, nil
}

func (s *PostgresStore) ExchangeAuthorizationCode(ctx context.Context, request exchangeRequest) (storedAuthorizationCode, error) {
	if s == nil || s.pool == nil {
		return storedAuthorizationCode{}, errStoreUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return storedAuthorizationCode{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := db.New(tx)
	record, err := queries.GetAuthorizationCodeForUpdate(ctx, request.CodeHash)
	if err != nil {
		return storedAuthorizationCode{}, mapPostgresNotFound(err)
	}
	if record.ConsumedAt.Valid || !request.Now.Before(record.ExpiresAt.Time) || record.ClientID != request.ClientID || record.RedirectUri != request.RedirectURI {
		return storedAuthorizationCode{}, errNotFound
	}
	session, err := queries.GetBrowserSessionForUpdate(ctx, record.BrowserSessionIDHash)
	if err != nil {
		return storedAuthorizationCode{}, mapPostgresNotFound(err)
	}
	if session.RevokedAt.Valid || session.EnterpriseID != record.EnterpriseID || session.EnterpriseUserID != record.EnterpriseUserID || !request.Now.Before(session.IdleExpiresAt.Time) || !request.Now.Before(session.AbsoluteExpiresAt.Time) {
		return storedAuthorizationCode{}, errNotFound
	}
	accessExpiresAt := session.AbsoluteExpiresAt.Time
	if request.AccessTokenHash == "" || request.Audience == "" || !accessExpiresAt.After(request.Now) {
		return storedAuthorizationCode{}, errNotFound
	}
	challenge, err := base64.RawURLEncoding.DecodeString(record.CodeChallenge)
	if err != nil || len(challenge) != len(request.VerifierDigest) || subtle.ConstantTimeCompare(challenge, request.VerifierDigest[:]) != 1 {
		return storedAuthorizationCode{}, errNotFound
	}
	rows, err := queries.ConsumeAuthorizationCode(ctx, db.ConsumeAuthorizationCodeParams{CodeHash: request.CodeHash, ConsumedAt: timestamp(request.Now)})
	if err != nil {
		return storedAuthorizationCode{}, err
	}
	if rows != 1 {
		return storedAuthorizationCode{}, errNotFound
	}
	if _, err := queries.CreateBrowserAccessToken(ctx, db.CreateBrowserAccessTokenParams{TokenHash: request.AccessTokenHash, BrowserSessionIDHash: record.BrowserSessionIDHash, EnterpriseID: record.EnterpriseID, EnterpriseUserID: record.EnterpriseUserID, ClientID: record.ClientID, Audience: request.Audience, CreatedAt: timestamp(request.Now), ExpiresAt: timestamp(accessExpiresAt)}); err != nil {
		return storedAuthorizationCode{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return storedAuthorizationCode{}, err
	}
	result := storedCodeFromDB(record, request.Now)
	result.AccessTokenExpiresAt = accessExpiresAt
	return result, nil
}

func (s *PostgresStore) UseAccessToken(ctx context.Context, tokenHash, clientID, audience string, now time.Time) (storedAccessToken, error) {
	if s == nil || s.pool == nil {
		return storedAccessToken{}, errStoreUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return storedAccessToken{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := db.New(tx)
	record, err := queries.GetActiveBrowserAccessToken(ctx, db.GetActiveBrowserAccessTokenParams{TokenHash: tokenHash, ClientID: clientID, Audience: audience, Now: timestamp(now)})
	if err != nil {
		return storedAccessToken{}, mapPostgresNotFound(err)
	}
	session, err := queries.GetBrowserSessionForUpdate(ctx, record.BrowserSessionIDHash)
	if err != nil || session.RevokedAt.Valid || session.EnterpriseID != record.EnterpriseID || session.EnterpriseUserID != record.EnterpriseUserID || !now.Before(session.IdleExpiresAt.Time) || !now.Before(session.AbsoluteExpiresAt.Time) {
		return storedAccessToken{}, errNotFound
	}
	session, err = queries.SlideBrowserSession(ctx, db.SlideBrowserSessionParams{IDHash: session.IDHash, LastSeenAt: timestamp(now), IdleExpiresAt: timestamp(minTime(now.Add(defaultIdleTimeout), session.AbsoluteExpiresAt.Time))})
	if err != nil {
		return storedAccessToken{}, mapPostgresNotFound(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return storedAccessToken{}, err
	}
	result := storedAccessToken{TokenHash: record.TokenHash, BrowserSessionIDHash: record.BrowserSessionIDHash, EnterpriseID: record.EnterpriseID, UserID: record.EnterpriseUserID, ClientID: record.ClientID, Audience: record.Audience, CreatedAt: record.CreatedAt.Time, ExpiresAt: record.ExpiresAt.Time, SessionCreatedAt: session.CreatedAt.Time, SessionLastSeenAt: session.LastSeenAt.Time, SessionIdleExpiresAt: session.IdleExpiresAt.Time, SessionAbsoluteExpiresAt: session.AbsoluteExpiresAt.Time}
	if record.RevokedAt.Valid {
		value := record.RevokedAt.Time
		result.RevokedAt = &value
	}
	return result, nil
}

func (s *PostgresStore) RevokeSessionByAccessToken(ctx context.Context, tokenHash, clientID, audience string, now time.Time) (storedSession, error) {
	if s == nil || s.pool == nil {
		return storedSession{}, errStoreUnavailable
	}
	record, err := db.New(s.pool).RevokeAndGetBrowserSessionByAccessToken(ctx, db.RevokeAndGetBrowserSessionByAccessTokenParams{TokenHash: tokenHash, ClientID: clientID, Audience: audience, RevokedAt: timestamp(now)})
	if err != nil {
		return storedSession{}, mapPostgresNotFound(err)
	}
	return storedSessionFromDB(record), nil
}

func storedSessionFromDB(record db.BrowserSession) storedSession {
	result := storedSession{IDHash: record.IDHash, EnterpriseID: record.EnterpriseID, UserID: record.EnterpriseUserID, CreatedAt: record.CreatedAt.Time, LastSeenAt: record.LastSeenAt.Time, IdleExpiresAt: record.IdleExpiresAt.Time, AbsoluteExpiresAt: record.AbsoluteExpiresAt.Time, UserAgentHash: record.UserAgentHash}
	if record.RevokedAt.Valid {
		value := record.RevokedAt.Time
		result.RevokedAt = &value
	}
	return result
}

func storedCodeFromDB(record db.OauthAuthorizationCode, consumedAt time.Time) storedAuthorizationCode {
	return storedAuthorizationCode{CodeHash: record.CodeHash, EnterpriseID: record.EnterpriseID, UserID: record.EnterpriseUserID, ClientID: record.ClientID, RedirectURI: record.RedirectUri, Nonce: record.Nonce, CodeChallenge: record.CodeChallenge, CreatedAt: record.CreatedAt.Time, ExpiresAt: record.ExpiresAt.Time, ConsumedAt: &consumedAt, BrowserSessionIDHash: record.BrowserSessionIDHash}
}

func timestamp(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}
func mapPostgresNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errNotFound
	}
	return err
}
