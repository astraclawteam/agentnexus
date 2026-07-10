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
		Nonce: code.Nonce, CreatedAt: timestamp(code.CreatedAt), ExpiresAt: timestamp(code.ExpiresAt),
	})
	return err
}

func (s *PostgresStore) CreateLoginAttempt(ctx context.Context, attempt storedLoginAttempt) error {
	if s == nil || s.pool == nil {
		return errStoreUnavailable
	}
	_, err := db.New(s.pool).CreateOIDCLoginAttempt(ctx, db.CreateOIDCLoginAttemptParams{
		StateHash: attempt.StateHash, BindingHash: attempt.BindingHash, EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID,
		RedirectUri: attempt.RedirectURI, ConsoleState: attempt.ConsoleState, ConsoleNonce: attempt.ConsoleNonce,
		CodeChallenge: attempt.CodeChallenge, UpstreamNonce: attempt.UpstreamNonce,
		CreatedAt: timestamp(attempt.CreatedAt), ExpiresAt: timestamp(attempt.ExpiresAt),
	})
	return err
}

func (s *PostgresStore) ConsumeLoginAttempt(ctx context.Context, stateHash, bindingHash string, now time.Time) (storedLoginAttempt, error) {
	if s == nil || s.pool == nil {
		return storedLoginAttempt{}, errStoreUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return storedLoginAttempt{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := db.New(tx)
	record, err := queries.GetOIDCLoginAttemptForUpdate(ctx, stateHash)
	if err != nil {
		return storedLoginAttempt{}, mapPostgresNotFound(err)
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
	return storedLoginAttempt{StateHash: record.StateHash, BindingHash: record.BindingHash, LoginAttempt: LoginAttempt{
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
	if err := tx.Commit(ctx); err != nil {
		return storedAuthorizationCode{}, err
	}
	return storedCodeFromDB(record, request.Now), nil
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
	return storedAuthorizationCode{CodeHash: record.CodeHash, EnterpriseID: record.EnterpriseID, UserID: record.EnterpriseUserID, ClientID: record.ClientID, RedirectURI: record.RedirectUri, Nonce: record.Nonce, CodeChallenge: record.CodeChallenge, CreatedAt: record.CreatedAt.Time, ExpiresAt: record.ExpiresAt.Time, ConsumedAt: &consumedAt}
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
