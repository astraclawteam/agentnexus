package browserauth

import (
	"context"
	"errors"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
)

type PostgresAuthorizeRateLimiter struct {
	database db.DBTX
	limit    int
	now      func() time.Time
}

func NewPostgresAuthorizeRateLimiter(database db.DBTX, limit int, now func() time.Time) (*PostgresAuthorizeRateLimiter, error) {
	if !ValidAuthorizeRateLimitPerMinute(limit) || now == nil {
		return nil, ErrInvalidInput
	}
	return &PostgresAuthorizeRateLimiter{database: database, limit: limit, now: now}, nil
}

func (l *PostgresAuthorizeRateLimiter) AllowAuthorize(ctx context.Context, enterpriseID, clientID, sourceHash string) (time.Duration, error) {
	if enterpriseID == "" || clientID == "" || !canonicalSHA256Hex(sourceHash) {
		return 0, ErrInvalidInput
	}
	if l == nil || l.database == nil || ctx.Err() != nil {
		return 0, ErrAuthorizeRateUnavailable
	}
	now := l.now().UTC()
	windowStart := now.Truncate(time.Minute)
	retryAfter := windowStart.Add(time.Minute).Sub(now)
	queries := db.New(l.database)
	if err := queries.DeleteExpiredOIDCAuthorizeRateLimits(ctx, timestamp(windowStart)); err != nil {
		return 0, ErrAuthorizeRateUnavailable
	}
	_, err := queries.ConsumeOIDCAuthorizeRateLimit(ctx, db.ConsumeOIDCAuthorizeRateLimitParams{
		EnterpriseID: enterpriseID,
		ClientID:     clientID,
		SourceHash:   sourceHash,
		WindowStart:  timestamp(windowStart),
		RequestLimit: int32(l.limit),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return retryAfter, ErrAuthorizeRateLimited
	}
	if err != nil {
		return 0, ErrAuthorizeRateUnavailable
	}
	return 0, nil
}

var _ AuthorizeRateLimiter = (*PostgresAuthorizeRateLimiter)(nil)
