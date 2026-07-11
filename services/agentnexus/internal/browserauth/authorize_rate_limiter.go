package browserauth

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const DefaultAuthorizeRateLimitPerMinute = 120
const MaxAuthorizeRateLimitPerMinute = 10000

var (
	ErrAuthorizeRateLimited     = errors.New("OIDC authorize source rate limit reached")
	ErrAuthorizeRateUnavailable = errors.New("OIDC authorize rate limiter unavailable")
)

type AuthorizeRateLimiter interface {
	AllowAuthorize(context.Context, string, string, string) (time.Duration, error)
}

type authorizeRateKey struct {
	enterpriseID string
	clientID     string
	sourceHash   string
	windowStart  int64
}

type MemoryAuthorizeRateLimiter struct {
	mu     sync.Mutex
	limit  int
	now    func() time.Time
	counts map[authorizeRateKey]int
}

func NewMemoryAuthorizeRateLimiter(limit int, now func() time.Time) (*MemoryAuthorizeRateLimiter, error) {
	if !ValidAuthorizeRateLimitPerMinute(limit) || now == nil {
		return nil, ErrInvalidInput
	}
	return &MemoryAuthorizeRateLimiter{limit: limit, now: now, counts: make(map[authorizeRateKey]int)}, nil
}

func ValidAuthorizeRateLimitPerMinute(limit int) bool {
	return limit >= 1 && limit <= MaxAuthorizeRateLimitPerMinute
}

func (l *MemoryAuthorizeRateLimiter) AllowAuthorize(ctx context.Context, enterpriseID, clientID, sourceHash string) (time.Duration, error) {
	if enterpriseID == "" || clientID == "" || !canonicalSHA256Hex(sourceHash) {
		return 0, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return 0, ErrAuthorizeRateUnavailable
	}
	now := l.now().UTC()
	windowStart := now.Truncate(time.Minute)
	resetAfter := windowStart.Add(time.Minute).Sub(now)
	key := authorizeRateKey{enterpriseID: enterpriseID, clientID: clientID, sourceHash: sourceHash, windowStart: windowStart.Unix()}
	l.mu.Lock()
	defer l.mu.Unlock()
	for existing := range l.counts {
		if existing.windowStart < windowStart.Unix() {
			delete(l.counts, existing)
		}
	}
	if l.counts[key] >= l.limit {
		return resetAfter, ErrAuthorizeRateLimited
	}
	l.counts[key]++
	return 0, nil
}

func canonicalSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
