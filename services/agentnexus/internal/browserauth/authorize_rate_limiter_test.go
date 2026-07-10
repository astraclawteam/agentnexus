package browserauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryAuthorizeRateLimiterIsAtomicAndScopedBySource(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 34, 45, 0, time.UTC)
	limiter, err := NewMemoryAuthorizeRateLimiter(7, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	sourceA := sourceHashFixture("192.0.2.1")
	var allowed atomic.Int32
	var limited atomic.Int32
	var unexpected atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := limiter.AllowAuthorize(context.Background(), "ent-1", "atlas", sourceA)
			switch {
			case err == nil:
				allowed.Add(1)
			case errors.Is(err, ErrAuthorizeRateLimited):
				limited.Add(1)
			default:
				unexpected.Store(err)
			}
		}()
	}
	wg.Wait()
	if err, _ := unexpected.Load().(error); err != nil {
		t.Fatal(err)
	}
	if allowed.Load() != 7 || limited.Load() != 57 {
		t.Fatalf("allowed=%d limited=%d", allowed.Load(), limited.Load())
	}
	if _, err := limiter.AllowAuthorize(context.Background(), "ent-1", "atlas", sourceHashFixture("192.0.2.2")); err != nil {
		t.Fatalf("independent source rejected: %v", err)
	}
}

func TestMemoryAuthorizeRateLimiterReturnsExactResetAndReopensNextUTCMinute(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 34, 45, 0, time.FixedZone("offset", 8*60*60))
	limiter, err := NewMemoryAuthorizeRateLimiter(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	source := sourceHashFixture("2001:db8::1")
	if _, err := limiter.AllowAuthorize(context.Background(), "ent-1", "atlas", source); err != nil {
		t.Fatal(err)
	}
	retryAfter, err := limiter.AllowAuthorize(context.Background(), "ent-1", "atlas", source)
	if !errors.Is(err, ErrAuthorizeRateLimited) || retryAfter != 15*time.Second {
		t.Fatalf("retry=%s err=%v", retryAfter, err)
	}
	now = now.Add(15 * time.Second)
	if _, err := limiter.AllowAuthorize(context.Background(), "ent-1", "atlas", source); err != nil {
		t.Fatalf("next window did not reopen: %v", err)
	}
}

func TestAuthorizeRateLimiterRejectsNonHashSourceAndCanceledContext(t *testing.T) {
	limiter, err := NewMemoryAuthorizeRateLimiter(DefaultAuthorizeRateLimitPerMinute, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.AllowAuthorize(context.Background(), "ent-1", "atlas", "192.0.2.1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("raw source accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := limiter.AllowAuthorize(ctx, "ent-1", "atlas", sourceHashFixture("192.0.2.1")); !errors.Is(err, ErrAuthorizeRateUnavailable) {
		t.Fatalf("canceled context err=%v", err)
	}
}

func sourceHashFixture(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}
