package browserauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)

func TestCreateSessionHashesSecretsAndUsesFixedTTLs(t *testing.T) {
	svc, store, clock := newTestService(t)
	token, session, err := svc.CreateSession(context.Background(), CreateSessionInput{
		EnterpriseID: "ent-1", UserID: "user-1", UserAgent: "raw browser agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "session-secret" {
		t.Fatalf("token=%q", token)
	}
	if session.IdleExpiresAt.Sub(clock.now) != 8*time.Hour {
		t.Fatalf("idle ttl=%s", session.IdleExpiresAt.Sub(clock.now))
	}
	if session.AbsoluteExpiresAt.Sub(clock.now) != 24*time.Hour {
		t.Fatalf("absolute ttl=%s", session.AbsoluteExpiresAt.Sub(clock.now))
	}
	stored := store.sessionSnapshot()
	if len(stored) != 1 {
		t.Fatalf("stored sessions=%d", len(stored))
	}
	for hash, record := range stored {
		if hash == token || strings.Contains(hash, token) || len(hash) != 64 {
			t.Fatalf("unsafe token hash=%q", hash)
		}
		if record.UserAgentHash == "raw browser agent" || strings.Contains(record.UserAgentHash, "raw browser agent") || len(record.UserAgentHash) != 64 {
			t.Fatalf("unsafe ua hash=%q", record.UserAgentHash)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", session), "raw browser agent") {
		t.Fatalf("unsafe public model=%+v", session)
	}
}

func TestDefaultGeneratorUsesUnpaddedBase64URLWithAtLeast256Bits(t *testing.T) {
	value, err := randomOpaqueSecret()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(value, "=") {
		t.Fatalf("padded secret=%q", value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 32 {
		t.Fatalf("entropy bytes=%d", len(raw))
	}
}

func TestGetSessionSlidesIdleAndClampsAtAbsoluteExpiry(t *testing.T) {
	svc, _, clock := newTestService(t)
	token, created, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(7 * time.Hour)
	session, err := svc.GetSession(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if want := clock.now.Add(8 * time.Hour); !session.IdleExpiresAt.Equal(want) {
		t.Fatalf("idle=%s want=%s", session.IdleExpiresAt, want)
	}
	clock.now = created.CreatedAt.Add(14 * time.Hour)
	if _, err = svc.GetSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	clock.now = created.AbsoluteExpiresAt.Add(-3 * time.Hour)
	session, err = svc.GetSession(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if !session.IdleExpiresAt.Equal(created.AbsoluteExpiresAt) {
		t.Fatalf("idle=%s absolute=%s", session.IdleExpiresAt, created.AbsoluteExpiresAt)
	}
}

func TestGetSessionExpiresAtIdleAndAbsoluteBoundary(t *testing.T) {
	for _, boundary := range []string{"idle", "absolute"} {
		t.Run(boundary, func(t *testing.T) {
			svc, _, clock := newTestService(t)
			token, session, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
			if err != nil {
				t.Fatal(err)
			}
			if boundary == "idle" {
				clock.now = session.IdleExpiresAt
			} else {
				clock.now = session.AbsoluteExpiresAt
			}
			if _, err := svc.GetSession(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestGetSessionMissingRevokedAndStoreErrorFailClosed(t *testing.T) {
	svc, store, _ := newTestService(t)
	if _, err := svc.GetSession(context.Background(), "missing"); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("missing err=%v", err)
	}
	token, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeSession(context.Background(), token); err != nil && !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("repeat revoke=%v", err)
	}
	if _, err := svc.GetSession(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("revoked err=%v", err)
	}
	store.err = errors.New("database unavailable")
	if _, err := svc.GetSession(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("store err=%v", err)
	}
}

func TestEnterpriseUserMismatchFailsClosedBeforePersistence(t *testing.T) {
	svc, store, _ := newTestService(t)
	if _, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-2", UserID: "user-1"}); err == nil {
		t.Fatal("mismatched user accepted")
	}
	if len(store.sessionSnapshot()) != 0 {
		t.Fatal("mismatched session persisted")
	}
	if _, err := svc.IssueCode(context.Background(), IssueCodeInput{EnterpriseID: "ent-2", UserID: "user-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", Nonce: "n", CodeChallenge: s256("verifier")}); err == nil {
		t.Fatal("mismatched code accepted")
	}
	if len(store.codeSnapshot()) != 0 {
		t.Fatal("mismatched code persisted")
	}
}

func TestExchangeCodeIsOneTimeAndPKCEBound(t *testing.T) {
	svc, _, _ := newTestService(t)
	code, err := svc.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: "wrong", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("wrong verifier=%v", err)
	}
	result, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: "verifier", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if result.EnterpriseID != "ent-1" || result.UserID != "user-1" || result.Nonce != "nonce-1" {
		t.Fatalf("result=%+v", result)
	}
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: "verifier", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("reuse=%v", err)
	}
}

func TestExchangeCodeRejectsWrongBindingWithoutConsuming(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ExchangeCodeInput)
	}{
		{"client", func(in *ExchangeCodeInput) { in.ClientID = "other" }},
		{"redirect exact string", func(in *ExchangeCodeInput) { in.RedirectURI = "https://atlas/auth/callback/" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newTestService(t)
			code, err := svc.IssueCode(context.Background(), validIssueInput())
			if err != nil {
				t.Fatal(err)
			}
			bad := ExchangeCodeInput{Code: code, Verifier: "verifier", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}
			tc.mutate(&bad)
			if _, err := svc.ExchangeCode(context.Background(), bad); !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("bad err=%v", err)
			}
			if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: "verifier", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); err != nil {
				t.Fatalf("valid after mismatch=%v", err)
			}
		})
	}
}

func TestExchangeCodeExpiredAtBoundaryAndStoreFailureReturnInvalidGrant(t *testing.T) {
	svc, store, clock := newTestService(t)
	code, err := svc.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(60 * time.Second)
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: "verifier", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expiry err=%v", err)
	}
	store.err = errors.New("unavailable")
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "missing", Verifier: "verifier", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("store err=%v", err)
	}
}

func TestIssueCodeRejectsMalformedS256Challenge(t *testing.T) {
	for _, challenge := range []string{"", "not-base64!", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 33))} {
		t.Run(challenge, func(t *testing.T) {
			svc, store, _ := newTestService(t)
			in := validIssueInput()
			in.CodeChallenge = challenge
			if _, err := svc.IssueCode(context.Background(), in); err == nil {
				t.Fatal("malformed challenge accepted")
			}
			if len(store.codeSnapshot()) != 0 {
				t.Fatal("malformed code persisted")
			}
		})
	}
}

func TestIssueCodeStoresOnlyHashAndUsesSixtySecondTTL(t *testing.T) {
	svc, store, clock := newTestService(t)
	code, err := svc.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	if code != "session-secret" {
		t.Fatalf("code=%q", code)
	}
	for hash, record := range store.codeSnapshot() {
		if hash == code || strings.Contains(hash, code) || len(hash) != 64 {
			t.Fatalf("unsafe code hash=%q", hash)
		}
		if record.ExpiresAt.Sub(clock.now) != 60*time.Second {
			t.Fatalf("ttl=%s", record.ExpiresAt.Sub(clock.now))
		}
	}
}

func TestConcurrentCorrectExchangeHasExactlyOneSuccess(t *testing.T) {
	svc, _, _ := newTestService(t)
	code, err := svc.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: "verifier", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"})
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrInvalidGrant) {
				t.Errorf("err=%v", err)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successes=%d", got)
	}
}

type mutableClock struct{ now time.Time }

func (c *mutableClock) Now() time.Time { return c.now }

type sequenceGenerator struct {
	mu     sync.Mutex
	values []string
}

func (g *sequenceGenerator) Generate() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.values) == 0 {
		return "", errors.New("sequence exhausted")
	}
	v := g.values[0]
	g.values = g.values[1:]
	return v, nil
}

func newTestService(t *testing.T) (*Service, *MemoryStore, *mutableClock) {
	t.Helper()
	clock := &mutableClock{now: fixedNow}
	store := NewMemoryStore()
	store.AddEnterpriseUser("ent-1", "user-1")
	svc := NewService(store, WithClock(clock.Now), WithTestSecretGenerator((&sequenceGenerator{values: []string{"session-secret", "code-secret"}}).Generate))
	return svc, store, clock
}

func validIssueInput() IssueCodeInput {
	return IssueCodeInput{EnterpriseID: "ent-1", UserID: "user-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback", Nonce: "nonce-1", CodeChallenge: s256("verifier")}
}
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
