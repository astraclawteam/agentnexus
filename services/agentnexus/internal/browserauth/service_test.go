package browserauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 7, 10, 8, 0, 0, 0, time.UTC)
var validVerifier = strings.Repeat("v", 43)
var wrongVerifier = strings.Repeat("w", 43)

func TestCreateSessionHashesSecretsAndUsesFixedTTLs(t *testing.T) {
	svc, store, clock := newTestService(t)
	token, session, err := svc.CreateSession(context.Background(), CreateSessionInput{
		EnterpriseID: "ent-1", UserID: "user-1", UserAgent: "raw browser agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != secretFixture('s') {
		t.Fatalf("token=%q", token)
	}
	if session.IdleExpiresAt.Sub(clock.now) != 8*time.Hour {
		t.Fatalf("idle ttl=%s", session.IdleExpiresAt.Sub(clock.now))
	}
	if session.AbsoluteExpiresAt.Sub(clock.now) != 24*time.Hour {
		t.Fatalf("absolute ttl=%s", session.AbsoluteExpiresAt.Sub(clock.now))
	}
	stored := store.sessionSnapshot()
	if len(stored) != 2 {
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

func TestTestGeneratorCannotWeakenSecretEntropy(t *testing.T) {
	store := NewMemoryStore()
	store.AddEnterpriseUser("ent-1", "user-1")
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator(func() (string, error) { return "short", nil }))
	if _, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err=%v", err)
	}
	if got := len(store.sessionSnapshot()); got != 0 {
		t.Fatalf("persisted sessions=%d", got)
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
	if _, err := svc.GetSession(context.Background(), token); !errors.Is(err, ErrSessionUnavailable) || errors.Is(err, ErrInvalidSession) {
		t.Fatalf("store err=%v", err)
	}
}

func TestEnterpriseUserMismatchFailsClosedBeforePersistence(t *testing.T) {
	svc, store, _ := newTestService(t)
	if _, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-2", UserID: "user-1"}); err == nil {
		t.Fatal("mismatched user accepted")
	}
	if len(store.sessionSnapshot()) != 1 {
		t.Fatal("mismatched session persisted")
	}
	if _, err := svc.IssueCode(context.Background(), IssueCodeInput{EnterpriseID: "ent-2", UserID: "user-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", Nonce: "n", CodeChallenge: s256(validVerifier)}); err == nil {
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
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: wrongVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("wrong verifier=%v", err)
	}
	result, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if result.EnterpriseID != "ent-1" || result.UserID != "user-1" || result.Nonce != "nonce-1" {
		t.Fatalf("unexpected identity enterprise=%q user=%q nonce=%q", result.EnterpriseID, result.UserID, result.Nonce)
	}
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("reuse=%v", err)
	}
}

func TestExchangeCodeIssuesSessionBoundOpaqueAccessToken(t *testing.T) {
	svc, store, _ := newTestService(t)
	sessionToken, session, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	input := validIssueInput()
	input.BrowserSessionToken = sessionToken
	code, err := svc.IssueCode(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if !validOpaqueSecret(result.AccessToken) || !result.AccessTokenExpiresAt.Equal(session.AbsoluteExpiresAt) {
		t.Fatalf("unsafe access token shape valid=%v expiry_matches=%v", validOpaqueSecret(result.AccessToken), result.AccessTokenExpiresAt.Equal(session.AbsoluteExpiresAt))
	}
	if strings.Contains(fmt.Sprintf("%+v", store.accessTokenSnapshot()), result.AccessToken) {
		t.Fatal("raw access token persisted")
	}
	resolved, err := svc.GetAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-1")
	if err != nil || resolved.EnterpriseID != "ent-1" || resolved.UserID != "user-1" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	clock := &mutableClock{now: fixedNow.Add(7 * time.Hour)}
	svc.now = clock.Now
	resolved, err = svc.GetAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-1")
	if err != nil || !resolved.IdleExpiresAt.Equal(fixedNow.Add(15*time.Hour)) {
		t.Fatalf("bearer idle slide=%s err=%v", resolved.IdleExpiresAt, err)
	}
	if err := svc.RevokeSession(context.Background(), sessionToken); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-1"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("revoked session token err=%v", err)
	}
}

func TestAccessTokenFailsClosedForWrongBindingAndExpiry(t *testing.T) {
	svc, store, clock := newTestService(t)
	sessionToken, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	input := validIssueInput()
	input.BrowserSessionToken = sessionToken
	code, err := svc.IssueCode(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range [][3]string{{"other", "agentatlas", "ent-1"}, {"agentatlas", "other", "ent-1"}, {"agentatlas", "agentatlas", "ent-2"}} {
		if _, err := svc.GetAccessTokenSession(context.Background(), result.AccessToken, binding[0], binding[1], binding[2]); !errors.Is(err, ErrInvalidAccessToken) {
			t.Fatalf("binding=%v err=%v", binding, err)
		}
	}
	if session := store.sessionSnapshot()[hashHex(sessionToken)]; !session.LastSeenAt.Equal(fixedNow) || session.RevokedAt != nil {
		t.Fatalf("wrong tenant mutated session")
	}
	if _, err := svc.LogoutAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-2"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("wrong tenant logout err=%v", err)
	}
	if _, err := svc.GetAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-1"); err != nil {
		t.Fatalf("wrong tenant logout revoked session: %v", err)
	}
	clock.now = fixedNow.Add(8 * time.Hour)
	if _, err := svc.GetAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-1"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("idle expiry err=%v", err)
	}
	clock.now = result.AccessTokenExpiresAt
	if _, err := svc.GetAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-1"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expiry err=%v", err)
	}
}

func TestAccessTokenLogoutCannotRevokeAContradictorySessionBinding(t *testing.T) {
	svc, store, _ := newTestService(t)
	sessionToken, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	input := validIssueInput()
	input.BrowserSessionToken = sessionToken
	code, err := svc.IssueCode(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	store.AddEnterpriseUser("ent-2", "user-2")
	foreignToken, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-2", UserID: "user-2"})
	if err != nil {
		t.Fatal(err)
	}
	accessHash := hashHex(result.AccessToken)
	store.mu.Lock()
	corrupt := store.accessTokens[accessHash]
	corrupt.BrowserSessionIDHash = hashHex(foreignToken)
	store.accessTokens[accessHash] = corrupt
	store.mu.Unlock()

	if _, err := svc.LogoutAccessTokenSession(context.Background(), result.AccessToken, "agentatlas", "agentatlas", "ent-1"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("contradictory binding logout err=%v", err)
	}
	if foreign := store.sessionSnapshot()[hashHex(foreignToken)]; foreign.RevokedAt != nil {
		t.Fatal("contradictory token binding revoked a foreign session")
	}
}

func TestAccessTokenHashCollisionDoesNotConsumeAuthorizationCode(t *testing.T) {
	svc, store, _ := newTestService(t)
	firstCode, err := svc.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: firstCode, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); err != nil {
		t.Fatal(err)
	}
	colliding := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('d'), secretFixture('c')}}).Generate))
	secondCode, err := colliding.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	request := ExchangeCodeInput{Code: secondCode, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}
	if _, err := colliding.ExchangeCode(context.Background(), request); !errors.Is(err, ErrGrantUnavailable) {
		t.Fatalf("collision err=%v", err)
	}
	retry := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator(func() (string, error) { return secretFixture('e'), nil }))
	if _, err := retry.ExchangeCode(context.Background(), request); err != nil {
		t.Fatalf("retry err=%v", err)
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
			bad := ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}
			tc.mutate(&bad)
			if _, err := svc.ExchangeCode(context.Background(), bad); !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("bad err=%v", err)
			}
			if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); err != nil {
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
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expiry err=%v", err)
	}
	store.err = errors.New("unavailable")
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: "missing", Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
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
	if code != secretFixture('s') {
		t.Fatalf("code=%q", code)
	}
	stored := store.codeSnapshot()
	if len(stored) != 1 {
		t.Fatalf("stored codes=%d", len(stored))
	}
	for hash, record := range stored {
		if hash == code || strings.Contains(hash, code) || len(hash) != 64 {
			t.Fatalf("unsafe code hash=%q", hash)
		}
		if record.ExpiresAt.Sub(clock.now) != 60*time.Second {
			t.Fatalf("ttl=%s", record.ExpiresAt.Sub(clock.now))
		}
	}
}

func TestExchangeRejectsInvalidRFC7636VerifierWithoutConsuming(t *testing.T) {
	for _, verifier := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + ":"} {
		t.Run(fmt.Sprintf("len-%d", len(verifier)), func(t *testing.T) {
			svc, store, _ := newTestService(t)
			input := validIssueInput()
			input.CodeChallenge = s256(verifier)
			code, err := svc.IssueCode(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: verifier, ClientID: input.ClientID, RedirectURI: input.RedirectURI}); !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("err=%v", err)
			}
			stored := store.codeSnapshot()
			if len(stored) != 1 {
				t.Fatalf("stored codes=%d", len(stored))
			}
			for _, record := range stored {
				if record.ConsumedAt != nil {
					t.Fatal("invalid verifier consumed code")
				}
			}
		})
	}
}

func TestMemoryStoreRejectsDuplicateSessionHashAcrossEnterprises(t *testing.T) {
	store := NewMemoryStore()
	store.AddEnterpriseUser("ent-a", "user-a")
	store.AddEnterpriseUser("ent-b", "user-b")
	secret := secretFixture('d')
	service := func() *Service {
		return NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator(func() (string, error) { return secret, nil }))
	}
	if _, _, err := service().CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-a", UserID: "user-a"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service().CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-b", UserID: "user-b"}); !errors.Is(err, errDuplicate) {
		t.Fatalf("duplicate err=%v", err)
	}
	stored := store.sessionSnapshot()
	if len(stored) != 1 {
		t.Fatalf("stored sessions=%d", len(stored))
	}
	for _, record := range stored {
		if record.EnterpriseID != "ent-a" || record.UserID != "user-a" {
			t.Fatalf("original session overwritten: %+v", record)
		}
	}
}

func TestMemoryStoreCannotRecreateConsumedAuthorizationCodeHash(t *testing.T) {
	store := NewMemoryStore()
	store.AddEnterpriseUser("ent-1", "user-1")
	store.sessions[hashHex(secretFixture('b'))] = storedSession{IDHash: hashHex(secretFixture('b')), EnterpriseID: "ent-1", UserID: "user-1", CreatedAt: fixedNow, LastSeenAt: fixedNow, IdleExpiresAt: fixedNow.Add(8 * time.Hour), AbsoluteExpiresAt: fixedNow.Add(24 * time.Hour), UserAgentHash: hashHex("test")}
	secret := secretFixture('c')
	service := func() *Service {
		return NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator(func() (string, error) { return secret, nil }))
	}
	code, err := service().IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service().ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service().IssueCode(context.Background(), validIssueInput()); !errors.Is(err, errDuplicate) {
		t.Fatalf("duplicate err=%v", err)
	}
	stored := store.codeSnapshot()
	if len(stored) != 1 {
		t.Fatalf("stored codes=%d", len(stored))
	}
	for _, record := range stored {
		if record.ConsumedAt == nil {
			t.Fatal("consumed code was revived")
		}
	}
}

func TestCanceledContextCannotMutateMemoryStore(t *testing.T) {
	svc, store, _ := newTestService(t)
	token, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := svc.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	sessionsBefore := store.sessionSnapshot()
	codesBefore := store.codeSnapshot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.GetSession(ctx, token); !errors.Is(err, ErrSessionUnavailable) || errors.Is(err, ErrInvalidSession) {
		t.Fatalf("get err=%v", err)
	}
	if err := svc.RevokeSession(ctx, token); !errors.Is(err, ErrSessionUnavailable) || errors.Is(err, ErrInvalidSession) {
		t.Fatalf("revoke err=%v", err)
	}
	if _, err := svc.ExchangeCode(ctx, ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrGrantUnavailable) || errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("exchange err=%v", err)
	}
	if _, _, err := svc.CreateSession(ctx, CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"}); err == nil {
		t.Fatal("create session accepted canceled context")
	}
	if _, err := svc.IssueCode(ctx, validIssueInput()); err == nil {
		t.Fatal("issue code accepted canceled context")
	}
	if _, err := store.EnterpriseUserBindingExists(ctx, "ent-1", "user-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("binding err=%v", err)
	}
	if !reflect.DeepEqual(sessionsBefore, store.sessionSnapshot()) || !reflect.DeepEqual(codesBefore, store.codeSnapshot()) {
		t.Fatal("canceled context changed persistence")
	}
}

func TestContextCanceledWhileWaitingForMemoryLockCannotSlideSession(t *testing.T) {
	svc, store, _ := newTestService(t)
	token, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	before := store.sessionSnapshot()
	ctx, cancel := context.WithCancel(context.Background())
	store.mu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := svc.GetSession(ctx, token)
		done <- err
	}()
	<-started
	cancel()
	store.mu.Unlock()
	if err := <-done; !errors.Is(err, ErrSessionUnavailable) || errors.Is(err, ErrInvalidSession) {
		t.Fatalf("err=%v", err)
	}
	if !reflect.DeepEqual(before, store.sessionSnapshot()) {
		t.Fatal("canceled waiter slid session")
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
			_, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"})
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

func TestLogoutSessionAtomicallyReturnsActorWithoutSlidingIdle(t *testing.T) {
	svc, store, clock := newTestService(t)
	raw, created, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	before := store.sessionSnapshot()
	clock.now = clock.now.Add(time.Hour)
	actor, err := svc.LogoutSession(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if actor.EnterpriseID != "ent-1" || actor.UserID != "user-1" {
		t.Fatalf("actor=%+v", actor)
	}
	for key, record := range store.sessionSnapshot() {
		if key != hashHex(secretFixture('b')) && (!record.LastSeenAt.Equal(before[key].LastSeenAt) || record.RevokedAt == nil) {
			t.Fatalf("record=%+v created=%+v", record, created)
		}
	}
	if _, err := svc.GetSession(context.Background(), raw); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("post logout=%v", err)
	}
}

func TestLogoutSessionDistinguishesInvalidFromStoreUnavailable(t *testing.T) {
	svc, store, _ := newTestService(t)
	if _, err := svc.LogoutSession(context.Background(), secretFixture('x')); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("invalid=%v", err)
	}
	store.err = errors.New("database unavailable")
	if _, err := svc.LogoutSession(context.Background(), secretFixture('x')); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("store=%v", err)
	}
}

func TestServiceDistinguishesMissingRecordsFromUnavailableStores(t *testing.T) {
	svc, store, _ := newTestService(t)
	session, _, err := svc.CreateSession(context.Background(), CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := svc.IssueCode(context.Background(), validIssueInput())
	if err != nil {
		t.Fatal(err)
	}
	store.err = errors.New("database unavailable")
	if _, err := svc.GetSession(context.Background(), session); !errors.Is(err, ErrSessionUnavailable) || errors.Is(err, ErrInvalidSession) {
		t.Fatalf("get=%v", err)
	}
	if err := svc.RevokeSession(context.Background(), session); !errors.Is(err, ErrSessionUnavailable) || errors.Is(err, ErrInvalidSession) {
		t.Fatalf("revoke=%v", err)
	}
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: code, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrGrantUnavailable) || errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("exchange=%v", err)
	}
	store.err = nil
	attemptSvc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, _, err := attemptSvc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "agentatlas", BrowserID: secretFixture('z'), RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
	if err != nil {
		t.Fatal(err)
	}
	store.err = errors.New("database unavailable")
	if _, err := attemptSvc.ConsumeLoginAttempt(context.Background(), state, binding); !errors.Is(err, ErrLoginAttemptUnavailable) || errors.Is(err, ErrInvalidLoginAttempt) {
		t.Fatalf("consume=%v", err)
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
		return secretFixture('z'), nil
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
	store.sessions[hashHex(secretFixture('b'))] = storedSession{IDHash: hashHex(secretFixture('b')), EnterpriseID: "ent-1", UserID: "user-1", CreatedAt: fixedNow, LastSeenAt: fixedNow, IdleExpiresAt: fixedNow.Add(8 * time.Hour), AbsoluteExpiresAt: fixedNow.Add(24 * time.Hour), UserAgentHash: hashHex("test")}
	svc := NewService(store, WithClock(clock.Now), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('s'), secretFixture('c'), secretFixture('a')}}).Generate))
	return svc, store, clock
}

func validIssueInput() IssueCodeInput {
	return IssueCodeInput{EnterpriseID: "ent-1", UserID: "user-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback", Nonce: "nonce-1", CodeChallenge: s256(validVerifier), BrowserSessionToken: secretFixture('b')}
}
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func secretFixture(fill byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(fill), 32)))
}
