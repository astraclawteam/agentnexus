package browserauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginAttemptStoresStateHashAndExpiresAtFiveMinuteBoundary(t *testing.T) {
	store := NewMemoryStore()
	clock := &mutableClock{now: fixedNow}
	svc := NewService(store, WithClock(clock.Now), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, attempt, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{
		EnterpriseID: "ent-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback",
		ConsoleState: "console-state", ConsoleNonce: "console-nonce", CodeChallenge: s256(validVerifier),
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.ExpiresAt.Sub(fixedNow) != 5*time.Minute {
		t.Fatalf("ttl=%s", attempt.ExpiresAt.Sub(fixedNow))
	}
	for key, record := range store.loginAttemptSnapshot() {
		if key == state || strings.Contains(key, state) || len(key) != 64 {
			t.Fatalf("state stored unsafely: %q", key)
		}
		if record.StateHash != key || record.UpstreamNonce == "" || record.BindingHash == "" || record.BindingHash == binding || strings.Contains(record.BindingHash, binding) {
			t.Fatalf("record=%+v", record)
		}
	}
	clock.now = fixedNow.Add(5 * time.Minute)
	if _, err := svc.ConsumeLoginAttempt(context.Background(), state, binding); !errors.Is(err, ErrInvalidLoginAttempt) {
		t.Fatalf("boundary err=%v", err)
	}
	if got := len(store.loginAttemptSnapshot()); got != 0 {
		t.Fatalf("expired attempts retained=%d", got)
	}
}

func TestLoginAttemptIsConsumedExactlyOnceConcurrently(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{
		EnterpriseID: "ent-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback",
		ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier),
	})
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.ConsumeLoginAttempt(context.Background(), state, binding); err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrInvalidLoginAttempt) {
				t.Errorf("err=%v", err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("successes=%d", success.Load())
	}
}

func TestLoginAttemptCanceledContextDoesNotMutateStore(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.ConsumeLoginAttempt(ctx, state, binding); !errors.Is(err, ErrLoginAttemptUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if _, err := svc.ConsumeLoginAttempt(context.Background(), state, binding); err != nil {
		t.Fatalf("valid consume after cancellation: %v", err)
	}
}

func TestMemoryLoginAttemptStoreRejectsTTLAboveFiveMinutes(t *testing.T) {
	store := NewMemoryStore()
	attempt := storedLoginAttempt{StateHash: strings.Repeat("a", 64), BindingHash: strings.Repeat("b", 64), LoginAttempt: LoginAttempt{EnterpriseID: "ent-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier), UpstreamNonce: "up", CreatedAt: fixedNow, ExpiresAt: fixedNow.Add(5*time.Minute + time.Nanosecond)}}
	if err := store.CreateLoginAttempt(context.Background(), attempt); err == nil {
		t.Fatal("overlong login attempt accepted")
	}
}

func TestLoginAttemptWrongBrowserBindingDoesNotConsume(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConsumeLoginAttempt(context.Background(), state, secretFixture('x')); !errors.Is(err, ErrInvalidLoginAttempt) {
		t.Fatalf("wrong binding err=%v", err)
	}
	if _, err := svc.ConsumeLoginAttempt(context.Background(), state, binding); err != nil {
		t.Fatalf("valid binding after attack=%v", err)
	}
}

func TestLoginAttemptCleanupRemovesAllExpiredRows(t *testing.T) {
	store := NewMemoryStore()
	for i := 0; i < 10; i++ {
		key := string(rune('a' + i))
		store.loginAttempts[strings.Repeat(key, 64)] = storedLoginAttempt{StateHash: strings.Repeat(key, 64), BindingHash: strings.Repeat("b", 64), LoginAttempt: LoginAttempt{CreatedAt: fixedNow.Add(-10 * time.Minute), ExpiresAt: fixedNow.Add(-5 * time.Minute)}}
	}
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	if _, _, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}); err != nil {
		t.Fatal(err)
	}
	if got := len(store.loginAttemptSnapshot()); got != 1 {
		t.Fatalf("attempts=%d", got)
	}
}

func TestLoginAttemptLimitIsAtomicPerEnterpriseClient(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }))
	input := CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}

	var success, limited atomic.Int32
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, err := svc.CreateLoginAttempt(context.Background(), input)
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrLoginAttemptLimited):
				limited.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 32 || limited.Load() != 32 {
		t.Fatalf("success=%d limited=%d", success.Load(), limited.Load())
	}
}

func TestLoginAttemptLimitIsIndependentAndReopensAfterExpiry(t *testing.T) {
	clock := &mutableClock{now: fixedNow}
	svc := NewService(NewMemoryStore(), WithClock(clock.Now))
	create := func(enterpriseID, clientID string) error {
		_, _, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: enterpriseID, ClientID: clientID, RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
		return err
	}
	for range 32 {
		if err := create("ent-1", "atlas"); err != nil {
			t.Fatal(err)
		}
	}
	if err := create("ent-1", "atlas"); !errors.Is(err, ErrLoginAttemptLimited) {
		t.Fatalf("same key error=%v", err)
	}
	if err := create("ent-2", "atlas"); err != nil {
		t.Fatalf("different enterprise error=%v", err)
	}
	if err := create("ent-1", "other"); err != nil {
		t.Fatalf("different client error=%v", err)
	}
	clock.now = fixedNow.Add(defaultLoginTimeout)
	if err := create("ent-1", "atlas"); err != nil {
		t.Fatalf("after expiry error=%v", err)
	}
}

func TestCreateLoginAttemptMapsStoreErrors(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }))
	input := CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}
	store.err = errors.New("database unavailable")
	if _, _, _, err := svc.CreateLoginAttempt(context.Background(), input); !errors.Is(err, ErrLoginAttemptUnavailable) {
		t.Fatalf("store error=%v", err)
	}

	store.err = errLoginAttemptLimited
	if _, _, _, err := svc.CreateLoginAttempt(context.Background(), input); !errors.Is(err, ErrLoginAttemptLimited) {
		t.Fatalf("limit error=%v", err)
	}
}

func TestBrowserAuthorizationServiceRejectsOversizedProtocolInputs(t *testing.T) {
	base := CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}
	for name, mutate := range map[string]func(*CreateLoginAttemptInput){"client": func(v *CreateLoginAttemptInput) { v.ClientID = strings.Repeat("c", maxClientIDLength+1) }, "redirect": func(v *CreateLoginAttemptInput) { v.RedirectURI = strings.Repeat("r", maxRedirectURILength+1) }, "state": func(v *CreateLoginAttemptInput) { v.ConsoleState = strings.Repeat("s", maxConsoleStateLength+1) }, "nonce": func(v *CreateLoginAttemptInput) { v.ConsoleNonce = strings.Repeat("n", maxNonceLength+1) }} {
		t.Run(name, func(t *testing.T) {
			input := base
			mutate(&input)
			svc := NewService(NewMemoryStore(), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
			if _, _, _, err := svc.CreateLoginAttempt(context.Background(), input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	svc, store, _ := newTestService(t)
	issue := validIssueInput()
	issue.Nonce = strings.Repeat("n", maxNonceLength+1)
	if _, err := svc.IssueCode(context.Background(), issue); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("issue err=%v", err)
	}
	if len(store.codeSnapshot()) != 0 {
		t.Fatal("oversized code input persisted")
	}
	longCode := strings.Repeat("c", 44)
	store.codes[hashHex(longCode)] = storedAuthorizationCode{CodeHash: hashHex(longCode), EnterpriseID: "ent-1", UserID: "user-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback", Nonce: "n", CodeChallenge: s256(validVerifier), CreatedAt: fixedNow, ExpiresAt: fixedNow.Add(time.Minute)}
	if _, err := svc.ExchangeCode(context.Background(), ExchangeCodeInput{Code: longCode, Verifier: validVerifier, ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("exchange err=%v", err)
	}
}
