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
	svc := NewService(store, WithClock(clock.Now), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n')}}).Generate))
	state, attempt, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{
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
		if record.StateHash != key || record.UpstreamNonce == "" {
			t.Fatalf("record=%+v", record)
		}
	}
	clock.now = fixedNow.Add(5 * time.Minute)
	if _, err := svc.ConsumeLoginAttempt(context.Background(), state); !errors.Is(err, ErrInvalidLoginAttempt) {
		t.Fatalf("boundary err=%v", err)
	}
}

func TestLoginAttemptIsConsumedExactlyOnceConcurrently(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n')}}).Generate))
	state, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{
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
			if _, err := svc.ConsumeLoginAttempt(context.Background(), state); err == nil {
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
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n')}}).Generate))
	state, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.ConsumeLoginAttempt(ctx, state); !errors.Is(err, ErrInvalidLoginAttempt) {
		t.Fatalf("err=%v", err)
	}
	if _, err := svc.ConsumeLoginAttempt(context.Background(), state); err != nil {
		t.Fatalf("valid consume after cancellation: %v", err)
	}
}

func TestMemoryLoginAttemptStoreRejectsTTLAboveFiveMinutes(t *testing.T) {
	store := NewMemoryStore()
	attempt := storedLoginAttempt{StateHash: strings.Repeat("a", 64), LoginAttempt: LoginAttempt{EnterpriseID: "ent-1", ClientID: "atlas", RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier), UpstreamNonce: "up", CreatedAt: fixedNow, ExpiresAt: fixedNow.Add(5*time.Minute + time.Nanosecond)}}
	if err := store.CreateLoginAttempt(context.Background(), attempt); err == nil {
		t.Fatal("overlong login attempt accepted")
	}
}
