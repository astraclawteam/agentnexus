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

func TestLoginAttemptStoresStateHashAndExpiresAtFiveMinuteBoundary(t *testing.T) {
	store := NewMemoryStore()
	clock := &mutableClock{now: fixedNow}
	svc := NewService(store, WithClock(clock.Now), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, attempt, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{
		EnterpriseID: "ent-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback",
		BrowserID: secretFixture('z'), ConsoleState: "console-state", ConsoleNonce: "console-nonce", CodeChallenge: s256(validVerifier),
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
		if record.StateHash != key || record.UpstreamNonce == "" || record.BindingHash == "" || record.BindingHash == binding || strings.Contains(record.BindingHash, binding) || record.BrowserIDHash == "" || record.BrowserIDHash == secretFixture('z') || strings.Contains(record.BrowserIDHash, secretFixture('z')) {
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

func TestLoginAttemptExpiryIsSecondAlignedForBoundedCounterBuckets(t *testing.T) {
	now := fixedNow.Add(987654321 * time.Nanosecond)
	svc := NewService(NewMemoryStore(), WithClock(func() time.Time { return now }))
	_, _, attempt, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{
		EnterpriseID: "ent-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback",
		BrowserID: secretFixture('z'), ConsoleState: "console-state", ConsoleNonce: "console-nonce", CodeChallenge: s256(validVerifier),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !attempt.CreatedAt.Equal(attempt.CreatedAt.Truncate(time.Second)) || !attempt.ExpiresAt.Equal(attempt.ExpiresAt.Truncate(time.Second)) {
		t.Fatalf("attempt timestamps not second aligned: created=%s expires=%s", attempt.CreatedAt, attempt.ExpiresAt)
	}
}

func TestLoginAttemptIsConsumedExactlyOnceConcurrently(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{
		EnterpriseID: "ent-1", ClientID: "agentatlas", RedirectURI: "https://atlas/auth/callback",
		BrowserID: secretFixture('z'), ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier),
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
	state, binding, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "agentatlas", BrowserID: secretFixture('z'), RedirectURI: "https://atlas/auth/callback", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
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
	if err := store.CreateLoginAttempt(context.Background(), attempt, DefaultLoginAttemptLimits()); err == nil {
		t.Fatal("overlong login attempt accepted")
	}
}

func TestLoginAttemptWrongBrowserBindingDoesNotConsume(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	state, binding, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: secretFixture('z'), RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
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
		attempt := storedLoginAttempt{
			StateHash: strings.Repeat(key, 64), BindingHash: strings.Repeat("b", 64), BrowserIDHash: strings.Repeat(key, 64),
			LoginAttempt: LoginAttempt{EnterpriseID: "ent-1", ClientID: "atlas", CreatedAt: fixedNow, ExpiresAt: fixedNow.Add(defaultLoginTimeout)},
		}
		if err := store.CreateLoginAttempt(context.Background(), attempt, DefaultLoginAttemptLimits()); err != nil {
			t.Fatal(err)
		}
	}
	assertMemoryAttemptQuotaInvariant(t, store)
	svc := NewService(store, WithClock(func() time.Time { return fixedNow.Add(defaultLoginTimeout) }), WithTestSecretGenerator((&sequenceGenerator{values: []string{secretFixture('a'), secretFixture('n'), secretFixture('b')}}).Generate))
	if _, _, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: secretFixture('z'), RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}); err != nil {
		t.Fatal(err)
	}
	if got := len(store.loginAttemptSnapshot()); got != 1 {
		t.Fatalf("attempts=%d", got)
	}
	assertMemoryAttemptQuotaInvariant(t, store)
}

func TestDefaultLoginAttemptLimitsRemainEightPerBrowserAnd65536Global(t *testing.T) {
	if got := DefaultLoginAttemptLimits(); got != (LoginAttemptLimits{PerBrowser: 8, Global: 65536}) {
		t.Fatalf("defaults=%+v", got)
	}
}

func TestMemoryLoginAttemptExpiryHeapIgnoresStaleGenerationAfterStateReuse(t *testing.T) {
	store := NewMemoryStore()
	limits := LoginAttemptLimits{PerBrowser: 8, Global: 8}
	attempt := func(binding string, created time.Time) storedLoginAttempt {
		return storedLoginAttempt{
			StateHash: strings.Repeat("a", 64), BindingHash: strings.Repeat(binding, 64), BrowserIDHash: strings.Repeat("b", 64),
			LoginAttempt: LoginAttempt{EnterpriseID: "ent-1", ClientID: "atlas", CreatedAt: created, ExpiresAt: created.Add(defaultLoginTimeout)},
		}
	}
	first := attempt("c", fixedNow)
	if err := store.CreateLoginAttempt(context.Background(), first, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeLoginAttempt(context.Background(), first.StateHash, first.BindingHash, fixedNow); err != nil {
		t.Fatal(err)
	}
	second := attempt("d", fixedNow.Add(time.Minute))
	if err := store.CreateLoginAttempt(context.Background(), second, limits); err != nil {
		t.Fatal(err)
	}
	trigger := storedLoginAttempt{
		StateHash: strings.Repeat("e", 64), BindingHash: strings.Repeat("f", 64), BrowserIDHash: strings.Repeat("b", 64),
		LoginAttempt: LoginAttempt{EnterpriseID: "ent-1", ClientID: "atlas", CreatedAt: fixedNow.Add(defaultLoginTimeout), ExpiresAt: fixedNow.Add(2 * defaultLoginTimeout)},
	}
	if err := store.CreateLoginAttempt(context.Background(), trigger, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeLoginAttempt(context.Background(), second.StateHash, second.BindingHash, fixedNow.Add(defaultLoginTimeout)); err != nil {
		t.Fatalf("stale heap item removed reused state: %v", err)
	}
	assertMemoryAttemptQuotaInvariant(t, store)
}

func TestMemoryLoginAttemptQuotaReleasesImmediatelyAndDoesNotDriftOnErrors(t *testing.T) {
	store := NewMemoryStore()
	limits := LoginAttemptLimits{PerBrowser: 2, Global: 2}
	newAttempt := func(state, binding, browser string, created time.Time) storedLoginAttempt {
		return storedLoginAttempt{
			StateHash: strings.Repeat(state, 64), BindingHash: strings.Repeat(binding, 64), BrowserIDHash: strings.Repeat(browser, 64),
			LoginAttempt: LoginAttempt{EnterpriseID: "ent-1", ClientID: "atlas", CreatedAt: created, ExpiresAt: created.Add(defaultLoginTimeout)},
		}
	}
	a := newAttempt("a", "d", "b", fixedNow)
	b := newAttempt("c", "e", "b", fixedNow)
	if err := store.CreateLoginAttempt(context.Background(), a, limits); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateLoginAttempt(context.Background(), b, limits); err != nil {
		t.Fatal(err)
	}
	assertMemoryAttemptQuotaInvariant(t, store)

	if _, err := store.ConsumeLoginAttempt(context.Background(), a.StateHash, strings.Repeat("f", 64), fixedNow); !errors.Is(err, errNotFound) {
		t.Fatalf("wrong binding error=%v", err)
	}
	assertMemoryAttemptQuotaInvariant(t, store)

	if _, err := store.ConsumeLoginAttempt(context.Background(), a.StateHash, a.BindingHash, fixedNow); err != nil {
		t.Fatal(err)
	}
	assertMemoryAttemptQuotaInvariant(t, store)
	if err := store.CreateLoginAttempt(context.Background(), newAttempt("f", "a", "b", fixedNow), limits); err != nil {
		t.Fatalf("consume did not release quota immediately: %v", err)
	}
	assertMemoryAttemptQuotaInvariant(t, store)

	before := len(store.loginAttemptSnapshot())
	if err := store.CreateLoginAttempt(context.Background(), b, limits); !errors.Is(err, errLoginAttemptLimited) && !errors.Is(err, errDuplicate) {
		t.Fatalf("duplicate/limited error=%v", err)
	}
	if got := len(store.loginAttemptSnapshot()); got != before {
		t.Fatalf("failed create mutated attempts: before=%d after=%d", before, got)
	}
	assertMemoryAttemptQuotaInvariant(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.ConsumeLoginAttempt(ctx, b.StateHash, b.BindingHash, fixedNow); err == nil {
		t.Fatal("canceled consume succeeded")
	}
	assertMemoryAttemptQuotaInvariant(t, store)
}

func assertMemoryAttemptQuotaInvariant(t *testing.T, store *MemoryStore) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	value := reflect.ValueOf(store).Elem()
	scopeCounts := value.FieldByName("scopeCounts")
	browserCounts := value.FieldByName("browserCounts")
	expiry := value.FieldByName("loginAttemptExpiry")
	if !scopeCounts.IsValid() || !browserCounts.IsValid() || !expiry.IsValid() {
		t.Fatal("memory store quota counters/expiry heap are missing")
	}
	sum := func(counts reflect.Value) int {
		total := 0
		iter := counts.MapRange()
		for iter.Next() {
			total += int(iter.Value().Int())
		}
		return total
	}
	if got, want := sum(scopeCounts), len(store.loginAttempts); got != want {
		t.Fatalf("scope counter total=%d attempts=%d", got, want)
	}
	if got, want := sum(browserCounts), len(store.loginAttempts); got != want {
		t.Fatalf("browser counter total=%d attempts=%d", got, want)
	}
	if expiry.Len() < len(store.loginAttempts) {
		t.Fatalf("expiry heap=%d attempts=%d", expiry.Len(), len(store.loginAttempts))
	}
}

func TestLoginAttemptLimitIsAtomicPerBrowser(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithLoginAttemptLimits(LoginAttemptLimits{PerBrowser: 8, Global: 4096}))
	input := CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: secretFixture('z'), RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}

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
	if success.Load() != 8 || limited.Load() != 56 {
		t.Fatalf("success=%d limited=%d", success.Load(), limited.Load())
	}
}

func TestLoginAttemptLimitIsIndependentPerBrowserAndReopensAfterExpiry(t *testing.T) {
	clock := &mutableClock{now: fixedNow}
	svc := NewService(NewMemoryStore(), WithClock(clock.Now), WithLoginAttemptLimits(LoginAttemptLimits{PerBrowser: 8, Global: 4096}))
	create := func(browserID string) error {
		_, _, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: browserID, RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
		return err
	}
	for range 8 {
		if err := create(secretFixture('a')); err != nil {
			t.Fatal(err)
		}
	}
	if err := create(secretFixture('a')); !errors.Is(err, ErrLoginAttemptLimited) {
		t.Fatalf("same key error=%v", err)
	}
	if err := create(secretFixture('b')); err != nil {
		t.Fatalf("different browser error=%v", err)
	}
	clock.now = fixedNow.Add(defaultLoginTimeout)
	if err := create(secretFixture('a')); err != nil {
		t.Fatalf("after expiry error=%v", err)
	}
}

func TestLoginAttemptGlobalLimitIsAtomicAcrossBrowsers(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }), WithLoginAttemptLimits(LoginAttemptLimits{PerBrowser: 8, Global: 16}))
	var success, limited atomic.Int32
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			digest := sha256.Sum256([]byte(fmt.Sprintf("browser-%d", i)))
			browserID := base64.RawURLEncoding.EncodeToString(digest[:])
			_, _, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: browserID, RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)})
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrLoginAttemptLimited):
				limited.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if success.Load() != 16 || limited.Load() != 48 {
		t.Fatalf("success=%d limited=%d", success.Load(), limited.Load())
	}
}

func TestLoginAttemptAllowsAtLeast64DistinctBrowsersByDefault(t *testing.T) {
	svc := NewService(NewMemoryStore(), WithClock(func() time.Time { return fixedNow }))
	for i := range 64 {
		digest := sha256.Sum256([]byte(fmt.Sprintf("browser-%d", i)))
		browserID := base64.RawURLEncoding.EncodeToString(digest[:])
		if _, _, _, err := svc.CreateLoginAttempt(context.Background(), CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: browserID, RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}); err != nil {
			t.Fatalf("browser %d: %v", i, err)
		}
	}
}

func TestCreateLoginAttemptMapsStoreErrors(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return fixedNow }))
	input := CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: secretFixture('z'), RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}
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
	base := CreateLoginAttemptInput{EnterpriseID: "ent-1", ClientID: "atlas", BrowserID: secretFixture('z'), RedirectURI: "https://atlas/cb", ConsoleState: "s", ConsoleNonce: "n", CodeChallenge: s256(validVerifier)}
	for name, mutate := range map[string]func(*CreateLoginAttemptInput){"browser": func(v *CreateLoginAttemptInput) { v.BrowserID = "not-canonical" }, "client": func(v *CreateLoginAttemptInput) { v.ClientID = strings.Repeat("c", maxClientIDLength+1) }, "redirect": func(v *CreateLoginAttemptInput) { v.RedirectURI = strings.Repeat("r", maxRedirectURILength+1) }, "state": func(v *CreateLoginAttemptInput) { v.ConsoleState = strings.Repeat("s", maxConsoleStateLength+1) }, "nonce": func(v *CreateLoginAttemptInput) { v.ConsoleNonce = strings.Repeat("n", maxNonceLength+1) }} {
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
