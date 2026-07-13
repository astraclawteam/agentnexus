package secretprovider_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
)

// masterCanary is a seeded plaintext master credential. It must NEVER surface
// in a Handle, a redeemed Secret's serialized form, a log line or any audit
// record: the connector-facing surface only ever carries derived, scoped,
// short-lived material.
const masterCanary = "MASTER-CANARY-DO-NOT-LEAK-4f1a9c7e21b8"

const (
	testCallerToken = "caller-token-authenticated-local"
	// Credential references are delimiter- and control-char-free (canonical
	// rejects '/' and control bytes), so a ':'-separated reference is used.
	testCredential = "secret:knowledge_demo:http-token"
)

func testScope() secretprovider.Scope {
	return secretprovider.Scope{
		ConnectorRef: "knowledge_demo",
		Resource:     "documents",
		Operation:    "search",
		Action:       "read",
	}
}

func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

func newSeededProvider(t *testing.T, at time.Time) *secretprovider.LocalProvider {
	t.Helper()
	provider := secretprovider.NewLocalProvider(
		secretprovider.WithCallerToken(testCallerToken),
		secretprovider.WithClock(fixedClock(at)),
	)
	if _, err := provider.SetMaster(testCredential, masterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	return provider
}

func acquire(t *testing.T, provider secretprovider.Provider, req secretprovider.AcquireRequest) secretprovider.Handle {
	t.Helper()
	handle, err := provider.AcquireHandle(context.Background(), req)
	if err != nil {
		t.Fatalf("AcquireHandle: %v", err)
	}
	return handle
}

func TestSecretLocalProviderIssuesScopedHandleCarryingNoMaterial(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)

	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           90 * time.Second,
		SingleUse:     true,
	})

	if handle.ID() == "" {
		t.Fatal("handle has no id")
	}
	if handle.Scope() != testScope() {
		t.Fatalf("handle scope = %+v, want %+v", handle.Scope(), testScope())
	}
	if handle.Version() == "" {
		t.Fatal("handle carries no version")
	}
	if !handle.ExpiresAt().Equal(now.Add(90 * time.Second)) {
		t.Fatalf("handle expiry = %v, want %v", handle.ExpiresAt(), now.Add(90*time.Second))
	}
	if !handle.SingleUse() {
		t.Fatal("handle single-use flag lost")
	}

	// The handle is opaque metadata: no rendering of it may expose the master.
	for _, rendered := range []string{
		fmt.Sprintf("%v", handle),
		fmt.Sprintf("%+v", handle),
		fmt.Sprintf("%#v", handle),
		handle.String(),
	} {
		if strings.Contains(rendered, masterCanary) {
			t.Fatalf("handle rendering leaked master: %q", rendered)
		}
	}
	encoded, err := json.Marshal(handle)
	if err != nil {
		t.Fatalf("Marshal handle: %v", err)
	}
	if strings.Contains(string(encoded), masterCanary) {
		t.Fatalf("handle JSON leaked master: %s", encoded)
	}
}

func TestSecretRedeemReturnsDerivedMaterialNotMaster(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           90 * time.Second,
	})

	secret, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken,
		HandleID:    handle.ID(),
		Scope:       testScope(),
	})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	material := secret.Reveal()
	if material == "" {
		t.Fatal("redeemed material is empty")
	}
	if material == masterCanary || strings.Contains(material, masterCanary) {
		t.Fatalf("redeemed material is (or contains) the master credential")
	}
	// The Secret redacts itself everywhere except the explicit Reveal call.
	for _, rendered := range []string{
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret),
		fmt.Sprintf("%#v", secret),
		secret.String(),
	} {
		if strings.Contains(rendered, material) || strings.Contains(rendered, masterCanary) {
			t.Fatalf("secret rendering leaked material/master: %q", rendered)
		}
	}
	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("Marshal secret: %v", err)
	}
	if strings.Contains(string(encoded), material) || strings.Contains(string(encoded), masterCanary) {
		t.Fatalf("secret JSON leaked material/master: %s", encoded)
	}
}

func TestSecretProviderRejectsUnauthenticatedCaller(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)

	_, err := provider.AcquireHandle(context.Background(), secretprovider.AcquireRequest{
		CallerToken:   "wrong-token",
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
	})
	if !errors.Is(err, secretprovider.ErrUnauthenticated) {
		t.Fatalf("AcquireHandle err = %v, want ErrUnauthenticated", err)
	}
}

func TestSecretRedeemRejectsConnectorIdentityMismatch(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
	})

	// A handle issued for connector "knowledge_demo" replayed under a different
	// connector identity must be rejected.
	foreign := testScope()
	foreign.ConnectorRef = "attacker_connector"
	_, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken,
		HandleID:    handle.ID(),
		Scope:       foreign,
	})
	if !errors.Is(err, secretprovider.ErrScopeMismatch) {
		t.Fatalf("Redeem err = %v, want ErrScopeMismatch", err)
	}
}

func TestSecretRedeemRejectsOperationScopeMismatch(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
	})

	foreign := testScope()
	foreign.Operation = "update"
	foreign.Action = "write"
	_, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken,
		HandleID:    handle.ID(),
		Scope:       foreign,
	})
	if !errors.Is(err, secretprovider.ErrScopeMismatch) {
		t.Fatalf("Redeem err = %v, want ErrScopeMismatch", err)
	}
}

func TestSecretSingleUseHandleRejectsSecondRedeem(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
		SingleUse:     true,
	})

	if _, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: handle.ID(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	_, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: handle.ID(), Scope: testScope(),
	})
	if !errors.Is(err, secretprovider.ErrHandleConsumed) {
		t.Fatalf("second redeem err = %v, want ErrHandleConsumed", err)
	}
}

func TestSecretTTLBoundedHandleRejectedAfterExpiry(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	clock := &steppableClock{at: now}
	provider := secretprovider.NewLocalProvider(
		secretprovider.WithCallerToken(testCallerToken),
		secretprovider.WithClock(clock.now),
	)
	if _, err := provider.SetMaster(testCredential, masterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           30 * time.Second,
	})

	clock.at = now.Add(31 * time.Second)
	_, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: handle.ID(), Scope: testScope(),
	})
	if !errors.Is(err, secretprovider.ErrHandleExpired) {
		t.Fatalf("expired redeem err = %v, want ErrHandleExpired", err)
	}
}

func TestSecretRevokedVersionRejectsOutstandingHandle(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
	})

	if err := provider.Revoke(testCredential, handle.Version()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: handle.ID(), Scope: testScope(),
	})
	if !errors.Is(err, secretprovider.ErrRevokedVersion) {
		t.Fatalf("revoked redeem err = %v, want ErrRevokedVersion", err)
	}
}

func TestSecretRotationInvalidatesOldHandlesAndBindsNewVersion(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	old := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
	})

	newVersion, err := provider.Rotate(testCredential, "ROTATED-MASTER-CANARY-8b7d")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newVersion == old.Version() {
		t.Fatal("rotation did not advance the version")
	}

	// Old handle bound to the retired version is invalid post-rotation.
	if _, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: old.ID(), Scope: testScope(),
	}); !errors.Is(err, secretprovider.ErrRevokedVersion) {
		t.Fatalf("old handle after rotation err = %v, want ErrRevokedVersion", err)
	}

	// A freshly acquired handle binds the new version and redeems.
	fresh := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
	})
	if fresh.Version() != newVersion {
		t.Fatalf("fresh handle version = %q, want %q", fresh.Version(), newVersion)
	}
	if _, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: fresh.ID(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("fresh handle redeem: %v", err)
	}
}

func TestSecretUnknownCredentialRejected(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	_, err := provider.AcquireHandle(context.Background(), secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: "secret:unknown:ref",
		TTL:           time.Minute,
	})
	if !errors.Is(err, secretprovider.ErrUnknownCredential) {
		t.Fatalf("AcquireHandle err = %v, want ErrUnknownCredential", err)
	}
}

func TestSecretUnavailableProviderFailsClosed(t *testing.T) {
	provider := secretprovider.UnavailableProvider()
	if err := provider.Ping(context.Background()); !errors.Is(err, secretprovider.ErrProviderUnavailable) {
		t.Fatalf("Ping err = %v, want ErrProviderUnavailable", err)
	}
	if _, err := provider.AcquireHandle(context.Background(), secretprovider.AcquireRequest{
		CallerToken:   testCallerToken,
		Scope:         testScope(),
		CredentialRef: testCredential,
		TTL:           time.Minute,
	}); !errors.Is(err, secretprovider.ErrProviderUnavailable) {
		t.Fatalf("AcquireHandle err = %v, want ErrProviderUnavailable", err)
	}
}

func TestSecretDerivedMaterialIsUniquePerHandleAndNotMaster(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	redeemOnce := func() string {
		h := acquire(t, provider, secretprovider.AcquireRequest{
			CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: time.Minute,
		})
		secret, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
			CallerToken: testCallerToken, HandleID: h.ID(), Scope: testScope(),
		})
		if err != nil {
			t.Fatalf("Redeem: %v", err)
		}
		return secret.Reveal()
	}
	m1, m2 := redeemOnce(), redeemOnce()
	// HKDF-SHA256 output at 32 bytes renders to 64 lowercase hex characters.
	if len(m1) != 64 {
		t.Fatalf("material length = %d, want 64 hex characters", len(m1))
	}
	for _, r := range m1 {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("material is not lowercase hex: %q", m1)
		}
	}
	if m1 == m2 {
		t.Fatal("distinct handles produced identical material; the per-handle nonce is not bound")
	}
	if m1 == masterCanary || strings.Contains(m1, masterCanary) {
		t.Fatal("derived material is (or contains) the master credential")
	}
}

func TestSecretAcquireRejectsFullyRevokedCredential(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: time.Minute,
	})
	if err := provider.Revoke(testCredential, handle.Version()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// The credential still exists but has no live version: distinct from unknown.
	_, err := provider.AcquireHandle(context.Background(), secretprovider.AcquireRequest{
		CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: time.Minute,
	})
	if !errors.Is(err, secretprovider.ErrRevokedVersion) {
		t.Fatalf("AcquireHandle on fully-revoked credential err = %v, want ErrRevokedVersion", err)
	}
}

func TestSecretAcquireRejectsMalformedScopeOrCredentialRef(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	base := secretprovider.AcquireRequest{
		CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: time.Minute,
	}
	cases := []struct {
		name   string
		mutate func(*secretprovider.AcquireRequest)
	}{
		{"empty scope", func(r *secretprovider.AcquireRequest) { r.Scope = secretprovider.Scope{} }},
		{"slash in connector ref", func(r *secretprovider.AcquireRequest) { r.Scope.ConnectorRef = "tenant/connector" }},
		{"nul in operation", func(r *secretprovider.AcquireRequest) { r.Scope.Operation = "search\x00" }},
		{"slash in credential ref", func(r *secretprovider.AcquireRequest) { r.CredentialRef = "secret://x/y" }},
		{"nul in credential ref", func(r *secretprovider.AcquireRequest) { r.CredentialRef = "secret:x\x00y" }},
		{"zero ttl", func(r *secretprovider.AcquireRequest) { r.TTL = 0 }},
	}
	for _, tc := range cases {
		req := base
		tc.mutate(&req)
		if _, err := provider.AcquireHandle(context.Background(), req); !errors.Is(err, secretprovider.ErrInvalidRequest) {
			t.Fatalf("%s: AcquireHandle err = %v, want ErrInvalidRequest", tc.name, err)
		}
	}
}

func TestSecretRedeemRejectsForgedHandleID(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	_, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken,
		HandleID:    "forged-handle-id-never-issued",
		Scope:       testScope(),
	})
	if !errors.Is(err, secretprovider.ErrInvalidHandle) {
		t.Fatalf("Redeem forged handle err = %v, want ErrInvalidHandle", err)
	}
}

func TestSecretConcurrentSingleUseRedeemConsumesExactlyOnce(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	provider := newSeededProvider(t, now)
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: time.Minute, SingleUse: true,
	})
	const workers = 8
	var wg sync.WaitGroup
	var success, consumed int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
				CallerToken: testCallerToken, HandleID: handle.ID(), Scope: testScope(),
			})
			switch {
			case err == nil:
				atomic.AddInt64(&success, 1)
			case errors.Is(err, secretprovider.ErrHandleConsumed):
				atomic.AddInt64(&consumed, 1)
			default:
				t.Errorf("unexpected concurrent redeem err: %v", err)
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("single-use handle redeemed %d times, want exactly 1", success)
	}
	if consumed != workers-1 {
		t.Fatalf("consumed rejections = %d, want %d", consumed, workers-1)
	}
}

func TestSecretHandleStoreReclaimsExpiredHandles(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	clock := &steppableClock{at: now}
	provider := secretprovider.NewLocalProvider(
		secretprovider.WithCallerToken(testCallerToken),
		secretprovider.WithClock(clock.now),
	)
	if _, err := provider.SetMaster(testCredential, masterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	// Acquire many short-lived handles that are never redeemed (the wired
	// connector runtime path only acquires).
	for i := 0; i < 25; i++ {
		acquire(t, provider, secretprovider.AcquireRequest{
			CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: 30 * time.Second,
		})
	}
	if got := provider.OutstandingHandles(); got != 25 {
		t.Fatalf("outstanding = %d, want 25", got)
	}
	// Advance past the TTL; the next acquire sweeps every expired record.
	clock.at = now.Add(31 * time.Second)
	acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: 30 * time.Second,
	})
	if got := provider.OutstandingHandles(); got != 1 {
		t.Fatalf("after sweep outstanding = %d, want 1 (only the live handle)", got)
	}
}

func TestSecretSingleUseConsumptionDropsMaterialAndReclaims(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	clock := &steppableClock{at: now}
	provider := secretprovider.NewLocalProvider(
		secretprovider.WithCallerToken(testCallerToken),
		secretprovider.WithClock(clock.now),
	)
	if _, err := provider.SetMaster(testCredential, masterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	handle := acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: 30 * time.Second, SingleUse: true,
	})
	if _, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: handle.ID(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	// The consumed tombstone still reports consumed on replay (material dropped).
	if _, err := provider.Redeem(context.Background(), secretprovider.RedeemRequest{
		CallerToken: testCallerToken, HandleID: handle.ID(), Scope: testScope(),
	}); !errors.Is(err, secretprovider.ErrHandleConsumed) {
		t.Fatalf("replay err = %v, want ErrHandleConsumed", err)
	}
	// After the TTL a fresh acquire reclaims the consumed tombstone.
	clock.at = now.Add(31 * time.Second)
	acquire(t, provider, secretprovider.AcquireRequest{
		CallerToken: testCallerToken, Scope: testScope(), CredentialRef: testCredential, TTL: 30 * time.Second,
	})
	if got := provider.OutstandingHandles(); got != 1 {
		t.Fatalf("after reclaim outstanding = %d, want 1", got)
	}
}

// steppableClock is a mutable test clock.
type steppableClock struct{ at time.Time }

func (c *steppableClock) now() time.Time { return c.at }
