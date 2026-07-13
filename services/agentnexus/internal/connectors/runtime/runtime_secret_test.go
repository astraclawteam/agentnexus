package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
)

const (
	runtimeMasterCanary  = "MASTER-CANARY-DO-NOT-LEAK-runtime-7c2f"
	runtimeCallerToken   = "runtime-local-caller-token"
	runtimeCredentialRef = "secret:knowledge_demo:http-token"
)

// handleProviderAdapter adapts a secretprovider.Provider to the runtime's
// SecretHandleProvider port, injecting caller authentication and the handle
// lifetime policy, and capturing the scope the runtime derived.
type handleProviderAdapter struct {
	provider  secretprovider.Provider
	token     string
	ttl       time.Duration
	singleUse bool
	lastScope *secretprovider.Scope
}

func (a *handleProviderAdapter) AcquireHandle(ctx context.Context, scope secretprovider.Scope, credentialRef string) (secretprovider.Handle, error) {
	captured := scope
	a.lastScope = &captured
	return a.provider.AcquireHandle(ctx, secretprovider.AcquireRequest{
		CallerToken:   a.token,
		Scope:         scope,
		CredentialRef: credentialRef,
		TTL:           a.ttl,
		SingleUse:     a.singleUse,
	})
}

func seededHandleProvider(t *testing.T) *handleProviderAdapter {
	t.Helper()
	provider := secretprovider.NewLocalProvider(secretprovider.WithCallerToken(runtimeCallerToken))
	if _, err := provider.SetMaster(runtimeCredentialRef, runtimeMasterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	return &handleProviderAdapter{provider: provider, token: runtimeCallerToken, ttl: 90 * time.Second, singleUse: true}
}

func TestSecretRuntimeAcquiresOperationScopedHandle(t *testing.T) {
	adapter := seededHandleProvider(t)
	rt := New(RuntimeConfig{Manifest: testManifest(), SecretHandles: adapter})

	result, err := rt.Execute(context.Background(), Request{
		Resource:      "documents",
		Operation:     "search",
		Action:        ActionRead,
		Fields:        []string{"title"},
		CredentialRef: runtimeCredentialRef,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Audit.CredentialResolved {
		t.Fatal("CredentialResolved = false, want true")
	}
	if adapter.lastScope == nil {
		t.Fatal("runtime acquired no handle")
	}
	want := secretprovider.Scope{ConnectorRef: "knowledge_demo", Resource: "documents", Operation: "search", Action: "read"}
	if *adapter.lastScope != want {
		t.Fatalf("acquired scope = %+v, want %+v", *adapter.lastScope, want)
	}
	if result.Audit.HandleID == "" || result.Audit.HandleVersion == "" {
		t.Fatalf("audit missing handle facts: %+v", result.Audit)
	}
	if result.Audit.HandleScope != want.String() {
		t.Fatalf("audit handle scope = %q, want %q", result.Audit.HandleScope, want.String())
	}
}

func TestSecretRuntimeNeverExposesMasterCredential(t *testing.T) {
	adapter := seededHandleProvider(t)
	rt := New(RuntimeConfig{Manifest: testManifest(), SecretHandles: adapter})

	result, err := rt.Execute(context.Background(), Request{
		Resource:      "documents",
		Operation:     "search",
		Action:        ActionRead,
		Fields:        []string{"title"},
		CredentialRef: runtimeCredentialRef,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal result: %v", err)
	}
	for _, rendered := range []string{fmt.Sprintf("%+v", result), string(encoded)} {
		if strings.Contains(rendered, runtimeMasterCanary) {
			t.Fatalf("runtime result/audit leaked master credential: %q", rendered)
		}
	}
}

func TestSecretRuntimeFailsClosedWhenProviderUnavailable(t *testing.T) {
	adapter := &handleProviderAdapter{
		provider: secretprovider.UnavailableProvider(),
		token:    runtimeCallerToken,
		ttl:      time.Minute,
	}
	rt := New(RuntimeConfig{Manifest: testManifest(), SecretHandles: adapter})

	_, err := rt.Execute(context.Background(), Request{
		Resource:      "documents",
		Operation:     "search",
		Action:        ActionRead,
		Fields:        []string{"title"},
		CredentialRef: runtimeCredentialRef,
	})
	if !errors.Is(err, secretprovider.ErrProviderUnavailable) {
		t.Fatalf("Execute err = %v, want ErrProviderUnavailable (fail closed)", err)
	}
}

func TestSecretRuntimeFailsClosedWhenCredentialRefButNoProvider(t *testing.T) {
	// A request that references a credential while no secret provider (nor the
	// legacy resolver) is wired must fail closed, never proceed unresolved.
	rt := New(RuntimeConfig{Manifest: testManifest()})

	_, err := rt.Execute(context.Background(), Request{
		Resource:      "documents",
		Operation:     "search",
		Action:        ActionRead,
		Fields:        []string{"title"},
		CredentialRef: runtimeCredentialRef,
	})
	if !errors.Is(err, ErrNoSecretProvider) {
		t.Fatalf("Execute err = %v, want ErrNoSecretProvider (fail closed)", err)
	}
}
