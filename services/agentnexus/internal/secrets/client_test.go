package secrets_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

// masterCanary is a seeded plaintext master credential. The whole point of the
// Secret Handle contract is that this value never reaches a manifest, the
// process environment, a log line, a connector RPC payload or an audit record.
const masterCanary = "MASTER-CANARY-DO-NOT-LEAK-secrets-9d3e"

const (
	callerToken = "local-authenticated-caller-token"
	// Credential references are delimiter/control-char-free (canonical rejects
	// '/' and control bytes), so a ':'-separated reference is used.
	credentialRef  = "secret:knowledge_demo:http-token"
	rotatedCanary  = "ROTATED-MASTER-CANARY-secrets-11ac"
	foreignConnRef = "attacker_connector"
)

func scopeFor(connectorRef string) secretprovider.Scope {
	return secretprovider.Scope{
		ConnectorRef: connectorRef,
		Resource:     "documents",
		Operation:    "search",
		Action:       "read",
	}
}

func seededProvider(t *testing.T) *secretprovider.LocalProvider {
	t.Helper()
	provider := secretprovider.NewLocalProvider(secretprovider.WithCallerToken(callerToken))
	if _, err := provider.SetMaster(credentialRef, masterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	return provider
}

func TestSecretClientAcquiresScopedHandleAndRedeems(t *testing.T) {
	client := secrets.NewClient(seededProvider(t), callerToken)

	handle, err := client.AcquireHandle(context.Background(), scopeFor("knowledge_demo"), credentialRef)
	if err != nil {
		t.Fatalf("AcquireHandle: %v", err)
	}
	if handle.Scope() != scopeFor("knowledge_demo") {
		t.Fatalf("handle scope = %+v", handle.Scope())
	}
	secret, err := client.Redeem(context.Background(), handle, scopeFor("knowledge_demo"))
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if secret.Reveal() == "" || secret.Reveal() == masterCanary {
		t.Fatal("redeemed material is empty or is the master credential")
	}
}

// TestSecretHandleCanaryNeverLeaksToAnySink is the load-bearing no-leak test: a
// seeded master credential must be absent from every sink the binding contract
// names — manifest, environment, logs, connector RPC payload and audit record.
func TestSecretHandleCanaryNeverLeaksToAnySink(t *testing.T) {
	provider := seededProvider(t)
	client := secrets.NewClient(provider, callerToken)
	scope := scopeFor("knowledge_demo")

	handle, err := client.AcquireHandle(context.Background(), scope, credentialRef)
	if err != nil {
		t.Fatalf("AcquireHandle: %v", err)
	}
	secret, err := client.Redeem(context.Background(), handle, scope)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	// Sink 1: connector manifest — carries only an opaque credential reference.
	manifest := connector.Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "knowledge_demo",
		Version:       "0.1.0",
		Credentials:   []connector.Credential{{Name: "http", CredentialRef: credentialRef}},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	assertNoCanary(t, "manifest", string(manifestJSON))

	// Sink 2: process environment.
	for _, kv := range os.Environ() {
		assertNoCanary(t, "environment", kv)
	}

	// Sink 3: logs. Emit the handle, the redacted secret and an audit line.
	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	logger.Printf("acquired handle=%v secret=%v", handle, secret)
	logger.Printf("handle detail=%+v", handle)
	assertNoCanary(t, "log", logs.String())

	// Sink 4: connector RPC payload — the handle is what crosses the wire to a
	// connector; it must serialize without any master material.
	handleRPC, err := json.Marshal(handle)
	if err != nil {
		t.Fatalf("Marshal handle: %v", err)
	}
	assertNoCanary(t, "connector_rpc", string(handleRPC))

	// Neither the master NOR the derived redeemed material may appear in the log
	// or connector-RPC sinks: the handle carries no material and the Secret
	// redacts itself, so only an explicit Reveal ever exposes it.
	material := secret.Reveal()
	if strings.Contains(logs.String(), material) {
		t.Fatalf("log sink leaked derived material")
	}
	if strings.Contains(string(handleRPC), material) {
		t.Fatalf("connector RPC sink leaked derived material")
	}

	// Sink 5: audit record built from non-secret handle facts.
	auditJSON, err := json.Marshal(map[string]any{
		"handle_id":      handle.ID(),
		"handle_version": handle.Version(),
		"handle_scope":   handle.Scope().String(),
		"single_use":     handle.SingleUse(),
		"expires_at":     handle.ExpiresAt(),
	})
	if err != nil {
		t.Fatalf("Marshal audit: %v", err)
	}
	assertNoCanary(t, "audit", string(auditJSON))

	// Control: the derived material really is usable and really is not the master.
	if material == "" || strings.Contains(material, masterCanary) {
		t.Fatalf("redeemed material invalid: leaks=%v", strings.Contains(material, masterCanary))
	}
}

func TestSecretClientProductionReadinessFailsClosedWhenProviderUnavailable(t *testing.T) {
	client := secrets.NewClient(secretprovider.UnavailableProvider(), callerToken)

	if err := client.CheckReady(context.Background()); !errors.Is(err, secretprovider.ErrProviderUnavailable) {
		t.Fatalf("CheckReady err = %v, want ErrProviderUnavailable", err)
	}
	// No plaintext or cached-master fallback: acquisition also fails closed.
	if _, err := client.AcquireHandle(context.Background(), scopeFor("knowledge_demo"), credentialRef); !errors.Is(err, secretprovider.ErrProviderUnavailable) {
		t.Fatalf("AcquireHandle err = %v, want ErrProviderUnavailable", err)
	}
}

func TestSecretClientProductionReadinessFailsClosedWhenProviderMissing(t *testing.T) {
	client := secrets.NewClient(nil, callerToken)
	if err := client.CheckReady(context.Background()); !errors.Is(err, secretprovider.ErrProviderUnavailable) {
		t.Fatalf("CheckReady err = %v, want ErrProviderUnavailable", err)
	}
}

func TestSecretClientProductionReadinessPassesWhenProviderHealthy(t *testing.T) {
	client := secrets.NewClient(seededProvider(t), callerToken)
	if err := client.CheckReady(context.Background()); err != nil {
		t.Fatalf("CheckReady err = %v, want nil", err)
	}
}

func TestSecretClientRejectsConnectorIdentityMismatch(t *testing.T) {
	client := secrets.NewClient(seededProvider(t), callerToken)
	handle, err := client.AcquireHandle(context.Background(), scopeFor("knowledge_demo"), credentialRef)
	if err != nil {
		t.Fatalf("AcquireHandle: %v", err)
	}
	_, err = client.Redeem(context.Background(), handle, scopeFor(foreignConnRef))
	if !errors.Is(err, secretprovider.ErrScopeMismatch) {
		t.Fatalf("Redeem err = %v, want ErrScopeMismatch", err)
	}
}

func TestSecretClientSingleUseHandleRejectsReplay(t *testing.T) {
	client := secrets.NewClient(seededProvider(t), callerToken, secrets.WithSingleUse(true))
	scope := scopeFor("knowledge_demo")
	handle, err := client.AcquireHandle(context.Background(), scope, credentialRef)
	if err != nil {
		t.Fatalf("AcquireHandle: %v", err)
	}
	if _, err := client.Redeem(context.Background(), handle, scope); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := client.Redeem(context.Background(), handle, scope); !errors.Is(err, secretprovider.ErrHandleConsumed) {
		t.Fatalf("replay redeem err = %v, want ErrHandleConsumed", err)
	}
}

func TestSecretClientRotationInvalidatesOutstandingHandles(t *testing.T) {
	provider := seededProvider(t)
	client := secrets.NewClient(provider, callerToken)
	scope := scopeFor("knowledge_demo")

	old, err := client.AcquireHandle(context.Background(), scope, credentialRef)
	if err != nil {
		t.Fatalf("AcquireHandle: %v", err)
	}
	if _, err := provider.Rotate(credentialRef, rotatedCanary); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := client.Redeem(context.Background(), old, scope); !errors.Is(err, secretprovider.ErrRevokedVersion) {
		t.Fatalf("post-rotation redeem err = %v, want ErrRevokedVersion", err)
	}
	fresh, err := client.AcquireHandle(context.Background(), scope, credentialRef)
	if err != nil {
		t.Fatalf("AcquireHandle after rotate: %v", err)
	}
	if _, err := client.Redeem(context.Background(), fresh, scope); err != nil {
		t.Fatalf("fresh redeem: %v", err)
	}
}

// TestSecretClientAuthenticatedLocalSocketRoundTrip exercises the published
// provider protocol over a real net.Conn transport with caller authentication.
func TestSecretClientAuthenticatedLocalSocketRoundTrip(t *testing.T) {
	backing := seededProvider(t)
	dial := pipeDialer(backing)
	scope := scopeFor("knowledge_demo")

	authed := secrets.NewClient(secrets.NewSocketProvider(dial), callerToken)
	handle, err := authed.AcquireHandle(context.Background(), scope, credentialRef)
	if err != nil {
		t.Fatalf("socket AcquireHandle: %v", err)
	}
	secret, err := authed.Redeem(context.Background(), handle, scope)
	if err != nil {
		t.Fatalf("socket Redeem: %v", err)
	}
	if secret.Reveal() == "" || strings.Contains(secret.Reveal(), masterCanary) {
		t.Fatal("socket redeem material invalid")
	}
	if err := authed.CheckReady(context.Background()); err != nil {
		t.Fatalf("socket CheckReady: %v", err)
	}

	// A wrong caller token is rejected across the same transport.
	unauth := secrets.NewClient(secrets.NewSocketProvider(dial), "wrong-token")
	if _, err := unauth.AcquireHandle(context.Background(), scope, credentialRef); !errors.Is(err, secretprovider.ErrUnauthenticated) {
		t.Fatalf("unauthenticated socket AcquireHandle err = %v, want ErrUnauthenticated", err)
	}
}

func TestSecretSocketRedeemRejectsEmptyMaterialResponse(t *testing.T) {
	// A success-shaped reply with no material must not become an empty Secret.
	client := secrets.NewClient(secrets.NewSocketProvider(cannedResponseDialer("{}\n")), callerToken)
	_, err := client.Redeem(context.Background(), secretprovider.Handle{}, scopeFor("knowledge_demo"))
	if !errors.Is(err, secretprovider.ErrProviderUnavailable) {
		t.Fatalf("Redeem with empty-material response err = %v, want ErrProviderUnavailable", err)
	}
}

func TestSecretSocketServerRejectsOversizedMessage(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- secrets.ServeConn(serverConn, seededProvider(t)) }()

	// A JSON document past the server's read bound must be rejected (decode
	// error), never buffered wholesale and never left to hang.
	oversized := append([]byte(`{"op":"ping","pad":"`), bytes.Repeat([]byte("A"), 2<<20)...)
	oversized = append(oversized, '"', '}')
	go func() {
		_, _ = clientConn.Write(oversized)
		_ = clientConn.Close()
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ServeConn accepted an oversized message")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return on an oversized message (possible hang)")
	}
}

// cannedResponseDialer serves a fixed response after draining the request,
// modelling a malformed or hostile provider for fail-closed tests.
func cannedResponseDialer(response string) secrets.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			_ = json.NewDecoder(serverConn).Decode(new(map[string]any))
			_, _ = io.WriteString(serverConn, response)
		}()
		return clientConn, nil
	}
}

func assertNoCanary(t *testing.T, sink, payload string) {
	t.Helper()
	if strings.Contains(payload, masterCanary) || strings.Contains(payload, rotatedCanary) {
		t.Fatalf("master credential leaked into %s sink: %q", sink, payload)
	}
}

// pipeDialer serves the provider over an in-memory full-duplex connection: it
// exercises the exact wire codec and auth path with no external socket infra.
func pipeDialer(provider secretprovider.Provider) secrets.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() { _ = secrets.ServeConn(serverConn, provider) }()
		return clientConn, nil
	}
}
