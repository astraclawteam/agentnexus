package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

// masterCanary is a value that must NEVER appear in any host request, response,
// result, audit record or serialized grant. Tests scan for it to prove the host
// layer never carries master or derived secret material to a connector.
const masterCanary = "MASTER-CANARY-DO-NOT-LEAK-host-3f9a"

// --- fixtures -------------------------------------------------------------

func schemaDigest(seed string) string {
	sum := sha256.Sum256([]byte("host-test-schema:" + seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// testPack builds a structurally valid Product Pack whose content digest binds a
// CustomerBinding. The digest is computed with the same helper Task 2 uses, so
// the digest-swap vector exercises the real binding, not a hand-rolled hash.
func testPack() connector.ProductPack {
	p := connector.ProductPack{
		SchemaVersion: connector.ProductPackSchemaVersion,
		ProductKey:    "erp.demo.procurement",
		Version:       "1.4.0",
		Title:         "Demo ERP Procurement",
		Capabilities: []connector.Capability{{
			Name:   "erp.purchase_order.read",
			Title:  "read purchase order",
			Effect: connector.EffectRead,
			Input:  connector.IOSchema{Ref: "schema.erp.purchase_order.read.input", Digest: schemaDigest("in")},
			Output: connector.IOSchema{Ref: "schema.erp.purchase_order.read.output", Digest: schemaDigest("out")},
		}},
		Network: connector.NetworkRequirements{Egress: []string{"connector.api"}, Isolation: "outbound_only"},
		Runtime: connector.RuntimeRequirements{Runtime: "container", MinMemoryMB: 128},
		Limits:  connector.Limits{MaxConcurrency: 4, MaxRequestsPerMinute: 120},
	}
	p.Digest = connector.PackContentDigest(p)
	return p
}

func testBinding(pack connector.ProductPack) connector.CustomerBinding {
	return connector.CustomerBinding{
		SchemaVersion: connector.CustomerBindingSchemaVersion,
		BindingKey:    "acme-erp",
		Customer:      connector.CustomerRef{Name: "acme"},
		Product:       connector.ProductRef{ProductKey: pack.ProductKey, Version: pack.Version, Digest: pack.Digest},
		Endpoints:     []connector.Endpoint{{Name: "erp", URL: "https://erp.acme.example:8443/api"}},
		Secrets:       []connector.SecretRef{{Name: "erp-token", Ref: "secretref://vault/acme/erp"}},
	}
}

func readOperation() Operation {
	return Operation{
		RequestID:  "req-0001",
		Capability: "erp.purchase_order.read",
		Resource:   "purchase_orders",
		Operation:  "read",
		Action:     "read",
		Input:      json.RawMessage(`{"id":"PO-1"}`),
	}
}

// --- stub adapters --------------------------------------------------------

// stubAdapter runs an in-process function so a test can drive any failure mode
// (panic, hang, oversized output, malformed response) deterministically and
// prove the supervisor bounds it. The real process/container adapters are
// exercised separately by the os/exec helper-process tests below.
type stubAdapter struct {
	name string
	fn   func(ctx context.Context, policy Policy, req *HostRequest) (*HostResponse, error)
	mu   sync.Mutex
	last *HostRequest
	runs int
}

func (a *stubAdapter) Name() string {
	if a.name == "" {
		return "stub"
	}
	return a.name
}

func (a *stubAdapter) Dispatch(ctx context.Context, policy Policy, req *HostRequest) (*HostResponse, error) {
	a.mu.Lock()
	a.last = req
	a.runs++
	a.mu.Unlock()
	return a.fn(ctx, policy, req)
}

func (a *stubAdapter) lastRequest() *HostRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
}

// okResponse echoes the input back as a successful connector response.
func okResponse(req *HostRequest) *HostResponse {
	return &HostResponse{
		ProtocolVersion: ProtocolVersion,
		RequestID:       req.RequestID,
		Status:          StatusSucceeded,
		Output:          json.RawMessage(`{"ok":true}`),
	}
}

func newSupervisor(t *testing.T, adapter Adapter, opts ...DeriveOption) *Supervisor {
	t.Helper()
	pack := testPack()
	sup, err := NewSupervisor(Config{
		Pack:    pack,
		Binding: testBinding(pack),
		Adapter: adapter,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	return sup
}

// --- Vector 1: filesystem escape -----------------------------------------

func TestVectorFilesystemEscapeIsDenied(t *testing.T) {
	sandbox := t.TempDir()
	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		return okResponse(req), nil
	}}
	sup := newSupervisor(t, adapter, WithSandboxRoots(sandbox))

	escapes := []struct {
		name string
		path string
	}{
		{"absolute outside sandbox", filepath.Join(pickForeignRoot(), "secret.txt")},
		{"parent traversal", filepath.Join(sandbox, "..", "..", "secret.txt")},
		{"embedded traversal", filepath.Join(sandbox, "sub", "..", "..", "escape.txt")},
	}
	for _, tc := range escapes {
		t.Run(tc.name, func(t *testing.T) {
			op := readOperation()
			op.Filesystem = []FileAccess{{Path: tc.path, Write: true}}
			res := sup.Run(context.Background(), op)
			if res.Status != StatusDeniedPolicy {
				t.Fatalf("status = %v, want StatusDeniedPolicy for path %q", res.Status, tc.path)
			}
			if adapter.lastRequest() != nil {
				t.Fatal("adapter was dispatched despite a filesystem-policy denial; denial must happen before execution")
			}
		})
	}

	// A path inside the sandbox is allowed through to the adapter.
	op := readOperation()
	op.Filesystem = []FileAccess{{Path: filepath.Join(sandbox, "workdir", "out.json"), Write: true}}
	res := sup.Run(context.Background(), op)
	if res.Status != StatusSucceeded {
		t.Fatalf("in-sandbox path status = %v, want StatusSucceeded", res.Status)
	}
}

func TestPolicyAllowPathRejectsEscape(t *testing.T) {
	sandbox := t.TempDir()
	policy, err := DerivePolicy(testPack(), testBinding(testPack()), WithSandboxRoots(sandbox))
	if err != nil {
		t.Fatalf("DerivePolicy: %v", err)
	}
	if err := policy.AllowPath(filepath.Join(sandbox, "ok.txt")); err != nil {
		t.Fatalf("AllowPath in-sandbox = %v, want nil", err)
	}
	if err := policy.AllowPath(filepath.Join(sandbox, "..", "escape.txt")); !errors.Is(err, ErrPathOutsideSandbox) {
		t.Fatalf("AllowPath traversal err = %v, want ErrPathOutsideSandbox", err)
	}
	if err := policy.AllowPath(filepath.Join(pickForeignRoot(), "passwd")); !errors.Is(err, ErrPathOutsideSandbox) {
		t.Fatalf("AllowPath foreign-root err = %v, want ErrPathOutsideSandbox", err)
	}
}

// --- Vector 2: undeclared network target ----------------------------------

func TestVectorUndeclaredNetworkTargetIsDenied(t *testing.T) {
	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		return okResponse(req), nil
	}}
	sup := newSupervisor(t, adapter)

	op := readOperation()
	op.Network = []NetworkTarget{{Host: "evil.example", Port: 443}}
	res := sup.Run(context.Background(), op)
	if res.Status != StatusDeniedPolicy {
		t.Fatalf("status = %v, want StatusDeniedPolicy for undeclared egress", res.Status)
	}
	if adapter.lastRequest() != nil {
		t.Fatal("adapter dispatched despite an egress denial")
	}

	// The concrete allowed target comes from the binding endpoint.
	op = readOperation()
	op.Network = []NetworkTarget{{Host: "erp.acme.example", Port: 8443}}
	res = sup.Run(context.Background(), op)
	if res.Status != StatusSucceeded {
		t.Fatalf("declared endpoint status = %v, want StatusSucceeded", res.Status)
	}
}

func TestPolicyEgressComesFromBinding(t *testing.T) {
	pack := testPack()
	policy, err := DerivePolicy(pack, testBinding(pack))
	if err != nil {
		t.Fatalf("DerivePolicy: %v", err)
	}
	if err := policy.AllowEgress("erp.acme.example", 8443); err != nil {
		t.Fatalf("AllowEgress binding endpoint = %v, want nil", err)
	}
	if err := policy.AllowEgress("erp.acme.example", 443); !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("AllowEgress wrong port err = %v, want ErrEgressNotAllowed", err)
	}
	if err := policy.AllowEgress("attacker.example", 8443); !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("AllowEgress foreign host err = %v, want ErrEgressNotAllowed", err)
	}
}

// --- Vector 3: excess cpu/memory/time -------------------------------------

func TestVectorWallClockBudgetIsBounded(t *testing.T) {
	// A connector that never returns is terminated at the wall-clock budget and
	// reported as a bounded resource failure — never a hang.
	adapter := &stubAdapter{fn: func(ctx context.Context, _ Policy, _ *HostRequest) (*HostResponse, error) {
		<-ctx.Done() // honor cancellation like a real adapter
		return nil, ctx.Err()
	}}
	sup := newSupervisor(t, adapter, WithWallClock(150*time.Millisecond))

	done := make(chan Result, 1)
	go func() { done <- sup.Run(context.Background(), readOperation()) }()

	select {
	case res := <-done:
		if res.Status != StatusResourceExhausted {
			t.Fatalf("status = %v, want StatusResourceExhausted on wall-clock kill", res.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor hung past the wall-clock budget instead of returning a bounded result")
	}
}

func TestPolicyDerivesMemoryBudgetFromPack(t *testing.T) {
	pack := testPack()
	policy, err := DerivePolicy(pack, testBinding(pack))
	if err != nil {
		t.Fatalf("DerivePolicy: %v", err)
	}
	if policy.MemoryBytes <= 0 {
		t.Fatalf("MemoryBytes = %d, want a positive host-enforced ceiling", policy.MemoryBytes)
	}
	// The pack's MinMemoryMB is a floor; the derived ceiling must be at least it.
	if policy.MemoryBytes < int64(pack.Runtime.MinMemoryMB)*1024*1024 {
		t.Fatalf("MemoryBytes = %d, want >= pack floor %d MiB", policy.MemoryBytes, pack.Runtime.MinMemoryMB)
	}
	if policy.WallClock <= 0 || policy.CPUBudget <= 0 {
		t.Fatalf("WallClock=%v CPUBudget=%v, want positive host-enforced budgets", policy.WallClock, policy.CPUBudget)
	}
}

// --- Vector 5: secret handle reuse ----------------------------------------

func TestVectorSecretHandleReuseIsRejected(t *testing.T) {
	const callerToken = "host-local-caller-token"
	const credRef = "secret:acme:erp-token"
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	provider := secretprovider.NewLocalProvider(
		secretprovider.WithCallerToken(callerToken),
		secretprovider.WithClock(clock),
	)
	if _, err := provider.SetMaster(credRef, masterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	client := secrets.NewClient(provider, callerToken, secrets.WithSingleUse(true), secrets.WithHandleTTL(2*time.Minute))
	ctx := context.Background()
	scope := secretprovider.Scope{ConnectorRef: "acme", Resource: "purchase_orders", Operation: "read", Action: "read"}

	// The host acquires an operation-scoped, single-use handle. The connector
	// redeems it exactly once.
	handle, err := client.AcquireHandle(ctx, scope, credRef)
	if err != nil {
		t.Fatalf("AcquireHandle: %v", err)
	}
	secret, err := client.Redeem(ctx, handle, scope)
	if err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	if secret.Reveal() == "" || secret.Reveal() == masterCanary {
		t.Fatal("redeemed material must be non-empty derived material, never the master")
	}
	// Reuse of the consumed single-use handle is rejected.
	if _, err := client.Redeem(ctx, handle, scope); !errors.Is(err, secretprovider.ErrHandleConsumed) {
		t.Fatalf("reuse err = %v, want ErrHandleConsumed", err)
	}

	// A handle redeemed under a different scope is rejected.
	handle2, err := client.AcquireHandle(ctx, scope, credRef)
	if err != nil {
		t.Fatalf("AcquireHandle 2: %v", err)
	}
	wrongScope := secretprovider.Scope{ConnectorRef: "acme", Resource: "purchase_orders", Operation: "write", Action: "write"}
	if _, err := client.Redeem(ctx, handle2, wrongScope); !errors.Is(err, secretprovider.ErrScopeMismatch) {
		t.Fatalf("wrong-scope err = %v, want ErrScopeMismatch", err)
	}

	// A handle redeemed after its TTL is rejected.
	handle3, err := client.AcquireHandle(ctx, scope, credRef)
	if err != nil {
		t.Fatalf("AcquireHandle 3: %v", err)
	}
	advance(3 * time.Minute)
	if _, err := client.Redeem(ctx, handle3, scope); !errors.Is(err, secretprovider.ErrHandleExpired) {
		t.Fatalf("expired err = %v, want ErrHandleExpired", err)
	}

	// The host-facing grant carries only non-secret handle metadata.
	grant := SecretGrantFromHandle(handle)
	encoded, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	if strings.Contains(string(encoded), masterCanary) || strings.Contains(string(encoded), secret.Reveal()) {
		t.Fatalf("secret grant leaked material: %s", encoded)
	}
}

// recordingBroker acquires real handles from a client and records every handle
// id, so a test can prove the host acquires a fresh handle per operation and
// never re-presents a consumed one.
type recordingBroker struct {
	client *secrets.Client
	mu     sync.Mutex
	ids    []string
}

func (b *recordingBroker) AcquireHandle(ctx context.Context, scope secretprovider.Scope, credentialRef string) (secretprovider.Handle, error) {
	h, err := b.client.AcquireHandle(ctx, scope, credentialRef)
	if err == nil {
		b.mu.Lock()
		b.ids = append(b.ids, h.ID())
		b.mu.Unlock()
	}
	return h, err
}

func TestSupervisorAcquiresFreshHandlePerOperation(t *testing.T) {
	const callerToken = "host-local-caller-token"
	const credRef = "secret:acme:erp-token"
	provider := secretprovider.NewLocalProvider(secretprovider.WithCallerToken(callerToken))
	if _, err := provider.SetMaster(credRef, masterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	broker := &recordingBroker{client: secrets.NewClient(provider, callerToken)}

	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		// The connector receives only the safe grant — never any material.
		if req.Secret == nil || req.Secret.HandleID == "" {
			return nil, errors.New("missing secret grant")
		}
		blob, _ := json.Marshal(req)
		if strings.Contains(string(blob), masterCanary) {
			return nil, errors.New("request leaked master")
		}
		return okResponse(req), nil
	}}
	pack := testPack()
	sup, err := NewSupervisor(Config{Pack: pack, Binding: testBinding(pack), Adapter: adapter, Secrets: broker})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	op := readOperation()
	op.CredentialRef = credRef
	for i := 0; i < 2; i++ {
		res := sup.Run(context.Background(), op)
		if res.Status != StatusSucceeded {
			t.Fatalf("run %d status = %v (reason %q), want StatusSucceeded", i, res.Status, res.Reason)
		}
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if len(broker.ids) != 2 {
		t.Fatalf("acquired %d handles, want 2 (one fresh handle per operation)", len(broker.ids))
	}
	if broker.ids[0] == broker.ids[1] {
		t.Fatalf("host re-presented the same handle id %q across operations", broker.ids[0])
	}
}

func TestSupervisorFailsClosedWhenSecretBrokerUnavailable(t *testing.T) {
	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		return okResponse(req), nil
	}}
	sup := newSupervisor(t, adapter) // no Secrets configured

	op := readOperation()
	op.CredentialRef = "secret:acme:erp-token"
	res := sup.Run(context.Background(), op)
	if res.Status != StatusFailed {
		t.Fatalf("status = %v, want StatusFailed (fail closed without a secret broker)", res.Status)
	}
	if adapter.lastRequest() != nil {
		t.Fatal("adapter dispatched though the credential could not be resolved; must fail closed")
	}
}

// --- Vector 6: malformed rpc ----------------------------------------------

func TestVectorMalformedRPCIsBounded(t *testing.T) {
	t.Run("garbage envelope", func(t *testing.T) {
		if _, err := DecodeHostRequest([]byte("this is not json {{{")); err == nil {
			t.Fatal("DecodeHostRequest accepted garbage, want a bounded error")
		}
	})
	t.Run("oversized envelope is rejected without unbounded allocation", func(t *testing.T) {
		huge := make([]byte, MaxRequestBytes+4096)
		for i := range huge {
			huge[i] = 'a'
		}
		if _, err := DecodeHostRequest(huge); !errors.Is(err, ErrEnvelopeTooLarge) {
			t.Fatalf("DecodeHostRequest oversized err = %v, want ErrEnvelopeTooLarge", err)
		}
	})
	t.Run("wrong protocol version", func(t *testing.T) {
		req := &HostRequest{ProtocolVersion: "connector.host/v999", RequestID: "x"}
		if err := req.Validate(); !errors.Is(err, ErrProtocolVersion) {
			t.Fatalf("Validate wrong version err = %v, want ErrProtocolVersion", err)
		}
	})
	t.Run("connector returns malformed response", func(t *testing.T) {
		adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, _ *HostRequest) (*HostResponse, error) {
			return &HostResponse{ProtocolVersion: "bogus/v0", Status: StatusSucceeded}, nil
		}}
		sup := newSupervisor(t, adapter)
		res := sup.Run(context.Background(), readOperation())
		if res.Status != StatusFailed {
			t.Fatalf("status = %v, want StatusFailed for a malformed connector response", res.Status)
		}
	})
}

// --- Vector 7: oversized output -------------------------------------------

func TestVectorOversizedOutputIsBounded(t *testing.T) {
	const cap = 1024
	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		return &HostResponse{
			ProtocolVersion: ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          StatusSucceeded,
			Output:          json.RawMessage(strings.Repeat("A", cap*8)),
		}, nil
	}}
	sup := newSupervisor(t, adapter, WithMaxOutputBytes(cap))

	res := sup.Run(context.Background(), readOperation())
	if res.Status != StatusResourceExhausted {
		t.Fatalf("status = %v, want StatusResourceExhausted for oversized output", res.Status)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true for oversized output")
	}
	if len(res.Output) > cap {
		t.Fatalf("output len = %d, want <= cap %d (must be truncated, never buffered whole)", len(res.Output), cap)
	}
}

// --- Vector 8: package digest swap ----------------------------------------

func TestVectorPackageDigestSwapIsRefused(t *testing.T) {
	pack := testPack()
	binding := testBinding(pack)

	// Swap the pack content after the binding pinned its digest.
	swapped := pack
	swapped.Version = "9.9.9-tampered"
	swapped.Digest = connector.PackContentDigest(swapped)

	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		return okResponse(req), nil
	}}
	_, err := NewSupervisor(Config{Pack: swapped, Binding: binding, Adapter: adapter})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("NewSupervisor with swapped pack err = %v, want ErrDigestMismatch (refused before execution)", err)
	}

	// DerivePolicy refuses the same swap directly.
	if _, err := DerivePolicy(swapped, binding); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("DerivePolicy swapped err = %v, want ErrDigestMismatch", err)
	}
	// The pinned pack derives cleanly and carries the pinned digest.
	policy, err := DerivePolicy(pack, binding)
	if err != nil {
		t.Fatalf("DerivePolicy pinned = %v, want nil", err)
	}
	if policy.ExpectedDigest != binding.Product.Digest {
		t.Fatalf("ExpectedDigest = %q, want pinned %q", policy.ExpectedDigest, binding.Product.Digest)
	}
}

// --- crash isolation invariant --------------------------------------------

func TestSupervisorRecoversConnectorPanicAndStaysAlive(t *testing.T) {
	calls := 0
	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		calls++
		if calls == 1 {
			panic("connector blew up")
		}
		return okResponse(req), nil
	}}
	sup := newSupervisor(t, adapter)

	// First operation panics inside the connector: the supervisor recovers it
	// into a bounded failed result and does not crash.
	res := sup.Run(context.Background(), readOperation())
	if res.Status != StatusFailed {
		t.Fatalf("panicking connector status = %v, want StatusFailed", res.Status)
	}
	if strings.Contains(strings.ToLower(res.Reason), "panic") == false {
		t.Fatalf("reason = %q, want it to record the recovered panic", res.Reason)
	}

	// The supervisor is still alive and runs the next operation to success.
	res = sup.Run(context.Background(), readOperation())
	if res.Status != StatusSucceeded {
		t.Fatalf("post-panic status = %v, want StatusSucceeded (supervisor stayed alive)", res.Status)
	}
}

func TestSupervisorRunNeverReturnsSecretsInResult(t *testing.T) {
	adapter := &stubAdapter{fn: func(_ context.Context, _ Policy, req *HostRequest) (*HostResponse, error) {
		return okResponse(req), nil
	}}
	sup := newSupervisor(t, adapter)
	res := sup.Run(context.Background(), readOperation())
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), masterCanary) {
		t.Fatalf("result leaked master canary: %s", blob)
	}
}

// --- container adapter spec correctness -----------------------------------
//
// Real container execution (Linux namespaces, Windows Appliance container) is
// deferred to CI/release; this box has no container runtime. These fixtures
// assert the SPEC the container adapter derives from the same manifest policy is
// correct: read-only rootfs, dropped caps, no-new-privileges, restricted network
// to allowed egress, only allowed FS roots mounted, resource limits present, and
// the package digest pinned.

func TestContainerAdapterSpecEnforcesPolicy(t *testing.T) {
	sandbox := t.TempDir()
	pack := testPack()
	policy, err := DerivePolicy(pack, testBinding(pack), WithSandboxRoots(sandbox))
	if err != nil {
		t.Fatalf("DerivePolicy: %v", err)
	}
	adapter := &ContainerAdapter{Image: "registry.internal/erp-connector@" + policy.ExpectedDigest, Runtime: "container"}
	spec := adapter.Spec(policy, buildRequest(t, policy, readOperation()))

	if !spec.ReadOnlyRootfs {
		t.Error("ReadOnlyRootfs = false, want true")
	}
	if !spec.NoNewPrivileges {
		t.Error("NoNewPrivileges = false, want true")
	}
	if !spec.ContainProcesses {
		t.Error("ContainProcesses = false, want true (PID namespace containment)")
	}
	if !containsString(spec.DroppedCapabilities, "ALL") {
		t.Errorf("DroppedCapabilities = %v, want it to drop ALL", spec.DroppedCapabilities)
	}
	if spec.PackageDigest != policy.ExpectedDigest {
		t.Errorf("PackageDigest = %q, want pinned %q", spec.PackageDigest, policy.ExpectedDigest)
	}
	if spec.Resources.MemoryBytes != policy.MemoryBytes {
		t.Errorf("Resources.MemoryBytes = %d, want %d", spec.Resources.MemoryBytes, policy.MemoryBytes)
	}
	if spec.Resources.WallClock != policy.WallClock {
		t.Errorf("Resources.WallClock = %v, want %v", spec.Resources.WallClock, policy.WallClock)
	}
	if spec.Resources.PidsLimit <= 0 {
		t.Errorf("Resources.PidsLimit = %d, want a positive bound", spec.Resources.PidsLimit)
	}
	// Network is restricted to exactly the policy's allowed egress.
	if len(spec.Network.AllowedEgress) != len(policy.Egress) {
		t.Fatalf("Network.AllowedEgress = %v, want %v", spec.Network.AllowedEgress, policy.Egress)
	}
	for i, rule := range policy.Egress {
		if spec.Network.AllowedEgress[i] != rule {
			t.Errorf("Network.AllowedEgress[%d] = %v, want %v", i, spec.Network.AllowedEgress[i], rule)
		}
	}
	if spec.Network.Isolation == "" {
		t.Error("Network.Isolation is empty, want a restricted isolation mode")
	}
	// Only the allowed FS roots are mounted, and they are read-only by default.
	if len(spec.Mounts) == 0 {
		t.Fatal("spec mounts no filesystem roots; the sandbox root must be mounted")
	}
	for _, m := range spec.Mounts {
		if !isUnderAnyRoot(m.Source, policy.FSRoots) {
			t.Errorf("mount source %q is outside the allowed FS roots %v", m.Source, policy.FSRoots)
		}
	}
}

func TestContainerAdapterDispatchFailsClosedWithoutRuntime(t *testing.T) {
	pack := testPack()
	policy, err := DerivePolicy(pack, testBinding(pack), WithSandboxRoots(t.TempDir()))
	if err != nil {
		t.Fatalf("DerivePolicy: %v", err)
	}
	adapter := &ContainerAdapter{Image: "registry.internal/erp@" + policy.ExpectedDigest, Runtime: "container"}
	_, derr := adapter.Dispatch(context.Background(), policy, buildRequest(t, policy, readOperation()))
	if !errors.Is(derr, ErrContainerRuntimeUnavailable) {
		t.Fatalf("Dispatch err = %v, want ErrContainerRuntimeUnavailable (no runtime on this box)", derr)
	}

	// Under the supervisor, the same unavailable runtime is a bounded failure,
	// never a crash.
	sup, err := NewSupervisor(Config{Pack: pack, Binding: testBinding(pack), Adapter: adapter, Options: []DeriveOption{WithSandboxRoots(t.TempDir())}})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	res := sup.Run(context.Background(), readOperation())
	if res.Status != StatusFailed {
		t.Fatalf("container-runtime-unavailable status = %v, want StatusFailed", res.Status)
	}
}

// --- process adapter: real child-process enforcement ----------------------
//
// These exercise the real os/exec process adapter to prove OS-level bounds that
// an in-process stub cannot: a real hang is killed at the wall-clock budget, and
// a real child that spawns a grandchild leaves no orphan behind (Vector 4).

func TestProcessAdapterRoundTrip(t *testing.T) {
	adapter := helperProcessAdapter("echo")
	policy := helperPolicy(t)
	req := buildRequest(t, policy, readOperation())

	resp, err := adapter.Dispatch(context.Background(), policy, req)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if resp.Status != StatusSucceeded {
		t.Fatalf("status = %v, want StatusSucceeded", resp.Status)
	}
	if resp.RequestID != req.RequestID {
		t.Fatalf("response request id = %q, want %q", resp.RequestID, req.RequestID)
	}
}

func TestProcessAdapterKillsHangingConnector(t *testing.T) {
	adapter := helperProcessAdapter("hang")
	policy := helperPolicy(t)
	policy.WallClock = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), policy.WallClock)
	defer cancel()

	start := time.Now()
	_, err := adapter.Dispatch(ctx, policy, buildRequest(t, policy, readOperation()))
	if err == nil {
		t.Fatal("Dispatch returned nil error for a hanging connector, want a bounded timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Dispatch took %v, want it bounded near the wall-clock budget", elapsed)
	}
}

func TestProcessAdapterReapsChildProcessTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	adapter := helperProcessAdapter("spawn")
	adapter.Env = append(adapter.Env, "GO_HOST_PIDFILE="+pidFile)
	policy := helperPolicy(t)
	// A generous budget so the connector completes NORMALLY (it spawns the
	// grandchild, responds and exits) rather than racing a deadline. Dispatch
	// returns as soon as the connector exits, so the test stays fast; the point
	// under test is that the orphaned grandchild is reaped once it returns.
	policy.WallClock = 20 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), policy.WallClock)
	defer cancel()
	_, _ = adapter.Dispatch(ctx, policy, buildRequest(t, policy, readOperation()))

	// The grandchild wrote its pid before the connector exited; after Dispatch
	// returns it must have been reaped along with the child.
	assertGrandchildReaped(t, pidFile)
}

func TestProcessAdapterContainsNonCooperativeSpawn(t *testing.T) {
	// A hostile connector spawns a grandchild as its FIRST action, before it ever
	// reads the request. Containment must still reap it. On Windows this relies on
	// suspended-start assignment: the child cannot run — hence cannot spawn —
	// until it is already inside the job, closing the pre-assignment race.
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	adapter := helperProcessAdapter("spawn-hostile")
	adapter.Env = append(adapter.Env, "GO_HOST_PIDFILE="+pidFile)
	policy := helperPolicy(t)
	policy.WallClock = 20 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), policy.WallClock)
	defer cancel()
	_, _ = adapter.Dispatch(ctx, policy, buildRequest(t, policy, readOperation()))

	assertGrandchildReaped(t, pidFile)
}

func TestProcessAdapterBoundsFirehoseOutput(t *testing.T) {
	// A connector that firehoses stdout must be bounded in host memory and
	// reported as a bounded overflow, never buffered whole. This exercises the
	// real cappedBuffer overflow path in the process adapter.
	adapter := helperProcessAdapter("firehose")
	policy := helperPolicy(t)
	policy.MaxOutputBytes = 4096 // raw guard = ceiling + envelope headroom
	_, err := adapter.Dispatch(context.Background(), policy, buildRequest(t, policy, readOperation()))
	if !errors.Is(err, errOutputOverflow) {
		t.Fatalf("Dispatch err = %v, want errOutputOverflow for a firehose child", err)
	}
}

// assertGrandchildReaped waits for the helper connector to record its
// grandchild's pid, then asserts that pid is no longer alive once the operation
// has ended.
func assertGrandchildReaped(t *testing.T, pidFile string) {
	t.Helper()
	pid := waitForPidFile(t, pidFile)
	if pid <= 0 {
		t.Fatalf("grandchild pid file never populated (%q); cannot prove containment", pidFile)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return // reaped — containment works
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Best-effort cleanup so a failed containment does not leak a process.
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
	t.Fatalf("grandchild pid %d still alive after the operation ended; the process tree was not contained/reaped", pid)
}

// --- helper connector process ---------------------------------------------

// TestHelperConnector is not a real test: when GO_HOST_CONNECTOR_MODE is set the
// test binary re-executes itself as a connector process speaking the host RPC on
// stdin/stdout. This is the standard os/exec helper-process pattern.
func TestHelperConnector(t *testing.T) {
	mode := os.Getenv("GO_HOST_CONNECTOR_MODE")
	if mode == "" {
		return
	}
	runHelperConnector(mode)
	os.Exit(0)
}

func runHelperConnector(mode string) {
	switch mode {
	case "echo":
		raw, _ := readAllStdin()
		req, err := DecodeHostRequest(raw)
		if err != nil {
			os.Exit(3)
		}
		resp := &HostResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Status: StatusSucceeded, Output: json.RawMessage(`{"echo":true}`)}
		out, _ := EncodeHostResponse(resp)
		_, _ = os.Stdout.Write(out)
	case "hang":
		select {} // block forever until killed
	case "firehose":
		blob := strings.Repeat("A", 1<<16)
		for i := 0; i < 64; i++ {
			if _, err := os.Stdout.WriteString(blob); err != nil {
				os.Exit(0)
			}
		}
	case "spawn":
		// Read the request first: the host contains this process before writing
		// stdin, so waiting for stdin guarantees the grandchild is spawned inside
		// the containment (job object / process group).
		raw, _ := readAllStdin()
		req, _ := DecodeHostRequest(raw)
		grandchild := longRunningProcess()
		if err := grandchild.Start(); err == nil && grandchild.Process != nil {
			if pidFile := os.Getenv("GO_HOST_PIDFILE"); pidFile != "" {
				_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", grandchild.Process.Pid)), 0o600)
			}
		}
		// Respond and exit NORMALLY, orphaning the long-running grandchild. The
		// invariant under test is that the host reaps that orphan once the
		// operation ends — no deadline needed, so this stays robust under load.
		rid := "spawn"
		if req != nil {
			rid = req.RequestID
		}
		out, _ := EncodeHostResponse(&HostResponse{ProtocolVersion: ProtocolVersion, RequestID: rid, Status: StatusSucceeded, Output: json.RawMessage(`{"spawned":true}`)})
		_, _ = os.Stdout.Write(out)
	case "spawn-hostile":
		// Spawn the grandchild as the very FIRST action, WITHOUT waiting for
		// stdin. Only suspended-start containment can reap this; assign-after-start
		// would let the grandchild escape the job on Windows.
		grandchild := longRunningProcess()
		if err := grandchild.Start(); err == nil && grandchild.Process != nil {
			if pidFile := os.Getenv("GO_HOST_PIDFILE"); pidFile != "" {
				_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", grandchild.Process.Pid)), 0o600)
			}
		}
		raw, _ := readAllStdin()
		req, _ := DecodeHostRequest(raw)
		rid := "spawn-hostile"
		if req != nil {
			rid = req.RequestID
		}
		out, _ := EncodeHostResponse(&HostResponse{ProtocolVersion: ProtocolVersion, RequestID: rid, Status: StatusSucceeded, Output: json.RawMessage(`{"spawned":true}`)})
		_, _ = os.Stdout.Write(out)
	default:
		os.Exit(0)
	}
}

// longRunningProcess returns a real, long-lived system process to stand in for a
// grandchild the connector spawns. Using a plain system command (not a re-exec
// of the test binary) keeps the containment proof free of test-harness env and
// path fragility.
func longRunningProcess() *exec.Cmd {
	if os.PathSeparator == '\\' {
		// ping -n 60 keeps the process alive ~60s without any external network.
		return exec.Command("ping", "-n", "60", "127.0.0.1")
	}
	return exec.Command("sleep", "60")
}

func readAllStdin() ([]byte, error) {
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return []byte(buf.String()), nil
}

func helperProcessAdapter(mode string) *ProcessAdapter {
	return &ProcessAdapter{
		Command: os.Args[0],
		Args:    []string{"-test.run=^TestHelperConnector$"},
		Env:     append(os.Environ(), "GO_HOST_CONNECTOR_MODE="+mode),
	}
}

func helperPolicy(t *testing.T) Policy {
	t.Helper()
	pack := testPack()
	policy, err := DerivePolicy(pack, testBinding(pack), WithSandboxRoots(t.TempDir()))
	if err != nil {
		t.Fatalf("DerivePolicy: %v", err)
	}
	return policy
}

func buildRequest(t *testing.T, policy Policy, op Operation) *HostRequest {
	t.Helper()
	return &HostRequest{
		ProtocolVersion: ProtocolVersion,
		RequestID:       op.RequestID,
		Capability:      op.Capability,
		Resource:        op.Resource,
		Operation:       op.Operation,
		Action:          op.Action,
		Input:           op.Input,
		MaxOutputBytes:  policy.MaxOutputBytes,
	}
}

func waitForPidFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil && len(raw) > 0 {
			var pid int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &pid); err == nil {
				return pid
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0
}

// --- small helpers --------------------------------------------------------

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func isUnderAnyRoot(path string, roots []string) bool {
	for _, root := range roots {
		if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}

// pickForeignRoot returns an absolute path guaranteed to be outside any temp
// sandbox, for the filesystem-escape vector.
func pickForeignRoot() string {
	if os.PathSeparator == '\\' {
		return `C:\Windows\System32`
	}
	return "/etc"
}
