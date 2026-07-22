package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

const (
	workerTenant   = "tenant-1"
	workerWorkCase = "wc_0123456789abcdef"
	approveCap     = "erp.purchase_order.approve"
	readCap        = "erp.purchase_order.read"
)

// --- deterministic ids ------------------------------------------------------

func sequentialIDs() func(string) string {
	var mu sync.Mutex
	counters := map[string]int{}
	return func(prefix string) string {
		mu.Lock()
		defer mu.Unlock()
		counters[prefix]++
		return fmt.Sprintf("%s%016d", prefix, counters[prefix])
	}
}

// --- signing fixtures -------------------------------------------------------

func newReceiptSigner(t *testing.T) (*audit.Ed25519AuditSigner, sdkaudit.SigningKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate connector key: %v", err)
	}
	signer, err := audit.NewEd25519AuditSigner("connector-worker-1", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key := sdkaudit.SigningKey{KeyID: "connector-worker-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyActive}
	return signer, key
}

// --- request builders -------------------------------------------------------

func requesterPrincipal() runtime.PrincipalContext {
	now := time.Now().UTC()
	return runtime.PrincipalContext{
		TenantRef: workerTenant, PrincipalRef: "agent-1", AgentClientRef: "agc_client-1", AgentReleaseRef: "rel-1",
		TrustClass: runtime.TrustFirstParty, OrgSnapshotRef: "org-1", VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func testSignature() runtime.Signature {
	return runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "k1", Value: "AAAA"}
}

// actionRequest builds a valid ActionRequest. capability selects the connector;
// needs >0 attaches that many postcondition/verification-need pairs.
func actionRequest(t *testing.T, capability, idem string, needs int) runtime.ActionRequest {
	t.Helper()
	params, hash, err := runtime.BuildParameters(map[string]any{"amount": 100})
	if err != nil {
		t.Fatalf("build parameters: %v", err)
	}
	now := time.Now().UTC()
	req := runtime.ActionRequest{
		RequestID:          "req-" + idem,
		BusinessContextRef: workerWorkCase,
		Capability:         capability,
		Parameters:         params,
		ParameterHash:      hash,
		Purpose:            "execute",
		RiskDecision: runtime.RiskDecision{
			DecisionID: "dec-1", Authority: "acme-risk", RiskLevel: runtime.RiskMedium,
			Capability: capability, ParameterHash: hash, BusinessContextRef: workerWorkCase,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Signature: testSignature(),
		},
		IdempotencyKey:        idem,
		ExpiresAt:             now.Add(30 * time.Minute),
		ExpectedReceiptSchema: "erp.receipt.v1",
	}
	for i := 0; i < needs; i++ {
		pc := fmt.Sprintf("pc%d", i+1)
		nd := fmt.Sprintf("n%d", i+1)
		req.Postconditions = append(req.Postconditions, runtime.PostconditionSpec{PostconditionID: pc, Kind: "state", Reference: "po.field." + pc})
		req.VerificationNeeds = append(req.VerificationNeeds, runtime.VerificationNeed{NeedID: nd, PostconditionID: pc, DataClass: "purchase_order_" + pc})
	}
	return req
}

// --- fakes ------------------------------------------------------------------

// fakeResolver returns a fixed ResolvedBinding and records the (tenant,
// capability) pairs it was asked to resolve, proving the worker never resolves
// from a connector id.
type fakeResolver struct {
	mu        sync.Mutex
	binding   ResolvedBinding
	err       error
	tenants   []string
	caps      []string
	callCount int
}

func (r *fakeResolver) Resolve(_ context.Context, tenantRef, capability string) (ResolvedBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callCount++
	r.tenants = append(r.tenants, tenantRef)
	r.caps = append(r.caps, capability)
	if r.err != nil {
		return ResolvedBinding{}, r.err
	}
	return r.binding, nil
}

// fakeHost is a HostRunner that returns a configured Result and records every
// Operation and its run count (the exactly-once dimension).
type fakeHost struct {
	mu     sync.Mutex
	result host.Result
	ops    []host.Operation
	delay  time.Duration
	// crashFirst makes the FIRST Run record its op (the side effect is attempted)
	// and then panic, simulating a worker process that crashes after dispatch but
	// before it durably applies the result.
	crashFirst bool
}

func (h *fakeHost) Run(_ context.Context, op host.Operation) host.Result {
	h.mu.Lock()
	h.ops = append(h.ops, op)
	runNo := len(h.ops)
	delay := h.delay
	res := h.result
	crash := h.crashFirst && runNo == 1
	h.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if crash {
		panic("connector-worker crashed after dispatch, before durable apply")
	}
	return res
}

func (h *fakeHost) runs() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.ops)
}

func (h *fakeHost) lastOp() (host.Operation, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.ops) == 0 {
		return host.Operation{}, false
	}
	return h.ops[len(h.ops)-1], true
}

func successResult() host.Result {
	out := []byte(`{"ok":true}`)
	sum := sha256.Sum256(out)
	return host.Result{Status: host.StatusSucceeded, Output: out, OutputHash: "sha256:" + hex.EncodeToString(sum[:])}
}

// fakeObservations returns a valid signed ObservationReceipt for each binding
// and records the bindings. failNeeds names verification_need_ids whose Observe
// fails (a deny / detached need), so the worker must not fabricate.
type fakeObservations struct {
	mu        sync.Mutex
	bindings  []runtime.VerificationBinding
	failNeeds map[string]error
	// mismatch makes Observe return a receipt that does NOT bind the requested
	// need (a wrong action_ref), exercising the receipt-binding integrity guard.
	mismatch bool
}

func newFakeObservations() *fakeObservations { return &fakeObservations{failNeeds: map[string]error{}} }

func (o *fakeObservations) Observe(_ context.Context, _ string, binding runtime.VerificationBinding) (runtime.ObservationReceipt, error) {
	o.mu.Lock()
	o.bindings = append(o.bindings, binding)
	failErr := o.failNeeds[binding.VerificationNeedID]
	mismatch := o.mismatch
	o.mu.Unlock()
	if failErr != nil {
		return runtime.ObservationReceipt{}, failErr
	}
	boundActionRef := binding.ActionRef
	if mismatch {
		boundActionRef = "act_mismatchmismatch1" // a receipt for a DIFFERENT action
	}
	now := time.Now().UTC()
	sum := sha256.Sum256([]byte(binding.VerificationNeedID))
	receipt := runtime.ObservationReceipt{
		ObservationRef: "obs_0123456789abcdef", ActionRef: boundActionRef, ParameterHash: binding.ParameterHash,
		PostconditionID: binding.PostconditionID, VerificationNeedID: binding.VerificationNeedID,
		Source: binding.DataClass, SourceVersion: 1, Authority: "system_of_record",
		ObservedAt: now, FreshUntil: now.Add(time.Hour), ObservationHash: "sha256:" + hex.EncodeToString(sum[:]),
		EvidenceRef: "evd_0123456789abcdef", AuditRefID: "aud_obs_1",
		Signature: runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "obs-1", Value: "BBBB"},
	}
	return receipt, nil
}

func (o *fakeObservations) observed() []runtime.VerificationBinding {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]runtime.VerificationBinding(nil), o.bindings...)
}

// recordingPublisher captures DispatchMessages the outbox republishes, so tests
// obtain the exact durable dispatch intent (with its DispatchRef).
type recordingPublisher struct {
	mu   sync.Mutex
	sent []actions.DispatchMessage
}

func (p *recordingPublisher) PublishDispatch(_ context.Context, message actions.DispatchMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, message)
	return nil
}

func (p *recordingPublisher) messages() []actions.DispatchMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]actions.DispatchMessage(nil), p.sent...)
}

// --- fixture ----------------------------------------------------------------

type fixture struct {
	t         *testing.T
	svc       *actions.Service
	store     *actions.MemoryStore
	signer    *audit.Ed25519AuditSigner
	resolver  *fakeResolver
	host      *fakeHost
	obs       *fakeObservations
	worker    *Worker
	publisher *recordingPublisher
	principal runtime.PrincipalContext
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fh := &fakeHost{result: successResult()}
	resolver := &fakeResolver{binding: ResolvedBinding{Host: fh, Resource: "purchase_orders", Operation: "approve", OperationAction: "write", ConnectorRef: "conn_private_instance_9", CredentialRef: "secretref://vault/acme/erp"}}
	f := newFixtureOver(t, resolver)
	f.resolver = resolver
	f.host = fh
	return f
}

// newFixtureOver builds the same fully wired fixture over an arbitrary
// BindingResolver, so a test can drive the REAL PostgresBindingResolver through
// the worker instead of a fake that cannot reproduce its readiness contract.
func newFixtureOver(t *testing.T, resolver BindingResolver) *fixture {
	t.Helper()
	signer, key := newReceiptSigner(t)
	store := actions.NewMemoryStore()
	publisher := &recordingPublisher{}
	svc, err := actions.NewService(store, actions.NewMemoryAuditSink(),
		actions.WithIDGenerator(sequentialIDs()),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(sdkaudit.NewKeySet(key))),
		actions.WithPublisher(publisher),
	)
	if err != nil {
		t.Fatalf("actions.NewService: %v", err)
	}
	obs := newFakeObservations()
	w, err := New(Config{
		Actions: svc, Resolver: resolver, Signer: signer, Observations: obs, Identity: workerIdentity(),
	}, WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}
	return &fixture{t: t, svc: svc, store: store, signer: signer, obs: obs, worker: w, publisher: publisher, principal: requesterPrincipal()}
}

func workerIdentity() Identity {
	return Identity{PrincipalRef: "connector-worker", AgentClientRef: "agc_connector_worker", AgentReleaseRef: "worker-rel-1", OrgSnapshotRef: "org-system"}
}

// dispatch drives request -> grant -> dispatch and returns the (action, message)
// exactly as the durable outbox would publish it.
func (f *fixture) dispatch(req runtime.ActionRequest) (actions.Action, actions.DispatchMessage) {
	f.t.Helper()
	ctx := context.Background()
	action, err := f.svc.RequestAction(ctx, f.principal, req)
	if err != nil {
		f.t.Fatalf("RequestAction: %v", err)
	}
	if _, err := f.svc.Grant(ctx, f.principal, action.ActionRef); err != nil {
		f.t.Fatalf("Grant: %v", err)
	}
	if _, err := f.svc.Dispatch(ctx, f.principal, action.ActionRef); err != nil {
		f.t.Fatalf("Dispatch: %v", err)
	}
	if _, err := f.svc.RepublishPending(ctx, f.principal.TenantRef); err != nil {
		f.t.Fatalf("RepublishPending: %v", err)
	}
	msgs := f.publisher.messages()
	msg := msgs[len(msgs)-1]
	stored, err := f.svc.GetAction(ctx, f.principal, action.ActionRef)
	if err != nil {
		f.t.Fatalf("GetAction: %v", err)
	}
	return stored, msg
}

func (f *fixture) getAction(actionRef string) actions.Action {
	f.t.Helper()
	action, err := f.svc.GetAction(context.Background(), f.principal, actionRef)
	if err != nil {
		f.t.Fatalf("GetAction: %v", err)
	}
	return action
}

// ============================================================================
// readiness
// ============================================================================

func TestWorkerCheckReadyFailsClosedWithoutConcreteDeps(t *testing.T) {
	signer, key := newReceiptSigner(t)
	svc, err := actions.NewService(actions.NewMemoryStore(), actions.NewMemoryAuditSink(),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(sdkaudit.NewKeySet(key))))
	if err != nil {
		t.Fatal(err)
	}
	fh := &fakeHost{result: successResult()}
	resolver := &fakeResolver{binding: ResolvedBinding{Host: fh}}
	obs := newFakeObservations()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"nil resolver", Config{Actions: svc, Signer: signer, Observations: obs, Identity: workerIdentity()}},
		{"nil signer", Config{Actions: svc, Resolver: resolver, Observations: obs, Identity: workerIdentity()}},
		{"nil observations", Config{Actions: svc, Resolver: resolver, Signer: signer, Identity: workerIdentity()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.cfg, WithIDGenerator(sequentialIDs()))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := w.CheckReady(context.Background()); !errors.Is(err, ErrNotReady) {
				t.Fatalf("CheckReady = %v, want ErrNotReady (fail closed, no pass-stub)", err)
			}
		})
	}

	// Fully wired: ready.
	w, err := New(Config{Actions: svc, Resolver: resolver, Signer: signer, Observations: obs, Identity: workerIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.CheckReady(context.Background()); err != nil {
		t.Fatalf("CheckReady with all deps = %v, want ready", err)
	}
}

// countingGate wraps a Worker to count the gate's readiness probes, so a test
// can prove the gate is ALIVE and repeatedly asking rather than infer it from a
// sleep. Everything else (Run) is the real worker.
type countingGate struct {
	*Worker
	mu     sync.Mutex
	checks int
}

func (g *countingGate) CheckReady(ctx context.Context) error {
	g.mu.Lock()
	g.checks++
	g.mu.Unlock()
	return g.Worker.CheckReady(ctx)
}

func (g *countingGate) checkCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checks
}

// TestWorkerWithoutAHostFactoryNeverPullsADispatch closes the poison loop the
// nil HostFactory would open, at the level where it actually manifests.
//
// A PostgresBindingResolver with no HostFactory does the whole resolution and
// then refuses at ErrNoHostFactory, which is TRANSIENT on purpose (see
// PermanentResolutionFailure): a missing host runner is a fact about the
// DEPLOYMENT, and failing durable, executable Actions to report an outage would
// be the worse error. The consequence, left alone, is a worker that naks every
// intent it pulls forever and burns their delivery attempts. The resolution is
// that such a worker is NOT READY, so it never pulls one.
//
// Both directions are asserted against the SAME worker and the SAME dispatch,
// because the zero below only means something if the setup can consume at all:
// with a host factory the gate opens and the message is consumed (naked here,
// because the resolution then fails at the absent database — a genuine transient
// failure, which must still nak), and without one nothing is touched.
func TestWorkerWithoutAHostFactoryNeverPullsADispatch(t *testing.T) {
	pool := undialedPool(t)

	t.Run("no host factory: not ready, and nothing is ever pulled", func(t *testing.T) {
		f := newFixtureOver(t, NewPostgresBindingResolver(pool, nil))
		_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

		// Errorf, not Fatalf: the behavioural assertion below is the one that
		// matters, and it must still run (and fail) when this reason regresses.
		err := f.worker.CheckReady(context.Background())
		if !errors.Is(err, ErrNotReady) || !errors.Is(err, ErrNoHostFactory) {
			t.Errorf("CheckReady = %v, want not-ready naming the missing host factory", err)
		}

		gate := &countingGate{Worker: f.worker}
		src := newFakeSource(msg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = RunWhenReady(ctx, gate, src, time.Millisecond) }()

		// Wait until the gate has re-asked several times — proving it is alive and
		// polling rather than merely slow — or until something is consumed, which
		// is the failure this test exists to catch and must be reported as such.
		waitFor(t, 2*time.Second, func() bool {
			return gate.checkCount() >= 5 || src.ackCount()+src.nakCount() > 0
		})
		if src.ackCount()+src.nakCount() != 0 {
			t.Fatalf("acks=%d naks=%d, want 0: a worker that can resolve nothing must never pull a dispatch, or it naks every one of them forever",
				src.ackCount(), src.nakCount())
		}
	})

	t.Run("host factory wired: the gate opens and the dispatch is consumed", func(t *testing.T) {
		// This factory exists ONLY to flip the readiness bit; it is never invoked,
		// because resolution fails at the (absent) database first. Nothing here
		// stands in for a real connector host — a default or stub host runner in
		// production would execute against real customer systems.
		f := newFixtureOver(t, NewPostgresBindingResolver(pool, &recordingFactory{}))
		_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

		if err := f.worker.CheckReady(context.Background()); err != nil {
			t.Fatalf("CheckReady with a host factory = %v, want ready", err)
		}

		src := newFakeSource(msg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = RunWhenReady(ctx, f.worker, src, time.Millisecond) }()

		// A store outage is transient: the dispatch is naked for redelivery, never
		// failed. Fixing the poison loop must not convert a recoverable blip into a
		// lost Action.
		waitFor(t, 5*time.Second, func() bool { return src.ackCount()+src.nakCount() > 0 })
		if src.nakCount() == 0 || src.ackCount() != 0 {
			t.Fatalf("acks=%d naks=%d, want the unreachable store naked for redelivery", src.ackCount(), src.nakCount())
		}
		// Naked, not failed: the Action is still there to run when the store comes
		// back. Resolution ran before the executing barrier, so nothing executed.
		if got := f.getAction(msg.ActionRef).Status; got != actions.StatusDispatched {
			t.Fatalf("action status = %q, want it to stay dispatched through a store outage", got)
		}
	})
}

func TestWorkerNewRejectsIncompleteIdentity(t *testing.T) {
	signer, _ := newReceiptSigner(t)
	svc, _ := actions.NewService(actions.NewMemoryStore(), actions.NewMemoryAuditSink())
	if _, err := New(Config{Actions: svc, Signer: signer, Identity: Identity{PrincipalRef: "x"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New with partial identity = %v, want ErrInvalidConfig", err)
	}
	if _, err := New(Config{Identity: workerIdentity()}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New without action plane = %v, want ErrInvalidConfig", err)
	}
}

// ============================================================================
// happy path: durable execution -> one authoritative signed ActionReceipt
// ============================================================================

func TestWorkerCompletesDispatchedActionWithVerifiableSignedReceipt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	res, err := f.worker.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %q, want completed", res.Outcome)
	}
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d, want exactly 1", f.host.runs())
	}
	// The action reached the succeeded TECHNICAL terminal status with the receipt.
	final := f.getAction(action.ActionRef)
	if final.Status != actions.StatusSucceeded {
		t.Fatalf("action status = %q, want succeeded", final.Status)
	}
	if res.ActionReceipt == nil || final.ReceiptRef != res.ActionReceipt.ReceiptRef {
		t.Fatalf("action receipt ref = %q, receipt = %+v", final.ReceiptRef, res.ActionReceipt)
	}
	// The produced receipt VERIFIES against the registered connector key (the
	// completion only succeeded because IngestReceipt's SignedReceiptVerifier
	// accepted this worker's signature).
	fetched, err := f.svc.GetReceipt(ctx, f.principal, res.ActionReceipt.ReceiptRef)
	if err != nil {
		t.Fatalf("GetReceipt: %v", err)
	}
	if fetched.Signature == nil {
		t.Fatal("stored receipt is unsigned")
	}
	if fetched.Status != runtime.StatusSucceeded || fetched.ReceiptSchema != action.ExpectedReceiptSchema {
		t.Fatalf("receipt = %+v, want succeeded with the declared schema", fetched)
	}
}

func TestWorkerResolvesPrivateBindingByTenantAndCapabilityOnly(t *testing.T) {
	f := newFixture(t)
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	if _, err := f.worker.ProcessDispatch(context.Background(), msg); err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	// Binding was resolved from tenant + capability, never a connector id.
	if f.resolver.callCount != 1 || f.resolver.tenants[0] != workerTenant || f.resolver.caps[0] != approveCap {
		t.Fatalf("resolver calls tenants=%v caps=%v, want one (%s,%s)", f.resolver.tenants, f.resolver.caps, workerTenant, approveCap)
	}
	// The host operation was built from PRIVATE server-side facts.
	op, ok := f.host.lastOp()
	if !ok || op.Resource != "purchase_orders" || op.Operation != "approve" || op.CredentialRef != "secretref://vault/acme/erp" {
		t.Fatalf("host op = %+v, want the resolved private facts", op)
	}
	// Connector topology never leaks into the Agent-facing ActionReceipt.
	receipt := f.getAction(action.ActionRef).ReceiptRef
	stored, _ := f.svc.GetReceipt(context.Background(), f.principal, receipt)
	if stored.Capability == "conn_private_instance_9" || containsConnectorTopology(stored) {
		t.Fatalf("receipt leaked connector topology: %+v", stored)
	}
}

func containsConnectorTopology(r runtime.ActionReceipt) bool {
	// The ActionReceipt carries no field that could hold a connector instance id,
	// endpoint or path; assert the private connector ref is absent from every
	// string field the worker populated.
	for _, s := range []string{r.ReceiptRef, r.ActionRef, string(r.Status), r.Capability, r.ParameterHash, r.ReceiptSchema, r.ResultHash} {
		if s == "conn_private_instance_9" || s == "purchase_orders" || s == "secretref://vault/acme/erp" {
			return true
		}
	}
	return false
}

// ============================================================================
// exact digest/binding + grant validation
// ============================================================================

func TestWorkerRejectsMismatchedDigestBindingAndGrant(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		mutar func(*actions.DispatchMessage)
	}{
		{"wrong capability", func(m *actions.DispatchMessage) { m.Capability = "erp.invoice.pay" }},
		{"wrong parameter hash", func(m *actions.DispatchMessage) { m.ParameterHash = "sha256:" + hex.EncodeToString(make([]byte, 32)) }},
		{"wrong grant", func(m *actions.DispatchMessage) { m.GrantRef = "grant_forged0000000001" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
			tc.mutar(&msg)
			res, err := f.worker.ProcessDispatch(ctx, msg)
			if err != nil {
				t.Fatalf("ProcessDispatch = %v, want a clean rejection (no transient error)", err)
			}
			if res.Outcome != OutcomeRejected {
				t.Fatalf("outcome = %q, want rejected", res.Outcome)
			}
			if f.host.runs() != 0 {
				t.Fatal("host ran despite a binding mismatch; a rejected dispatch must never execute")
			}
			if got := f.getAction(action.ActionRef).Status; got != actions.StatusDispatched {
				t.Fatalf("action status = %q, want it to stay dispatched (never executed, never a receipt)", got)
			}
		})
	}
}

// ============================================================================
// Secret Handle acquisition (worker threads the credential to the host)
// ============================================================================

func TestWorkerThreadsResolvedCredentialToHost(t *testing.T) {
	f := newFixture(t)
	_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
	if _, err := f.worker.ProcessDispatch(context.Background(), msg); err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	op, _ := f.host.lastOp()
	if op.CredentialRef != "secretref://vault/acme/erp" {
		t.Fatalf("host op credential ref = %q, want the resolved binding's secret reference (acquisition happens in the host)", op.CredentialRef)
	}
}

// TestWorkerAcquiresSecretHandleThroughRealSupervisor drives a REAL Task 4
// Supervisor over the in-process reference Secret Provider, proving the worker's
// operation actually triggers an operation-scoped Secret Handle acquisition.
func TestWorkerAcquiresSecretHandleThroughRealSupervisor(t *testing.T) {
	const callerToken = "worker-local-caller-token"
	const credRef = "secret:acme:erp-token"
	provider := secretprovider.NewLocalProvider(secretprovider.WithCallerToken(callerToken))
	if _, err := provider.SetMaster(credRef, "MASTER-DO-NOT-LEAK"); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	broker := &recordingBroker{client: secrets.NewClient(provider, callerToken)}
	adapter := &okAdapter{}
	pack := realPack()
	sup, err := host.NewSupervisor(host.Config{Pack: pack, Binding: realBinding(pack), Adapter: adapter, Secrets: broker})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	signer, key := newReceiptSigner(t)
	store := actions.NewMemoryStore()
	publisher := &recordingPublisher{}
	svc, err := actions.NewService(store, actions.NewMemoryAuditSink(),
		actions.WithIDGenerator(sequentialIDs()),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(sdkaudit.NewKeySet(key))),
		actions.WithPublisher(publisher))
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{binding: ResolvedBinding{Host: sup, Resource: "purchase_orders", Operation: "read", OperationAction: "read", CredentialRef: credRef}}
	w, err := New(Config{Actions: svc, Resolver: resolver, Signer: signer, Observations: newFakeObservations(), Identity: workerIdentity()}, WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatal(err)
	}

	f := &fixture{t: t, svc: svc, publisher: publisher, principal: requesterPrincipal()}
	_, msg := f.dispatch(actionRequest(t, readCap, "idem-000000000001", 0))
	res, err := w.ProcessDispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %q, want completed", res.Outcome)
	}
	if n := broker.count(); n != 1 {
		t.Fatalf("secret handle acquisitions = %d, want exactly 1 (operation-scoped)", n)
	}
}

// ============================================================================
// duplicate dispatch / redelivery / worker restart idempotency
// ============================================================================

func TestWorkerDuplicateDispatchIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	first, err := f.worker.ProcessDispatch(ctx, msg)
	if err != nil || first.Outcome != OutcomeCompleted {
		t.Fatalf("first ProcessDispatch = %+v err=%v", first, err)
	}
	// A redelivery of the SAME dispatch (broker at-least-once / worker restart).
	second, err := f.worker.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("redelivery ProcessDispatch: %v", err)
	}
	if second.Outcome != OutcomeDeduped {
		t.Fatalf("redelivery outcome = %q, want deduped", second.Outcome)
	}
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d, want exactly 1 (no duplicate external side effect)", f.host.runs())
	}
	if got := f.getAction(action.ActionRef); got.Status != actions.StatusSucceeded || got.ReceiptRef != first.ActionReceipt.ReceiptRef {
		t.Fatalf("action after redelivery = %+v, want the FIRST receipt preserved", got)
	}
}

// ============================================================================
// crash during execution -> result_unknown (never blind retry, never fabricate)
// ============================================================================

func TestWorkerCrashDuringExecutionBecomesResultUnknown(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	// Simulate a crash AFTER the worker marked the action executing (the side
	// effect may already have run) but BEFORE it wrote the result: advance the
	// action to executing out of band, then redeliver the dispatch.
	if _, err := f.svc.MarkExecuting(ctx, f.principal, action.ActionRef); err != nil {
		t.Fatalf("MarkExecuting (crash setup): %v", err)
	}
	res, err := f.worker.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	if res.Outcome != OutcomeResultUnknown {
		t.Fatalf("outcome = %q, want result_unknown", res.Outcome)
	}
	if f.host.runs() != 0 {
		t.Fatal("host RE-RAN an action that may already have executed; blind retry is forbidden")
	}
	if res.ActionReceipt != nil {
		t.Fatal("a fabricated receipt was produced for an uncertain outcome")
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
		t.Fatalf("action status = %q, want result_unknown", got)
	}
}

// TestWorkerMarkExecutingBarrierPreventsBlindReExecutionAcrossCrash proves the
// PRESENCE of the durable MarkExecuting barrier (I1). The worker crashes AFTER the
// host is dispatched but BEFORE IngestReceipt durably applies; because the barrier
// advanced the action to executing first, a redelivery recovers it as
// result_unknown WITHOUT re-running the host. This test FAILS if MarkExecuting is
// removed from executeAndComplete: the crashed action would remain dispatched and
// the redelivery would blindly re-execute the side effect (host.runs()==2). Unlike
// TestWorkerCrashDuringExecutionBecomesResultUnknown (which sets executing out of
// band), this drives the barrier through the real code path.
func TestWorkerMarkExecutingBarrierPreventsBlindReExecutionAcrossCrash(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.host.crashFirst = true // the first host.Run crashes the worker mid-flight
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	// Delivery 1: the worker crashes after dispatch, before IngestReceipt.
	func() {
		defer func() { _ = recover() }() // the crash unwinds out through ProcessDispatch
		_, _ = f.worker.ProcessDispatch(ctx, msg)
	}()
	if f.host.runs() != 1 {
		t.Fatalf("host runs after the crash = %d, want 1", f.host.runs())
	}
	// The barrier MUST have advanced the action to executing before the host ran;
	// a dispatched action here would mean the barrier is missing and a redelivery
	// would re-execute.
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusExecuting {
		t.Fatalf("action after crash = %q, want executing (the MarkExecuting barrier is what makes this executing, not dispatched)", got)
	}

	// Delivery 2 (redelivery / worker restart): recover as result_unknown, host
	// NEVER re-run.
	res, err := f.worker.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("redelivery ProcessDispatch: %v", err)
	}
	if res.Outcome != OutcomeResultUnknown {
		t.Fatalf("redelivery outcome = %q, want result_unknown (no blind re-execution across a crash)", res.Outcome)
	}
	if f.host.runs() != 1 {
		t.Fatalf("host runs after redelivery = %d, want exactly 1 (blind re-execution across a crash is forbidden)", f.host.runs())
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
		t.Fatalf("action after redelivery = %q, want result_unknown", got)
	}
}

// ============================================================================
// uncertain host outcomes -> result_unknown (Q4 explicit)
// ============================================================================

func TestWorkerUncertainHostOutcomesBecomeResultUnknown(t *testing.T) {
	ctx := context.Background()
	t.Run("waiting external receipt", func(t *testing.T) {
		f := newFixture(t)
		f.host.result = host.Result{Status: host.StatusWaitingExternalReceipt}
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
		res, err := f.worker.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("ProcessDispatch: %v", err)
		}
		if res.Outcome != OutcomeResultUnknown || res.ActionReceipt != nil {
			t.Fatalf("res = %+v, want result_unknown with no fabricated receipt", res)
		}
		if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
			t.Fatalf("status = %q, want result_unknown", got)
		}
	})

	// A host wall-clock / memory-ceiling cutoff: the supervisor lets the adapter
	// run past the deadline, so a timed-out external WRITE may already have
	// committed. It MUST be result_unknown (not a fabricated failed receipt) so
	// reconciliation stays reachable — failed -> reconciling is not a legal edge.
	t.Run("resource exhausted (possibly-committed timeout)", func(t *testing.T) {
		f := newFixture(t)
		f.host.result = host.Result{Status: host.StatusResourceExhausted, Reason: "wall-clock budget exceeded"}
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))
		res, err := f.worker.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("ProcessDispatch: %v", err)
		}
		if res.Outcome != OutcomeResultUnknown || res.ActionReceipt != nil {
			t.Fatalf("res = %+v, want result_unknown with NO fabricated receipt (a timed-out write may have committed)", res)
		}
		if len(res.ObservationReceipts) != 0 || len(f.obs.observed()) != 0 {
			t.Fatalf("observations produced for an uncertain outcome: %d", len(res.ObservationReceipts))
		}
		if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
			t.Fatalf("status = %q, want result_unknown (reconciliation must stay reachable)", got)
		}
	})

	// The host's C1 provenance signal: the connector was dispatched but gave no
	// bounded verdict (adapter panic / transport failure / post-dispatch
	// cancellation / malformed response), so the side effect may have committed.
	t.Run("execution uncertain (post-dispatch, no verdict)", func(t *testing.T) {
		f := newFixture(t)
		f.host.result = host.Result{Status: host.StatusExecutionUncertain, Reason: "connector panicked after dispatch"}
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))
		res, err := f.worker.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("ProcessDispatch: %v", err)
		}
		if res.Outcome != OutcomeResultUnknown || res.ActionReceipt != nil {
			t.Fatalf("res = %+v, want result_unknown with NO fabricated receipt (side effect may have committed)", res)
		}
		if len(res.ObservationReceipts) != 0 || len(f.obs.observed()) != 0 {
			t.Fatalf("observations produced for an uncertain outcome: %d", len(res.ObservationReceipts))
		}
		if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
			t.Fatalf("status = %q, want result_unknown (reconciliation must stay reachable)", got)
		}
	})

	t.Run("signer failure after successful execution", func(t *testing.T) {
		signer := &failingSigner{}
		store := actions.NewMemoryStore()
		publisher := &recordingPublisher{}
		// Wire a permissive verifier so a fabricated receipt WOULD have completed —
		// proving the worker fails closed by choice, not because verification blocked it.
		svc, _ := actions.NewService(store, actions.NewMemoryAuditSink(),
			actions.WithIDGenerator(sequentialIDs()), actions.WithReceiptVerifier(acceptingVerifier{}), actions.WithPublisher(publisher))
		fh := &fakeHost{result: successResult()}
		resolver := &fakeResolver{binding: ResolvedBinding{Host: fh, Resource: "purchase_orders", Operation: "approve", OperationAction: "write"}}
		w, _ := New(Config{Actions: svc, Resolver: resolver, Signer: signer, Observations: newFakeObservations(), Identity: workerIdentity()}, WithIDGenerator(sequentialIDs()))
		f := &fixture{t: t, svc: svc, publisher: publisher, principal: requesterPrincipal(), host: fh}
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
		res, err := w.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("ProcessDispatch: %v", err)
		}
		if res.Outcome != OutcomeResultUnknown || res.ActionReceipt != nil {
			t.Fatalf("res = %+v, want result_unknown with no fabricated receipt", res)
		}
		if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
			t.Fatalf("status = %q, want result_unknown (executed but unattestable)", got)
		}
	})
}

// ============================================================================
// host failure -> signed FAILED receipt
// ============================================================================

func TestWorkerBoundedHostFailureProducesSignedFailedReceipt(t *testing.T) {
	ctx := context.Background()
	// resource_exhausted is deliberately EXCLUDED here: it is a possibly-committed
	// timeout, so it is result_unknown (see TestWorkerUncertainHostOutcomesBecomeResultUnknown),
	// never a signed failed receipt.
	for _, st := range []host.Status{host.StatusFailed, host.StatusDenied, host.StatusDeniedPolicy} {
		t.Run(st.String(), func(t *testing.T) {
			f := newFixture(t)
			f.host.result = host.Result{Status: st, Reason: "bounded failure"}
			action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))
			res, err := f.worker.ProcessDispatch(ctx, msg)
			if err != nil {
				t.Fatalf("ProcessDispatch: %v", err)
			}
			if res.Outcome != OutcomeCompleted || res.ActionReceipt == nil || res.ActionReceipt.Status != runtime.StatusFailed {
				t.Fatalf("res = %+v, want a completed FAILED receipt", res)
			}
			if got := f.getAction(action.ActionRef).Status; got != actions.StatusFailed {
				t.Fatalf("status = %q, want failed", got)
			}
			// No postcondition observation on a failed execution.
			if len(res.ObservationReceipts) != 0 || len(f.obs.observed()) != 0 {
				t.Fatalf("observations produced for a FAILED action: %d", len(res.ObservationReceipts))
			}
		})
	}
}

// ============================================================================
// binding resolution: permanent refusal fails the Action, transient one retries
// ============================================================================

// permanentResolutionErrors are the resolver refusals that can never succeed on
// redelivery, in the exact shapes PostgresBindingResolver.Resolve returns them
// (bare, %w-wrapped and errors.Join-ed).
func permanentResolutionErrors() []struct {
	name string
	err  error
} {
	return []struct {
		name string
		err  error
	}{
		{"no binding for the capability", ErrBindingNotFound},
		{"ambiguous binding", fmt.Errorf("%w: %d bindings declare it", ErrBindingAmbiguous, 2)},
		{"unmapped resource", errors.Join(ErrBindingUnresolvable, errors.New("the customer binding maps no resource for this capability"))},
		{"ambiguous credential", errors.Join(ErrBindingUnresolvable, errors.New("the customer binding declares 2 secrets"))},
		{"digest mismatch", errors.Join(ErrBindingUnresolvable, errors.New("customer binding pins a different product digest"))},
	}
}

// TestWorkerPermanentBindingResolutionFailsActionWithoutExecuting pins the
// permanent half of the split. An unresolvable binding (unknown capability,
// ambiguous binding, missing/ambiguous credential) is a fact about STORED
// customer data: redelivery re-derives it forever. So the Action reaches the
// terminal FAILED status with a signed receipt on the FIRST delivery, and the
// redelivery is an idempotent dedup — never a nak loop that burns delivery
// attempts on something that cannot work.
//
// It also pins the status CHOICE: failed, not result_unknown. Resolution happens
// before the MarkExecuting barrier, so the side effect provably never ran and
// there is nothing to reconcile.
func TestWorkerPermanentBindingResolutionFailsActionWithoutExecuting(t *testing.T) {
	ctx := context.Background()
	for _, tc := range permanentResolutionErrors() {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))
			f.resolver.err = tc.err

			res, err := f.worker.ProcessDispatch(ctx, msg)
			if err != nil {
				t.Fatalf("ProcessDispatch = %v, want a terminal decision (an error here naks the message forever)", err)
			}
			if res.Outcome != OutcomeCompleted {
				t.Fatalf("outcome = %q, want completed with a failed receipt", res.Outcome)
			}
			if res.ActionReceipt == nil || res.ActionReceipt.Status != runtime.StatusFailed {
				t.Fatalf("receipt = %+v, want a signed FAILED receipt", res.ActionReceipt)
			}
			if res.ActionReceipt.Signature == nil {
				t.Fatal("the failed receipt is unsigned")
			}
			if res.ActionReceipt.ResultHash != "" {
				t.Fatalf("result_hash = %q, want empty: nothing executed, so there is no connector output to bind", res.ActionReceipt.ResultHash)
			}
			if f.host.runs() != 0 {
				t.Fatalf("host runs = %d, want 0: an unresolvable binding never reaches the host", f.host.runs())
			}
			final := f.getAction(action.ActionRef)
			if final.Status != actions.StatusFailed {
				t.Fatalf("action status = %q, want failed (the side effect provably never ran, so it is NOT result_unknown)", final.Status)
			}
			if final.ReceiptRef != res.ActionReceipt.ReceiptRef {
				t.Fatalf("action receipt ref = %q, want the produced receipt %q", final.ReceiptRef, res.ActionReceipt.ReceiptRef)
			}
			// No post-state exists, so no postcondition was observed.
			if len(res.ObservationReceipts) != 0 || len(f.obs.observed()) != 0 {
				t.Fatalf("observations produced for an action that never executed: %d", len(res.ObservationReceipts))
			}
			// The poison loop is gone: the redelivery is a dedup, not another attempt.
			second, err := f.worker.ProcessDispatch(ctx, msg)
			if err != nil {
				t.Fatalf("redelivery ProcessDispatch = %v, want a terminal decision", err)
			}
			if second.Outcome != OutcomeDeduped {
				t.Fatalf("redelivery outcome = %q, want deduped", second.Outcome)
			}
			if f.host.runs() != 0 {
				t.Fatalf("host runs after redelivery = %d, want 0", f.host.runs())
			}
		})
	}
}

// TestWorkerTransientBindingResolutionNaksAndStillRetries pins the transient
// half. A store outage, an unwired deployment and an unrecognised error must all
// still nak: the Action stays dispatched with no barrier and no side effect, and
// the very next delivery executes it normally. Fixing the poison loop must not
// turn a database blip into a lost Action.
func TestWorkerTransientBindingResolutionNaksAndStillRetries(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		err  error
	}{
		{"store outage", errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")},
		{"resolver not ready", errors.Join(ErrNotReady, errors.New("binding resolver has no database pool"))},
		{"no host factory in this deployment", ErrNoHostFactory},
		{"unrecognised error defaults to transient", errors.New("something the classifier has never been taught")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
			f.resolver.err = tc.err

			if _, err := f.worker.ProcessDispatch(ctx, msg); err == nil {
				t.Fatal("ProcessDispatch = nil, want a transient error so the delivery naks and is redelivered")
			}
			if got := f.getAction(action.ActionRef).Status; got != actions.StatusDispatched {
				t.Fatalf("action status = %q, want it to stay dispatched (retryable, no barrier, no side effect)", got)
			}
			if f.host.runs() != 0 {
				t.Fatalf("host runs = %d, want 0", f.host.runs())
			}

			// The outage clears; the redelivery must still execute the Action.
			f.resolver.err = nil
			res, err := f.worker.ProcessDispatch(ctx, msg)
			if err != nil {
				t.Fatalf("ProcessDispatch after the outage cleared: %v", err)
			}
			if res.Outcome != OutcomeCompleted || res.ActionReceipt.Status != runtime.StatusSucceeded {
				t.Fatalf("res = %+v, want the retry to complete the action successfully", res)
			}
			if f.host.runs() != 1 {
				t.Fatalf("host runs = %d, want exactly 1 (a transient failure must not lose the action)", f.host.runs())
			}
			if got := f.getAction(action.ActionRef).Status; got != actions.StatusSucceeded {
				t.Fatalf("action status = %q, want succeeded", got)
			}
		})
	}
}

// TestWorkerResolutionOutcomeDrivesAckAndNak drives the split through the real
// pull loop, where the poison loop actually manifests: a permanent refusal must
// ACK (the message leaves the consumer), a transient one must NAK (redelivery).
func TestWorkerResolutionOutcomeDrivesAckAndNak(t *testing.T) {
	t.Run("permanent refusal acks", func(t *testing.T) {
		f := newFixture(t)
		_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
		f.resolver.err = ErrBindingNotFound
		src := newFakeSource(msg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = f.worker.Run(ctx, src) }()
		waitFor(t, 2*time.Second, func() bool { return src.ackCount()+src.nakCount() > 0 })
		cancel()

		if src.ackCount() != 1 || src.nakCount() != 0 {
			t.Fatalf("acks=%d naks=%d, want the unresolvable dispatch acked (naking it redelivers a message that can never succeed)", src.ackCount(), src.nakCount())
		}
	})

	t.Run("transient failure naks", func(t *testing.T) {
		f := newFixture(t)
		_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
		f.resolver.err = errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
		src := newFakeSource(msg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = f.worker.Run(ctx, src) }()
		waitFor(t, 2*time.Second, func() bool { return src.ackCount()+src.nakCount() > 0 })
		cancel()

		if src.nakCount() != 1 || src.ackCount() != 0 {
			t.Fatalf("acks=%d naks=%d, want the store outage naked for redelivery", src.ackCount(), src.nakCount())
		}
	})
}

// TestWorkerUnresolvableBindingWithUnsignableReceiptStaysRetryable pins the one
// place the two failure vocabularies could be confused. When the signer is down,
// the permanent-resolution path cannot mint the failed receipt — but nothing
// executed, so it must NAK (retryable, still dispatched), NOT fall through to
// result_unknown the way a post-execution signing outage does.
func TestWorkerUnresolvableBindingWithUnsignableReceiptStaysRetryable(t *testing.T) {
	store := actions.NewMemoryStore()
	publisher := &recordingPublisher{}
	svc, err := actions.NewService(store, actions.NewMemoryAuditSink(),
		actions.WithIDGenerator(sequentialIDs()), actions.WithReceiptVerifier(acceptingVerifier{}), actions.WithPublisher(publisher))
	if err != nil {
		t.Fatal(err)
	}
	fh := &fakeHost{result: successResult()}
	resolver := &fakeResolver{binding: ResolvedBinding{Host: fh}, err: ErrBindingNotFound}
	w, err := New(Config{Actions: svc, Resolver: resolver, Signer: &failingSigner{}, Observations: newFakeObservations(), Identity: workerIdentity()},
		WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, svc: svc, publisher: publisher, principal: requesterPrincipal(), host: fh}
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	if _, err := w.ProcessDispatch(context.Background(), msg); err == nil {
		t.Fatal("ProcessDispatch = nil, want a transient error: an unsignable receipt must not complete the action")
	}
	got := f.getAction(action.ActionRef).Status
	if got == actions.StatusResultUnknown {
		t.Fatal("action = result_unknown, but resolution runs BEFORE the executing barrier: nothing ran, so there is nothing to reconcile")
	}
	if got != actions.StatusDispatched {
		t.Fatalf("action status = %q, want it to stay dispatched (retryable)", got)
	}
}

// ============================================================================
// separate signed ObservationReceipt set: exactly the declared needs, deduped
// ============================================================================

func TestWorkerProducesExactDeduplicatedObservationSet(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 2))

	res, err := f.worker.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %q, want completed", res.Outcome)
	}
	if len(res.ObservationReceipts) != 2 {
		t.Fatalf("observation receipts = %d, want exactly the 2 declared needs", len(res.ObservationReceipts))
	}
	// Each observation binds exactly one declared need (deduped set) and the exact
	// action + parameter hash + postcondition pair.
	seen := map[string]bool{}
	for _, r := range res.ObservationReceipts {
		if r.ActionRef != action.ActionRef || r.ParameterHash != action.ParameterHash {
			t.Fatalf("observation does not bind the exact action: %+v", r)
		}
		if seen[r.VerificationNeedID] {
			t.Fatalf("duplicate observation for need %q; the set must be deduplicated", r.VerificationNeedID)
		}
		seen[r.VerificationNeedID] = true
	}
	if !seen["n1"] || !seen["n2"] {
		t.Fatalf("observation needs = %v, want exactly {n1,n2}", seen)
	}
	// The producer was invoked with the exact declared bindings — the worker never
	// invented a need beyond the declared VerificationNeeds.
	if got := len(f.obs.observed()); got != 2 {
		t.Fatalf("producer invocations = %d, want exactly 2 (only the declared needs)", got)
	}
	for _, b := range f.obs.observed() {
		if b.ActionRef != action.ActionRef || b.ParameterHash != action.ParameterHash {
			t.Fatalf("producer binding does not bind the action: %+v", b)
		}
	}
}

func TestWorkerObservationFailureNeverFabricatesAndKeepsActionSucceeded(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.obs.failNeeds["n2"] = errors.New("action_binding_mismatch") // a detached / denied need
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 2))

	res, err := f.worker.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	// The ActionReceipt (technical execution) is independent and still authoritative.
	if res.Outcome != OutcomeCompleted || f.getAction(action.ActionRef).Status != actions.StatusSucceeded {
		t.Fatalf("action must stay succeeded despite an observation failure: %+v", res)
	}
	// Only the satisfiable need produced a receipt; the failed need was NOT fabricated.
	if len(res.ObservationReceipts) != 1 || res.ObservationReceipts[0].VerificationNeedID != "n1" {
		t.Fatalf("observation receipts = %+v, want only n1 (n2 must not be fabricated)", res.ObservationReceipts)
	}
	if res.ObservationErr == nil {
		t.Fatal("the observation failure was swallowed; a failed verification need must surface, never fabricate")
	}
}

// TestWorkerProduceObservationsFailsClosedOnDefenseInDepthBranches drives the two
// fail-closed guards in produceObservations directly (a stored Action cannot
// normally carry a detached need — ActionRequest.Validate rejects it — so these
// defense-in-depth branches are exercised with hand-built Actions): neither
// branch ever fabricates an ObservationReceipt.
func TestWorkerProduceObservationsFailsClosedOnDefenseInDepthBranches(t *testing.T) {
	ctx := context.Background()
	validHash := "sha256:" + hex.EncodeToString(make([]byte, 32))

	t.Run("need bound to an undeclared postcondition", func(t *testing.T) {
		f := newFixture(t)
		action := actions.Action{
			TenantRef: workerTenant, ActionRef: "act_0123456789abcdef", ParameterHash: validHash,
			Postconditions:    []runtime.PostconditionSpec{{PostconditionID: "pc1", Kind: "state", Reference: "po.status"}},
			VerificationNeeds: []runtime.VerificationNeed{{NeedID: "n1", PostconditionID: "pc_undeclared", DataClass: "purchase_order_status"}},
		}
		receipts, err := f.worker.produceObservations(ctx, workerTenant, action)
		if !errors.Is(err, ErrObservationRejected) {
			t.Fatalf("err = %v, want ErrObservationRejected", err)
		}
		if len(receipts) != 0 {
			t.Fatalf("receipts = %d, want none (a detached need is never fabricated)", len(receipts))
		}
		if len(f.obs.observed()) != 0 {
			t.Fatal("the evidence producer was invoked for an undeclared postcondition; it must be rejected before Observe")
		}
	})

	t.Run("producer returns a receipt not binding the need", func(t *testing.T) {
		f := newFixture(t)
		f.obs.mismatch = true
		action := actions.Action{
			TenantRef: workerTenant, ActionRef: "act_0123456789abcdef", ParameterHash: validHash,
			Postconditions:    []runtime.PostconditionSpec{{PostconditionID: "pc1", Kind: "state", Reference: "po.status"}},
			VerificationNeeds: []runtime.VerificationNeed{{NeedID: "n1", PostconditionID: "pc1", DataClass: "purchase_order_status"}},
		}
		receipts, err := f.worker.produceObservations(ctx, workerTenant, action)
		if !errors.Is(err, ErrObservationRejected) {
			t.Fatalf("err = %v, want ErrObservationRejected", err)
		}
		if len(receipts) != 0 {
			t.Fatalf("receipts = %d, want none (a mis-bound observation is never accepted)", len(receipts))
		}
	})
}

// ============================================================================
// concurrency: many deliveries of one Action -> host runs exactly once
// ============================================================================

func TestWorkerConcurrentDeliveriesExecuteHostExactlyOnce(t *testing.T) {
	f := newFixture(t)
	f.host.delay = 5 * time.Millisecond // widen the race window
	_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	const goroutines = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	completed := 0
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			res, err := f.worker.ProcessDispatch(context.Background(), msg)
			if err != nil {
				return
			}
			if res.Outcome == OutcomeCompleted {
				mu.Lock()
				completed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d under %d concurrent deliveries, want exactly 1", f.host.runs(), goroutines)
	}
	if completed != 1 {
		t.Fatalf("completions = %d, want exactly 1 authoritative completion", completed)
	}
}

// ============================================================================
// durable pull loop + worker restart
// ============================================================================

func TestWorkerRunDurablePullAcksAfterApply(t *testing.T) {
	f := newFixture(t)
	_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
	src := newFakeSource(msg, msg) // deliver, then redeliver (restart / at-least-once)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.worker.Run(ctx, src) }()

	waitFor(t, 2*time.Second, func() bool { return src.ackCount() >= 2 })
	cancel()

	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d across a redelivery, want exactly 1", f.host.runs())
	}
	if src.ackCount() < 2 || src.nakCount() != 0 {
		t.Fatalf("acks=%d naks=%d, want both deliveries acked after durable apply", src.ackCount(), src.nakCount())
	}
}

// ============================================================================
// status query reflects the durable outcome
// ============================================================================

func TestWorkerStatusQueryReflectsOutcome(t *testing.T) {
	f := newFixture(t)
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
	if _, err := f.worker.ProcessDispatch(context.Background(), msg); err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	got := f.getAction(action.ActionRef)
	if got.Status != actions.StatusSucceeded || got.ReceiptRef == "" {
		t.Fatalf("status query = %+v, want succeeded with a receipt ref", got)
	}
}

// --- supporting fakes for the loop / signer / verifier ----------------------

type failingSigner struct{}

func (failingSigner) Sign(context.Context, []byte) (runtime.Signature, error) {
	return runtime.Signature{}, errors.New("kms unavailable")
}

type acceptingVerifier struct{}

func (acceptingVerifier) VerifyReceipt(context.Context, string, runtime.ActionReceipt) error {
	return nil
}

// recordingBroker wraps the real secrets client and counts acquisitions.
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

func (b *recordingBroker) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.ids)
}

type okAdapter struct{}

func (okAdapter) Name() string { return "ok" }
func (okAdapter) Dispatch(_ context.Context, _ host.Policy, req *host.HostRequest) (*host.HostResponse, error) {
	if req.Secret == nil || req.Secret.HandleID == "" {
		return nil, errors.New("missing secret grant")
	}
	return &host.HostResponse{ProtocolVersion: host.ProtocolVersion, RequestID: req.RequestID, Status: host.StatusSucceeded, Output: []byte(`{"ok":true}`)}, nil
}

func realPack() connector.ProductPack {
	p := connector.ProductPack{
		SchemaVersion: connector.ProductPackSchemaVersion,
		ProductKey:    "erp.demo.procurement",
		Version:       "1.4.0",
		Capabilities: []connector.Capability{{
			Name: readCap, Title: "read purchase order", Effect: connector.EffectRead,
			Input:  connector.IOSchema{Ref: "schema.in", Digest: refDigest("in")},
			Output: connector.IOSchema{Ref: "schema.out", Digest: refDigest("out")},
		}},
		Network: connector.NetworkRequirements{Egress: []string{"connector.api"}, Isolation: "outbound_only"},
		Runtime: connector.RuntimeRequirements{Runtime: "container", MinMemoryMB: 128},
		Limits:  connector.Limits{MaxConcurrency: 4, MaxRequestsPerMinute: 120},
	}
	p.Digest = connector.PackContentDigest(p)
	return p
}

func realBinding(pack connector.ProductPack) connector.CustomerBinding {
	return connector.CustomerBinding{
		SchemaVersion: connector.CustomerBindingSchemaVersion,
		BindingKey:    "acme-erp",
		Customer:      connector.CustomerRef{Name: "acme"},
		Product:       connector.ProductRef{ProductKey: pack.ProductKey, Version: pack.Version, Digest: pack.Digest},
		Endpoints:     []connector.Endpoint{{Name: "erp", URL: "https://erp.acme.example:8443/api"}},
		Secrets:       []connector.SecretRef{{Name: "erp-token", Ref: "secretref://vault/acme/erp"}},
	}
}

func refDigest(seed string) string {
	sum := sha256.Sum256([]byte("worker-test-schema:" + seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fakeSource / fakeDelivery drive Worker.Run deterministically.
type fakeSource struct {
	mu      sync.Mutex
	pending []actions.DispatchMessage
	acks    int
	naks    int
}

func newFakeSource(msgs ...actions.DispatchMessage) *fakeSource {
	return &fakeSource{pending: append([]actions.DispatchMessage(nil), msgs...)}
}

func (s *fakeSource) Fetch(_ context.Context, n int, _ time.Duration) ([]Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		return nil, nil
	}
	if n > len(s.pending) {
		n = len(s.pending)
	}
	batch := s.pending[:n]
	s.pending = s.pending[n:]
	out := make([]Delivery, 0, len(batch))
	for _, m := range batch {
		out = append(out, &fakeDelivery{src: s, msg: m})
	}
	return out, nil
}

func (s *fakeSource) ackCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.acks }
func (s *fakeSource) nakCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.naks }

type fakeDelivery struct {
	src *fakeSource
	msg actions.DispatchMessage
}

func (d *fakeDelivery) Message() actions.DispatchMessage { return d.msg }
func (d *fakeDelivery) Ack() error                       { d.src.mu.Lock(); d.src.acks++; d.src.mu.Unlock(); return nil }
func (d *fakeDelivery) Nak() error                       { d.src.mu.Lock(); d.src.naks++; d.src.mu.Unlock(); return nil }

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
