package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
)

const (
	agentTenant = "tenant-1"
	agentCase   = "wc_0123456789abcdef"
	approveCap  = "erp.purchase_order.approve"
	readCap     = "erp.purchase_order.read"
	privateConn = "conn_private_instance_9"
	privateRes  = "purchase_orders"
	privateCred = "secretref://vault/acme/erp"
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
	signer, err := audit.NewEd25519AuditSigner("connector-agent-1", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key := sdkaudit.SigningKey{KeyID: "connector-agent-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyActive}
	return signer, key
}

// --- request builders -------------------------------------------------------

func requesterPrincipal() runtime.PrincipalContext {
	now := time.Now().UTC()
	return runtime.PrincipalContext{
		TenantRef: agentTenant, PrincipalRef: "agent-1", AgentClientRef: "agc_client-1", AgentReleaseRef: "rel-1",
		TrustClass: runtime.TrustFirstParty, OrgSnapshotRef: "org-1", VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func testSignature() runtime.Signature {
	return runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "k1", Value: "AAAA"}
}

func actionRequest(t *testing.T, capability, idem string, needs int) runtime.ActionRequest {
	t.Helper()
	params, hash, err := runtime.BuildParameters(map[string]any{"amount": 100})
	if err != nil {
		t.Fatalf("build parameters: %v", err)
	}
	now := time.Now().UTC()
	req := runtime.ActionRequest{
		RequestID:          "req-" + idem,
		BusinessContextRef: agentCase,
		Capability:         capability,
		Parameters:         params,
		ParameterHash:      hash,
		Purpose:            "execute",
		RiskDecision: runtime.RiskDecision{
			DecisionID: "dec-1", Authority: "acme-risk", RiskLevel: runtime.RiskMedium,
			Capability: capability, ParameterHash: hash, BusinessContextRef: agentCase,
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

type fakeResolver struct {
	mu        sync.Mutex
	binding   worker.ResolvedBinding
	err       error
	tenants   []string
	caps      []string
	callCount int
}

func (r *fakeResolver) Resolve(_ context.Context, tenantRef, capability string) (worker.ResolvedBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callCount++
	r.tenants = append(r.tenants, tenantRef)
	r.caps = append(r.caps, capability)
	if r.err != nil {
		return worker.ResolvedBinding{}, r.err
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
}

func (h *fakeHost) Run(_ context.Context, op host.Operation) host.Result {
	h.mu.Lock()
	h.ops = append(h.ops, op)
	delay := h.delay
	res := h.result
	h.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
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

// fakeObservations returns a valid signed ObservationReceipt per binding and
// records them. failNeeds names needs whose Observe fails permanently; failNeedsTransient
// names needs whose Observe fails a bounded number of times (a disconnect) then succeeds.
type fakeObservations struct {
	mu                 sync.Mutex
	bindings           []runtime.VerificationBinding
	failNeeds          map[string]error
	failNeedsTransient map[string]int
	mismatch           bool
	observeDelay       time.Duration
}

func newFakeObservations() *fakeObservations {
	return &fakeObservations{failNeeds: map[string]error{}, failNeedsTransient: map[string]int{}}
}

func (o *fakeObservations) Observe(_ context.Context, _ string, binding runtime.VerificationBinding) (runtime.ObservationReceipt, error) {
	o.mu.Lock()
	o.bindings = append(o.bindings, binding)
	failErr := o.failNeeds[binding.VerificationNeedID]
	transient := o.failNeedsTransient[binding.VerificationNeedID]
	if transient > 0 {
		o.failNeedsTransient[binding.VerificationNeedID] = transient - 1
	}
	mismatch := o.mismatch
	delay := o.observeDelay
	o.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay) // widen the race window between LoadObservation and RecordObservation
	}
	if failErr != nil {
		return runtime.ObservationReceipt{}, failErr
	}
	if transient > 0 {
		return runtime.ObservationReceipt{}, errObsDisconnected
	}
	boundActionRef := binding.ActionRef
	if mismatch {
		boundActionRef = "act_mismatchmismatch1"
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

// countFor reports how many times Observe was invoked for a given need.
func (o *fakeObservations) countFor(needID string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, b := range o.bindings {
		if b.VerificationNeedID == needID {
			n++
		}
	}
	return n
}

var errObsDisconnected = errors.New("observation producer unreachable (session disconnected)")

// recordingPublisher captures the DispatchMessage the outbox republishes.
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

// flakyPlane wraps the real *actions.Service ActionPlane and injects transient
// "session disconnected" failures at named methods, modeling the outbound
// session dropping mid-pipeline (the failure never reaches the inner service).
type flakyPlane struct {
	inner    worker.ActionPlane
	mu       sync.Mutex
	failNext map[string]int
}

func newFlakyPlane(inner worker.ActionPlane) *flakyPlane {
	return &flakyPlane{inner: inner, failNext: map[string]int{}}
}

var errSessionDisconnected = errors.New("outbound session disconnected")

func (p *flakyPlane) fail(method string, n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failNext[method] = n
}

func (p *flakyPlane) shouldFail(method string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext[method] > 0 {
		p.failNext[method]--
		return true
	}
	return false
}

func (p *flakyPlane) GetAction(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	if p.shouldFail("GetAction") {
		return actions.Action{}, errSessionDisconnected
	}
	return p.inner.GetAction(ctx, principal, actionRef)
}

func (p *flakyPlane) MarkExecuting(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	if p.shouldFail("MarkExecuting") {
		return actions.Action{}, errSessionDisconnected
	}
	return p.inner.MarkExecuting(ctx, principal, actionRef)
}

func (p *flakyPlane) IngestReceipt(ctx context.Context, principal runtime.PrincipalContext, resultID string, receipt runtime.ActionReceipt) (actions.Action, error) {
	if p.shouldFail("IngestReceipt") {
		return actions.Action{}, errSessionDisconnected
	}
	return p.inner.IngestReceipt(ctx, principal, resultID, receipt)
}

func (p *flakyPlane) MarkResultUnknown(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	if p.shouldFail("MarkResultUnknown") {
		return actions.Action{}, errSessionDisconnected
	}
	return p.inner.MarkResultUnknown(ctx, principal, actionRef)
}

// memJournal is an in-memory EdgeJournal fake (the concrete durable edge store
// is deferred to Task 7).
type memJournal struct {
	mu       sync.Mutex
	receipts map[string]runtime.ActionReceipt
	obs      map[string]runtime.ObservationReceipt
	// Fault injection (nil = healthy): a set error is returned by the named method
	// on every call, modeling a durable edge-journal outage.
	recordReceiptErr error
	loadReceiptErr   error
	loadObsErr       error
}

func newMemJournal() *memJournal {
	return &memJournal{receipts: map[string]runtime.ActionReceipt{}, obs: map[string]runtime.ObservationReceipt{}}
}

func rKey(tenant, action, dispatch string) string { return tenant + "|" + action + "|" + dispatch }
func oKey(tenant, action, need string) string      { return tenant + "|" + action + "|" + need }

func (j *memJournal) LoadReceipt(_ context.Context, tenant, action, dispatch string) (runtime.ActionReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.loadReceiptErr != nil {
		return runtime.ActionReceipt{}, false, j.loadReceiptErr
	}
	r, ok := j.receipts[rKey(tenant, action, dispatch)]
	return r, ok, nil
}

func (j *memJournal) RecordReceipt(_ context.Context, tenant, action, dispatch string, receipt runtime.ActionReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.recordReceiptErr != nil {
		return j.recordReceiptErr
	}
	j.receipts[rKey(tenant, action, dispatch)] = receipt
	return nil
}

func (j *memJournal) LoadObservation(_ context.Context, tenant, action, need string) (runtime.ObservationReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.loadObsErr != nil {
		return runtime.ObservationReceipt{}, false, j.loadObsErr
	}
	r, ok := j.obs[oKey(tenant, action, need)]
	return r, ok, nil
}

func (j *memJournal) RecordObservation(_ context.Context, tenant, action, need string, receipt runtime.ObservationReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.obs[oKey(tenant, action, need)] = receipt
	return nil
}

func (j *memJournal) observationCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.obs)
}

// --- transport fakes --------------------------------------------------------

type fakeTransport struct{ closed bool }

func (t *fakeTransport) Connected() bool { return !t.closed }
func (t *fakeTransport) Close() error    { t.closed = true; return nil }

type fakeDialer struct {
	mu        sync.Mutex
	dialCalls int
	err       error
	last      *fakeTransport
}

func (d *fakeDialer) Dial(_ context.Context, _ *tls.Config) (Transport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dialCalls++
	if d.err != nil {
		return nil, d.err
	}
	d.last = &fakeTransport{}
	return d.last, nil
}

func (d *fakeDialer) calls() int { d.mu.Lock(); defer d.mu.Unlock(); return d.dialCalls }

// fakeTLSProvider records how the session builds its outbound client config,
// proving the mutual-identity material is threaded through ClientTLSConfig.
type fakeTLSProvider struct {
	mu          sync.Mutex
	peers       sdk.PeerAuthorization
	serverName  string
	called      int
	buildErr    error
	identityURI string
}

func (p *fakeTLSProvider) ClientTLSConfig(peers sdk.PeerAuthorization, serverName string) (*tls.Config, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.called++
	p.peers = peers
	p.serverName = serverName
	if p.buildErr != nil {
		return nil, p.buildErr
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}, nil
}

func (p *fakeTLSProvider) IdentityURI() string { return p.identityURI }
func (p *fakeTLSProvider) OnRotate(func())     {}
func (p *fakeTLSProvider) Reload() error       { return nil }

// --- fixture ----------------------------------------------------------------

func agentIdentity() worker.Identity {
	return worker.Identity{PrincipalRef: "connector-agent", AgentClientRef: "agc_connector_agent", AgentReleaseRef: "agent-rel-1", OrgSnapshotRef: "org-system"}
}

func agentPin() Pin { return Pin{TenantRef: agentTenant, Capabilities: []string{approveCap, readCap}} }

type fixture struct {
	t         *testing.T
	svc       *actions.Service
	plane     *flakyPlane
	signer    *audit.Ed25519AuditSigner
	resolver  *fakeResolver
	host      *fakeHost
	obs       *fakeObservations
	journal   *memJournal
	session   *Session
	publisher *recordingPublisher
	principal runtime.PrincipalContext
}

type fixtureOpts struct {
	pin Pin
}

func newFixture(t *testing.T) *fixture { return newFixtureOpts(t, fixtureOpts{pin: agentPin()}) }

func newFixtureOpts(t *testing.T, fo fixtureOpts) *fixture {
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
	fh := &fakeHost{result: successResult()}
	resolver := &fakeResolver{binding: worker.ResolvedBinding{Host: fh, Resource: privateRes, Operation: "approve", OperationAction: "write", ConnectorRef: privateConn, CredentialRef: privateCred}}
	obs := newFakeObservations()
	journal := newMemJournal()
	plane := newFlakyPlane(svc)
	s, err := New(Config{
		ActionPlane: plane, Resolver: resolver, Signer: signer, Observations: obs, Journal: journal,
		Identity: agentIdentity(), Pin: fo.pin, Version: "1.0.0", IdentityURI: "agentnexus://enterprise/acme/service/connector-agent/installation/agent-7",
	}, WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	return &fixture{t: t, svc: svc, plane: plane, signer: signer, resolver: resolver, host: fh, obs: obs, journal: journal, session: s, publisher: publisher, principal: requesterPrincipal()}
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
// 1. outbound only, never listens
// ============================================================================

func TestAgentDialsOutboundOnlyNeverListens(t *testing.T) {
	f := newFixture(t)
	dialer := &fakeDialer{}
	f.session.dialer = dialer
	if err := f.session.Establish(context.Background()); err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if dialer.calls() != 1 {
		t.Fatalf("dial calls = %d, want exactly 1 (the agent initiates the session outbound)", dialer.calls())
	}
	if !f.session.Health().Connected {
		t.Fatal("session not connected after outbound Establish")
	}
	// The agent is a CLIENT: it exposes no inbound Serve/Listen/Accept surface.
	// This is a compile-time guarantee (no such method exists); the integration
	// test proves nothing can connect TO the agent over real sockets.
	if _, isServer := any(f.session).(interface{ Serve(context.Context) error }); isServer {
		t.Fatal("the connector agent must never expose an inbound Serve surface")
	}
	if _, isListener := any(f.session).(interface{ Listen(string) error }); isListener {
		t.Fatal("the connector agent must never bind an inbound listener")
	}
}

// ============================================================================
// 2. mutual identity
// ============================================================================

func TestAgentRequiresMutualIdentity(t *testing.T) {
	f := newFixture(t)
	prov := &fakeTLSProvider{}
	f.session.tls = prov
	f.session.peers = sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"connector-worker", "gateway-api"}}
	f.session.serverName = "central.acme.example"
	f.session.dialer = &fakeDialer{}

	if err := f.session.Establish(context.Background()); err != nil {
		t.Fatalf("Establish with valid material: %v", err)
	}
	if prov.called == 0 {
		t.Fatal("the session did not build its client config via ClientTLSConfig (mutual identity is not opt-out)")
	}
	if len(prov.peers.Services) == 0 || prov.peers.Enterprise == "" {
		t.Fatalf("client config built with an empty PeerAuthorization %+v; the server identity must be pinned", prov.peers)
	}
	if prov.serverName == "" {
		t.Fatal("client config built without a server name; hostname verification is mandatory")
	}

	// A missing/unauthorized server name fails closed.
	f2 := newFixture(t)
	f2.session.tls = &fakeTLSProvider{}
	f2.session.peers = sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"connector-worker"}}
	f2.session.serverName = ""
	f2.session.dialer = &fakeDialer{}
	if err := f2.session.Establish(context.Background()); err == nil {
		t.Fatal("Establish accepted an empty server name; the mutual-TLS profile requires hostname verification")
	}

	// A client whose material cannot be expressed (no cert) fails closed.
	f3 := newFixture(t)
	f3.session.tls = &fakeTLSProvider{buildErr: errors.New("no client certificate")}
	f3.session.peers = sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"connector-worker"}}
	f3.session.serverName = "central.acme.example"
	f3.session.dialer = &fakeDialer{}
	if err := f3.session.Establish(context.Background()); err == nil {
		t.Fatal("Establish accepted a client that cannot present its certificate; mutual identity must fail closed")
	}
}

// ============================================================================
// 3. tenant/binding pin
// ============================================================================

func TestAgentPinsTenantAndBinding(t *testing.T) {
	// The session is pinned to readCap only; an approveCap dispatch is outside the
	// pin and must be rejected without ever running the host.
	f := newFixtureOpts(t, fixtureOpts{pin: Pin{TenantRef: agentTenant, Capabilities: []string{readCap}}})
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	res, err := f.session.ProcessDispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("ProcessDispatch = %v, want a clean rejection", err)
	}
	if res.Outcome != worker.OutcomeRejected {
		t.Fatalf("outcome = %q, want rejected (dispatch capability outside the agent's pin)", res.Outcome)
	}
	if f.host.runs() != 0 {
		t.Fatal("host ran a dispatch outside the agent's tenant/binding pin")
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusDispatched {
		t.Fatalf("action status = %q, want it to stay dispatched (never executed)", got)
	}
}

// ============================================================================
// 4. disconnect BEFORE execution resumes and executes once
// ============================================================================

func TestAgentDisconnectBeforeExecutionResumesAndExecutesOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	// Disconnect at MarkExecuting: the session drops before the host runs.
	f.plane.fail("MarkExecuting", 1)
	if _, err := f.session.ProcessDispatch(ctx, msg); err == nil {
		t.Fatal("expected a transient disconnect error, got nil")
	}
	if f.host.runs() != 0 {
		t.Fatalf("host ran %d times after a disconnect BEFORE execution, want 0", f.host.runs())
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusDispatched {
		t.Fatalf("action status = %q after pre-execution disconnect, want dispatched", got)
	}

	// Resume: the redelivered dispatch executes exactly once.
	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("resume ProcessDispatch: %v", err)
	}
	if res.Outcome != worker.OutcomeCompleted {
		t.Fatalf("resume outcome = %q, want completed", res.Outcome)
	}
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d after resume, want exactly 1", f.host.runs())
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusSucceeded {
		t.Fatalf("action status = %q, want succeeded", got)
	}
}

// ============================================================================
// 5. disconnect AFTER execution resumes without duplicate (journal re-apply)
// ============================================================================

func TestAgentDisconnectAfterExecutionResumesWithoutDuplicate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	// Disconnect at IngestReceipt: the host ran and the receipt was edge-journaled,
	// but the central apply never landed.
	f.plane.fail("IngestReceipt", 1)
	if _, err := f.session.ProcessDispatch(ctx, msg); err == nil {
		t.Fatal("expected a transient disconnect error at central apply, got nil")
	}
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d after execution, want 1", f.host.runs())
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusExecuting {
		t.Fatalf("action status = %q, want executing (barrier crossed, central apply lost)", got)
	}
	if _, ok, _ := f.journal.LoadReceipt(ctx, action.TenantRef, action.ActionRef, msg.DispatchRef); !ok {
		t.Fatal("the minted ActionReceipt was not edge-journaled BEFORE the central apply")
	}

	// Resume: the journaled receipt is re-applied; the host is NEVER re-run.
	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("resume ProcessDispatch: %v", err)
	}
	if res.Outcome != worker.OutcomeCompleted {
		t.Fatalf("resume outcome = %q, want completed (re-applied journaled receipt)", res.Outcome)
	}
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d after resume, want exactly 1 (no duplicate external operation)", f.host.runs())
	}
	final := f.getAction(action.ActionRef)
	if final.Status != actions.StatusSucceeded || final.ReceiptRef == "" {
		t.Fatalf("action = %+v, want succeeded with the one journaled receipt", final)
	}
	if res.ActionReceipt != nil && res.ActionReceipt.ReceiptRef != final.ReceiptRef {
		t.Fatalf("resumed receipt %q != applied receipt %q (one authoritative ActionReceipt)", res.ActionReceipt.ReceiptRef, final.ReceiptRef)
	}
}

// ============================================================================
// 6. disconnect before / after (partial) observation resumes the remaining set
// ============================================================================

func TestAgentDisconnectBeforeObservationResumesRemainingNeeds(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// Both declared needs are unreachable on the first pass (disconnect at the
	// observation phase); nothing is journaled.
	f.obs.failNeedsTransient["n1"] = 1
	f.obs.failNeedsTransient["n2"] = 1
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 2))

	if _, err := f.session.ProcessDispatch(ctx, msg); err == nil {
		t.Fatal("expected a transient observation disconnect, got nil (the dispatch must not ack with observations incomplete)")
	}
	if f.getAction(action.ActionRef).Status != actions.StatusSucceeded {
		t.Fatal("the ActionReceipt must be applied (succeeded) even when observations are deferred")
	}
	if f.journal.observationCount() != 0 {
		t.Fatalf("journaled observations = %d before resume, want 0 (nothing observed yet)", f.journal.observationCount())
	}

	// Resume: both declared needs are observed exactly once; the final set is exact.
	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("resume ProcessDispatch: %v", err)
	}
	assertExactObservationSet(t, res.ObservationReceipts, action, "n1", "n2")
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d, want exactly 1 (observations never re-run the host)", f.host.runs())
	}
}

func TestAgentDisconnectAfterPartialObservationResumesExactSet(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.obs.failNeedsTransient["n2"] = 1 // n1 succeeds and is journaled; n2 disconnects once
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 2))

	if _, err := f.session.ProcessDispatch(ctx, msg); err == nil {
		t.Fatal("expected a transient observation disconnect on n2, got nil")
	}
	before := len(f.obs.observed())
	if _, ok, _ := f.journal.LoadObservation(ctx, action.TenantRef, action.ActionRef, "n1"); !ok {
		t.Fatal("n1 must be journaled after the first pass")
	}

	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("resume ProcessDispatch: %v", err)
	}
	// On resume ONLY the remaining need (n2) is observed; n1 is loaded from the journal.
	added := f.obs.observed()[before:]
	if len(added) != 1 || added[0].VerificationNeedID != "n2" {
		t.Fatalf("resume observed %+v, want only the remaining need n2 (n1 must come from the journal)", added)
	}
	assertExactObservationSet(t, res.ObservationReceipts, action, "n1", "n2")
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d, want exactly 1", f.host.runs())
	}
}

func assertExactObservationSet(t *testing.T, receipts []runtime.ObservationReceipt, action actions.Action, wantNeeds ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, r := range receipts {
		if r.ActionRef != action.ActionRef || r.ParameterHash != action.ParameterHash {
			t.Fatalf("observation does not bind the exact action: %+v", r)
		}
		if seen[r.VerificationNeedID] {
			t.Fatalf("duplicate observation for need %q; the set must be deduplicated", r.VerificationNeedID)
		}
		seen[r.VerificationNeedID] = true
	}
	if len(seen) != len(wantNeeds) {
		t.Fatalf("observation set = %v, want exactly %v", seen, wantNeeds)
	}
	for _, need := range wantNeeds {
		if !seen[need] {
			t.Fatalf("observation set = %v, missing declared need %q", seen, need)
		}
	}
}

// ============================================================================
// 7. resume targets the SAME action_ref and need_ids
// ============================================================================

func TestAgentResumeSameActionAndVerificationNeed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.obs.failNeedsTransient["n1"] = 1
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))

	if _, err := f.session.ProcessDispatch(ctx, msg); err == nil {
		t.Fatal("expected a transient observation disconnect, got nil")
	}
	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("resume ProcessDispatch: %v", err)
	}
	// The host ran once, for the SAME action_ref (its dispatch ref binds the action).
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d, want 1 (resume must not re-execute)", f.host.runs())
	}
	op, _ := f.host.lastOp()
	if op.RequestID != msg.DispatchRef {
		t.Fatalf("host op request id = %q, want the same dispatch ref %q", op.RequestID, msg.DispatchRef)
	}
	if len(res.ObservationReceipts) != 1 || res.ObservationReceipts[0].ActionRef != action.ActionRef || res.ObservationReceipts[0].VerificationNeedID != "n1" {
		t.Fatalf("resumed observation = %+v, want the SAME action_ref %q and need n1", res.ObservationReceipts, action.ActionRef)
	}
}

// ============================================================================
// 8. revoked certificate tears down the session and does not duplicate
// ============================================================================

func TestAgentRevokedCertificateTearsDownAndDoesNotDuplicate(t *testing.T) {
	t.Run("teardown_then_journaled_resume_no_duplicate", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		dialer := &fakeDialer{}
		f.session.dialer = dialer
		if err := f.session.Establish(ctx); err != nil {
			t.Fatalf("Establish: %v", err)
		}
		_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

		// In-flight when the peer is revoked: host ran, receipt journaled, central
		// apply lost as the session drops.
		f.plane.fail("IngestReceipt", 1)
		if _, err := f.session.ProcessDispatch(ctx, msg); err == nil {
			t.Fatal("expected the in-flight disconnect error, got nil")
		}
		if f.host.runs() != 1 {
			t.Fatalf("host runs = %d, want 1", f.host.runs())
		}

		// The CRL revocation fires the rotation teardown: the live session drops.
		f.session.HandleRotation()
		if f.session.Health().Connected {
			t.Fatal("session still reports connected after a revocation teardown")
		}

		// Re-establish with fresh material and redeliver: the connector is NOT re-run.
		if err := f.session.Establish(ctx); err != nil {
			t.Fatalf("re-establish: %v", err)
		}
		res, err := f.session.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("resume after re-establish: %v", err)
		}
		if res.Outcome != worker.OutcomeCompleted {
			t.Fatalf("resume outcome = %q, want completed", res.Outcome)
		}
		if f.host.runs() != 1 {
			t.Fatalf("host runs = %d after revocation teardown + re-establish, want exactly 1 (no duplicate)", f.host.runs())
		}
	})

	t.Run("in_flight_uncertain_becomes_result_unknown_on_rotation", func(t *testing.T) {
		f := newFixture(t)
		ctx := context.Background()
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

		// Model an action mid-execution in THIS session: barrier crossed, owned here.
		if _, err := f.svc.MarkExecuting(ctx, f.principal, action.ActionRef); err != nil {
			t.Fatalf("MarkExecuting (in-flight setup): %v", err)
		}
		f.session.inflight.acquire(msg.ActionRef)

		f.session.HandleRotation()
		if f.session.Health().Connected {
			t.Fatal("session still connected after rotation")
		}
		if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
			t.Fatalf("in-flight action after revocation = %q, want result_unknown (never a fabricated verdict)", got)
		}
		if f.host.runs() != 0 {
			t.Fatal("the connector must not run during a revocation teardown")
		}
	})
}

// ============================================================================
// 9. stale package refuses execution (real host digest check)
// ============================================================================

func TestAgentStalePackageRefusesExecution(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	adapter := &countingAdapter{}
	// A resolver that binds a REAL supervisor for a pack whose content digest does
	// not match the binding's pinned ProductRef.Digest: host.NewSupervisor refuses
	// it (ErrDigestMismatch) before any execution is possible.
	f.resolver.binding = worker.ResolvedBinding{}
	f.resolver.err = staleSupervisorError(t, adapter)

	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch = %v, want a clean refusal (a digest mismatch is permanent, not transient)", err)
	}
	if res.Outcome != worker.OutcomeRejected {
		t.Fatalf("outcome = %q, want rejected (stale package digest)", res.Outcome)
	}
	if adapter.dispatches() != 0 {
		t.Fatal("the connector body ran despite a stale package digest; a digest-swapped pack must never execute")
	}
	if res.ActionReceipt != nil {
		t.Fatal("a receipt was produced for a refused stale package")
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusDispatched {
		t.Fatalf("action status = %q, want dispatched (never executed)", got)
	}
}

// staleSupervisorError builds a real host.Supervisor for a pack whose digest does
// not match the binding's pinned digest and returns the resulting error.
func staleSupervisorError(t *testing.T, adapter host.Adapter) error {
	t.Helper()
	pack := realPack()
	binding := realBinding(pack)
	// Mutate the pack content AFTER the binding pinned its digest so the derived
	// content digest no longer matches the pinned ProductRef.Digest.
	pack.Version = "9.9.9-tampered"
	_, err := host.NewSupervisor(host.Config{Pack: pack, Binding: binding, Adapter: adapter})
	if err == nil {
		t.Fatal("expected host.NewSupervisor to refuse a digest-mismatched pack")
	}
	if !errors.Is(err, host.ErrDigestMismatch) {
		t.Fatalf("supervisor error = %v, want ErrDigestMismatch", err)
	}
	return err
}

type countingAdapter struct {
	mu sync.Mutex
	n  int
}

func (a *countingAdapter) Name() string { return "counting" }
func (a *countingAdapter) Dispatch(_ context.Context, _ host.Policy, req *host.HostRequest) (*host.HostResponse, error) {
	a.mu.Lock()
	a.n++
	a.mu.Unlock()
	return &host.HostResponse{ProtocolVersion: host.ProtocolVersion, RequestID: req.RequestID, Status: host.StatusSucceeded, Output: []byte(`{"ok":true}`)}, nil
}
func (a *countingAdapter) dispatches() int { a.mu.Lock(); defer a.mu.Unlock(); return a.n }

// ============================================================================
// 10. replayed dispatch is idempotent
// ============================================================================

func TestAgentReplayedDispatchIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	first, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil || first.Outcome != worker.OutcomeCompleted {
		t.Fatalf("first ProcessDispatch = %+v err=%v", first, err)
	}
	second, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("replay ProcessDispatch: %v", err)
	}
	if second.Outcome != worker.OutcomeDeduped {
		t.Fatalf("replay outcome = %q, want deduped", second.Outcome)
	}
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d, want exactly 1 (no second side effect on replay)", f.host.runs())
	}
	if got := f.getAction(action.ActionRef); got.Status != actions.StatusSucceeded || got.ReceiptRef != first.ActionReceipt.ReceiptRef {
		t.Fatalf("action after replay = %+v, want the FIRST receipt preserved", got)
	}
}

// ============================================================================
// 11. bounded local queue applies backpressure
// ============================================================================

func TestAgentBoundedLocalQueueAppliesBackpressure(t *testing.T) {
	q := newIntakeQueue(3)
	for i := 0; i < 3; i++ {
		if !q.offer(&countingDelivery{}) {
			t.Fatalf("offer %d rejected below the bound", i)
		}
	}
	if q.offer(&countingDelivery{}) {
		t.Fatal("the intake queue accepted a delivery past its bound; it must apply backpressure, never grow unbounded")
	}
	if q.length() != 3 {
		t.Fatalf("queue length = %d, want 3 (bounded, nothing dropped)", q.length())
	}

	f := newFixture(t)
	src := &countingSource{perFetch: 10}

	// A full queue: the session STOPS fetching (backpressure) rather than pulling
	// more durably-owed work than it can buffer.
	full := newIntakeQueue(2)
	full.offer(&countingDelivery{})
	full.offer(&countingDelivery{})
	fetched, err := f.session.fetchInto(context.Background(), src, full)
	if err != nil {
		t.Fatalf("fetchInto: %v", err)
	}
	if fetched != 0 || src.calls() != 0 {
		t.Fatalf("fetched=%d source calls=%d against a full queue, want no fetch (backpressure)", fetched, src.calls())
	}

	// With room, the session fetches at most the available capacity and never
	// exceeds the bound.
	room := newIntakeQueue(2)
	fetched, err = f.session.fetchInto(context.Background(), src, room)
	if err != nil {
		t.Fatalf("fetchInto: %v", err)
	}
	if fetched != 2 || room.length() != 2 {
		t.Fatalf("fetched=%d len=%d, want 2/2 (fetch bounded by available capacity)", fetched, room.length())
	}
	if got := src.maxRequested(); got > 2 {
		t.Fatalf("source asked for %d, want <= available capacity 2 (no unbounded pull)", got)
	}
}

type countingDelivery struct{}

func (d *countingDelivery) Message() actions.DispatchMessage { return actions.DispatchMessage{} }
func (d *countingDelivery) Ack() error                       { return nil }
func (d *countingDelivery) Nak() error                       { return nil }

type countingSource struct {
	mu       sync.Mutex
	perFetch int
	nCalls   int
	maxN     int
}

func (s *countingSource) Fetch(_ context.Context, n int, _ time.Duration) ([]worker.Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nCalls++
	if n > s.maxN {
		s.maxN = n
	}
	count := n
	if count > s.perFetch {
		count = s.perFetch
	}
	out := make([]worker.Delivery, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, &countingDelivery{})
	}
	return out, nil
}

func (s *countingSource) calls() int        { s.mu.Lock(); defer s.mu.Unlock(); return s.nCalls }
func (s *countingSource) maxRequested() int  { s.mu.Lock(); defer s.mu.Unlock(); return s.maxN }

// ============================================================================
// 12. signed self-update rollback (external trust anchor)
// ============================================================================

func TestAgentSignedSelfUpdateRollback(t *testing.T) {
	anchorPub, anchorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	roguePub, roguePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	newUpdater := func(apply func(UpdatePackage) error) *Updater {
		u, err := NewUpdater(anchorPub, "1.0.0", apply)
		if err != nil {
			t.Fatalf("NewUpdater: %v", err)
		}
		return u
	}
	okApply := func(UpdatePackage) error { return nil }

	// Unsigned: refused.
	u := newUpdater(okApply)
	unsigned := SignUpdatePackage(anchorPriv, "2.0.0", []byte("payload"))
	unsigned.Signature = nil
	if err := u.Apply(unsigned); !errors.Is(err, ErrUpdateUnsigned) {
		t.Fatalf("unsigned update err = %v, want ErrUpdateUnsigned", err)
	}
	if u.ActiveVersion() != "1.0.0" {
		t.Fatalf("active version = %q after a refused update, want 1.0.0", u.ActiveVersion())
	}

	// Signed by a ROGUE key (which the package even embeds): refused. The trust
	// anchor is EXTERNAL; the package's own embedded key is never trusted.
	u = newUpdater(okApply)
	rogue := SignUpdatePackage(roguePriv, "2.0.0", []byte("payload"))
	rogue.EmbeddedKey = roguePub // the package vouches for itself — must be ignored
	if err := u.Apply(rogue); !errors.Is(err, ErrUpdateUntrusted) {
		t.Fatalf("rogue-signed update err = %v, want ErrUpdateUntrusted (embedded key must not be trusted)", err)
	}
	if u.ActiveVersion() != "1.0.0" {
		t.Fatalf("active version = %q after a rogue update, want 1.0.0", u.ActiveVersion())
	}

	// Wrong digest: refused.
	u = newUpdater(okApply)
	badDigest := SignUpdatePackage(anchorPriv, "2.0.0", []byte("payload"))
	badDigest.Digest = "sha256:" + hex.EncodeToString(make([]byte, 32))
	if err := u.Apply(badDigest); !errors.Is(err, ErrUpdateDigestMismatch) {
		t.Fatalf("wrong-digest update err = %v, want ErrUpdateDigestMismatch", err)
	}

	// A valid, anchor-signed update whose apply FAILS rolls back to the prior version.
	u = newUpdater(func(UpdatePackage) error { return errors.New("swap failed") })
	valid := SignUpdatePackage(anchorPriv, "2.0.0", []byte("payload"))
	if err := u.Apply(valid); !errors.Is(err, ErrUpdateApplyFailed) {
		t.Fatalf("failed-apply update err = %v, want ErrUpdateApplyFailed", err)
	}
	if u.ActiveVersion() != "1.0.0" {
		t.Fatalf("active version = %q after a failed apply, want the rolled-back 1.0.0", u.ActiveVersion())
	}

	// A valid, anchor-signed update that applies cleanly advances the active version.
	u = newUpdater(okApply)
	if err := u.Apply(valid); err != nil {
		t.Fatalf("valid update: %v", err)
	}
	if u.ActiveVersion() != "2.0.0" {
		t.Fatalf("active version = %q after a clean apply, want 2.0.0", u.ActiveVersion())
	}

	// Health reports the active (rolled-back) version.
	f := newFixture(t)
	rolledBack := newUpdater(func(UpdatePackage) error { return errors.New("swap failed") })
	_ = rolledBack.Apply(valid)
	f.session.updater = rolledBack
	if got := f.session.Health().AgentVersion; got != "1.0.0" {
		t.Fatalf("health agent version = %q, want the active rolled-back version 1.0.0", got)
	}
}

// ============================================================================
// 13. CheckReady fails closed without concrete seams
// ============================================================================

func TestAgentCheckReadyFailsClosedWithoutConcreteSeams(t *testing.T) {
	signer, key := newReceiptSigner(t)
	svc, err := actions.NewService(actions.NewMemoryStore(), actions.NewMemoryAuditSink(),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(sdkaudit.NewKeySet(key))))
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{binding: worker.ResolvedBinding{Host: &fakeHost{result: successResult()}}}
	obs := newFakeObservations()
	journal := newMemJournal()
	full := Config{ActionPlane: svc, Resolver: resolver, Signer: signer, Observations: obs, Journal: journal, Identity: agentIdentity(), Pin: agentPin()}

	cases := []struct {
		name  string
		mutar func(*Config)
	}{
		{"nil action plane", func(c *Config) { c.ActionPlane = nil }},
		{"nil resolver", func(c *Config) { c.Resolver = nil }},
		{"nil signer", func(c *Config) { c.Signer = nil }},
		{"nil observations", func(c *Config) { c.Observations = nil }},
		{"nil journal", func(c *Config) { c.Journal = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full
			tc.mutar(&cfg)
			s, err := New(cfg, WithIDGenerator(sequentialIDs()))
			if err != nil {
				// A nil ActionPlane may be rejected at construction; that is also fail-closed.
				if tc.name == "nil action plane" {
					return
				}
				t.Fatalf("New: %v", err)
			}
			if err := s.CheckReady(context.Background()); !errors.Is(err, ErrNotReady) {
				t.Fatalf("CheckReady = %v, want ErrNotReady (fail closed, no pass-stub)", err)
			}
		})
	}

	s, err := New(full, WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReady(context.Background()); err != nil {
		t.Fatalf("CheckReady with all seams wired = %v, want ready", err)
	}
}

// ============================================================================
// 14. never leaks connector topology to an outward surface
// ============================================================================

func TestAgentNeverLeaksConnectorTopology(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))
	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}

	forbidden := []string{privateConn, privateRes, privateCred, "approve", "write"}
	// The outward health view carries no connector topology.
	health := f.session.Health()
	for _, s := range []string{health.IdentityURI, health.AgentVersion, health.DurableConsumer, health.PendingSeam} {
		for _, bad := range forbidden {
			if s != "" && s == bad {
				t.Fatalf("health view leaked connector topology %q", bad)
			}
		}
	}
	// The Agent-facing ActionReceipt carries no connector topology.
	if res.ActionReceipt != nil {
		for _, s := range []string{res.ActionReceipt.ReceiptRef, res.ActionReceipt.ActionRef, res.ActionReceipt.Capability, res.ActionReceipt.ParameterHash, res.ActionReceipt.ReceiptSchema, res.ActionReceipt.ResultHash} {
			for _, bad := range []string{privateConn, privateRes, privateCred} {
				if s == bad {
					t.Fatalf("ActionReceipt leaked connector topology %q", bad)
				}
			}
		}
	}
	// The Agent-facing ObservationReceipts carry no connector topology.
	for _, o := range res.ObservationReceipts {
		for _, s := range []string{o.ObservationRef, o.ActionRef, o.Source, o.Authority, o.EvidenceRef} {
			for _, bad := range []string{privateConn, privateRes, privateCred} {
				if s == bad {
					t.Fatalf("ObservationReceipt leaked connector topology %q", bad)
				}
			}
		}
	}
}

// ============================================================================
// 15. identical provenance as the central worker (no forked classifier)
// ============================================================================

func TestAgentUsesIdenticalProvenanceAsWorker(t *testing.T) {
	ctx := context.Background()
	// A HARD-CODED provenance oracle — deliberately NOT computed from
	// worker.ClassifyHostResult (the function under test), so a mutation of the
	// classifier moves behavior WITHOUT moving this expectation and the mismatch
	// is caught here (and in the worker's own tests) rather than staying green.
	cases := []struct {
		name         string
		status       host.Status
		wantStatus   runtime.ActionStatus
		wantUncertain bool
	}{
		{"succeeded", host.StatusSucceeded, runtime.StatusSucceeded, false},
		{"connector failed", host.StatusFailed, runtime.StatusFailed, false},
		{"connector denied", host.StatusDenied, runtime.StatusFailed, false},
		{"policy denied", host.StatusDeniedPolicy, runtime.StatusFailed, false},
		{"execution uncertain", host.StatusExecutionUncertain, "", true},
		{"resource exhausted", host.StatusResourceExhausted, "", true},
		{"waiting external receipt", host.StatusWaitingExternalReceipt, "", true},
		{"unspecified", host.StatusUnspecified, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.host.result = host.Result{Status: tc.status, Output: successResult().Output, OutputHash: successResult().OutputHash}
			action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
			res, err := f.session.ProcessDispatch(ctx, msg)
			if err != nil {
				t.Fatalf("ProcessDispatch: %v", err)
			}

			if tc.wantUncertain {
				if res.Outcome != worker.OutcomeResultUnknown || res.ActionReceipt != nil {
					t.Fatalf("uncertain host status %q: outcome=%q receipt=%v, want result_unknown with NO receipt", tc.status, res.Outcome, res.ActionReceipt)
				}
				if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
					t.Fatalf("action status = %q, want result_unknown", got)
				}
				return
			}
			if res.Outcome != worker.OutcomeCompleted || res.ActionReceipt == nil {
				t.Fatalf("bounded host status %q: outcome=%q, want a completed signed receipt", tc.status, res.Outcome)
			}
			if res.ActionReceipt.Status != tc.wantStatus {
				t.Fatalf("receipt status = %q, want the hard-coded expectation %q (the agent must NOT fork the worker's provenance)", res.ActionReceipt.Status, tc.wantStatus)
			}
		})
	}
}

// ============================================================================
// concurrency: many redeliveries of one Action -> host runs exactly once
// (race detector unavailable without cgo; -count=N + this test is the honest substitute)
// ============================================================================

func TestAgentConcurrentRedeliveriesExecuteHostExactlyOnce(t *testing.T) {
	f := newFixture(t)
	f.host.delay = 5 * time.Millisecond
	_, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	const goroutines = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	completed := 0
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			res, err := f.session.ProcessDispatch(context.Background(), msg)
			if err != nil {
				return
			}
			if res.Outcome == worker.OutcomeCompleted {
				mu.Lock()
				completed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if f.host.runs() != 1 {
		t.Fatalf("host runs = %d under %d concurrent redeliveries, want exactly 1", f.host.runs(), goroutines)
	}
	if completed != 1 {
		t.Fatalf("completions = %d, want exactly 1 authoritative completion", completed)
	}
}

// ============================================================================
// resume from executing with NO journaled receipt -> result_unknown
// ============================================================================

func TestAgentResumeExecutingWithoutJournalIsResultUnknown(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))

	// The action was left executing by a prior attempt (barrier crossed), the edge
	// journal holds NO receipt for this dispatch_ref, and THIS fresh session does
	// not own it in-process.
	if _, err := f.svc.MarkExecuting(ctx, f.principal, action.ActionRef); err != nil {
		t.Fatalf("MarkExecuting (executing setup): %v", err)
	}
	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch: %v", err)
	}
	if res.Outcome != worker.OutcomeResultUnknown || res.ActionReceipt != nil {
		t.Fatalf("res = %+v, want result_unknown with no receipt (no journaled receipt to re-apply, so never a blind retry)", res)
	}
	if f.host.runs() != 0 {
		t.Fatal("the host was run for an action left executing with no journaled receipt; blind re-execution is forbidden")
	}
	if got := f.getAction(action.ActionRef).Status; got != actions.StatusResultUnknown {
		t.Fatalf("action status = %q, want result_unknown", got)
	}
}

// ============================================================================
// edge journal outage is transient (no ack, no fabricated/dropped outcome)
// ============================================================================

var errJournalOutage = errors.New("edge journal unavailable")

func TestAgentEdgeJournalOutageIsTransient(t *testing.T) {
	ctx := context.Background()

	t.Run("record_receipt_outage_before_central_apply", func(t *testing.T) {
		f := newFixture(t)
		f.journal.recordReceiptErr = errJournalOutage
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
		res, err := f.session.ProcessDispatch(ctx, msg)
		if !errors.Is(err, ErrRecordReceipt) {
			t.Fatalf("err = %v, want a transient ErrRecordReceipt (do not ack, do not apply centrally without a durable edge record)", err)
		}
		if res.Outcome != "" || res.ActionReceipt != nil {
			t.Fatalf("res = %+v, want an empty transient result", res)
		}
		if f.host.runs() != 1 {
			t.Fatalf("host runs = %d, want 1", f.host.runs())
		}
		// The central apply never happened: the action stays executing (barrier
		// crossed), never succeeded on a journal outage.
		if got := f.getAction(action.ActionRef).Status; got != actions.StatusExecuting {
			t.Fatalf("action status = %q, want executing (no central apply on a journal outage)", got)
		}
	})

	t.Run("load_receipt_outage_on_resume", func(t *testing.T) {
		f := newFixture(t)
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 0))
		if _, err := f.svc.MarkExecuting(ctx, f.principal, action.ActionRef); err != nil {
			t.Fatalf("MarkExecuting: %v", err)
		}
		f.journal.loadReceiptErr = errJournalOutage
		res, err := f.session.ProcessDispatch(ctx, msg)
		if !errors.Is(err, errJournalOutage) {
			t.Fatalf("err = %v, want the transient journal outage (nak/resume, never a fabricated verdict)", err)
		}
		if res.Outcome != "" || res.ActionReceipt != nil {
			t.Fatalf("res = %+v, want an empty transient result", res)
		}
		if got := f.getAction(action.ActionRef).Status; got != actions.StatusExecuting {
			t.Fatalf("action status = %q, want executing (a journal outage never resolves the outcome)", got)
		}
	})

	t.Run("load_observation_outage_on_resume", func(t *testing.T) {
		f := newFixture(t)
		action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))
		// Complete the action cleanly first so its declared need is journaled.
		if _, err := f.session.ProcessDispatch(ctx, msg); err != nil {
			t.Fatalf("first ProcessDispatch: %v", err)
		}
		if f.getAction(action.ActionRef).Status != actions.StatusSucceeded {
			t.Fatal("setup: action must be succeeded")
		}
		// Now a journal read outage on a redelivery must be transient (resume),
		// never a dropped or fabricated observation.
		f.journal.loadObsErr = errJournalOutage
		res, err := f.session.ProcessDispatch(ctx, msg)
		if !errors.Is(err, errJournalOutage) {
			t.Fatalf("err = %v, want the transient journal outage (nak/resume)", err)
		}
		if res.Outcome != "" {
			t.Fatalf("res outcome = %q, want an empty transient result", res.Outcome)
		}
	})
}

// ============================================================================
// a structurally-rejected observation is surfaced, never fabricated or looped
// ============================================================================

func TestAgentObservationRejectionSurfacedNeverFabricated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// The producer returns a receipt that does NOT bind the requested need, so the
	// worker's integrity guard rejects it (worker.ErrObservationRejected).
	f.obs.mismatch = true
	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))

	res, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("ProcessDispatch = %v, want a clean ack (a structural rejection is not transient)", err)
	}
	// The technically-authoritative ActionReceipt is independent and stays complete.
	if res.Outcome != worker.OutcomeCompleted || f.getAction(action.ActionRef).Status != actions.StatusSucceeded {
		t.Fatalf("action must stay succeeded despite an observation rejection: %+v", res)
	}
	// The rejection is SURFACED (never swallowed), the need is NOT fabricated into
	// the set, and it never journaled a bogus observation.
	if res.ObservationErr == nil || !errors.Is(res.ObservationErr, worker.ErrObservationRejected) {
		t.Fatalf("observation err = %v, want ErrObservationRejected surfaced", res.ObservationErr)
	}
	if len(res.ObservationReceipts) != 0 {
		t.Fatalf("observation receipts = %+v, want none (a mis-bound need must never be fabricated)", res.ObservationReceipts)
	}
	if f.journal.observationCount() != 0 {
		t.Fatalf("journaled observations = %d, want 0 (a rejected need is never journaled)", f.journal.observationCount())
	}
	// It never poison-loops: a redelivery returns cleanly (ack) with the same
	// surfaced rejection, not a transient nak forever.
	res2, err := f.session.ProcessDispatch(ctx, msg)
	if err != nil {
		t.Fatalf("redelivery ProcessDispatch = %v, want a clean ack (no poison loop)", err)
	}
	if res2.ObservationErr == nil || !errors.Is(res2.ObservationErr, worker.ErrObservationRejected) {
		t.Fatalf("redelivery observation err = %v, want ErrObservationRejected still surfaced", res2.ObservationErr)
	}
}

// ============================================================================
// concurrent redeliveries of a SUCCEEDED action observe each need exactly once
// (race detector unavailable without cgo; -count=N + this test is the honest substitute)
// ============================================================================

func TestAgentConcurrentSucceededRedeliveriesObserveNeedOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.obs.observeDelay = 5 * time.Millisecond // widen the LoadObservation->RecordObservation window
	f.obs.failNeedsTransient["n1"] = 1         // defer n1 on the first pass -> succeeded-but-un-journaled

	action, msg := f.dispatch(actionRequest(t, approveCap, "idem-000000000001", 1))
	// First pass: the ActionReceipt applies (succeeded) but n1 is deferred, so it
	// is NOT yet journaled.
	if _, err := f.session.ProcessDispatch(ctx, msg); err == nil {
		t.Fatal("expected a transient observation disconnect on the first pass, got nil")
	}
	if f.getAction(action.ActionRef).Status != actions.StatusSucceeded {
		t.Fatal("the ActionReceipt must be applied (succeeded) with n1 deferred")
	}
	base := f.obs.countFor("n1")

	// Two concurrent redeliveries of the succeeded Action race to observe n1.
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, _ = f.session.ProcessDispatch(context.Background(), msg)
		}()
	}
	wg.Wait()

	// n1 is observed EXACTLY once across the two concurrent redeliveries: the
	// in-process ownership guard makes "produced at most once" uniform on the
	// resume-observation path, not only on the execution path.
	if got := f.obs.countFor("n1") - base; got != 1 {
		t.Fatalf("Observe(n1) during concurrent redeliveries = %d, want exactly 1 (the resume path must be single-owner)", got)
	}
	if _, ok, _ := f.journal.LoadObservation(ctx, action.TenantRef, action.ActionRef, "n1"); !ok {
		t.Fatal("n1 was never journaled after the concurrent resume")
	}
}

// --- outbound dial fails closed on plaintext --------------------------------

func TestAgentOutboundDialRefusesPlaintext(t *testing.T) {
	// The agent is a CLIENT that only ever dials; the production dial path refuses
	// a nil mTLS config so it can never establish a plaintext outbound session.
	if _, err := ConnectOutbound(OutboundConfig{URL: "nats://central.acme.example:4222"}); err == nil {
		t.Fatal("ConnectOutbound accepted a nil mTLS client config; production must never dial plaintext")
	}
}

// --- cert-derived identity (registration) -----------------------------------

type fakeIdentityProvider struct{ uri string }

func (p fakeIdentityProvider) IdentityURI() string { return p.uri }

func TestAgentCertDerivedIdentity(t *testing.T) {
	id, err := CertDerivedIdentity(fakeIdentityProvider{uri: "agentnexus://enterprise/acme/service/connector-agent/installation/agent-7"})
	if err != nil {
		t.Fatalf("CertDerivedIdentity: %v", err)
	}
	if id.Enterprise != "acme" || id.Installation != "agent-7" {
		t.Fatalf("identity = %+v, want enterprise=acme installation=agent-7", id)
	}

	// A URI for a different service is not a connector-agent identity.
	if _, err := CertDerivedIdentity(fakeIdentityProvider{uri: "agentnexus://enterprise/acme/service/gateway-api"}); !errors.Is(err, ErrIdentityNotCertDerived) {
		t.Fatalf("wrong-service identity err = %v, want ErrIdentityNotCertDerived", err)
	}
	// A connector-agent URI without an installation is not a bound installation.
	if _, err := CertDerivedIdentity(fakeIdentityProvider{uri: "agentnexus://enterprise/acme/service/connector-agent"}); !errors.Is(err, ErrIdentityNotCertDerived) {
		t.Fatalf("no-installation identity err = %v, want ErrIdentityNotCertDerived", err)
	}
	// A malformed URI is refused.
	if _, err := CertDerivedIdentity(fakeIdentityProvider{uri: "not-a-uri"}); !errors.Is(err, ErrIdentityNotCertDerived) {
		t.Fatalf("malformed identity err = %v, want ErrIdentityNotCertDerived", err)
	}
}

// --- shared real pack/binding (mirrors worker_test) -------------------------

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
	sum := sha256.Sum256([]byte("agent-test-schema:" + seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
