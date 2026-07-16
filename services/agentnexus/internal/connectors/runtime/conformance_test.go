package runtime_test

// conformance_test.go is the GA Task 7 dual-topology conformance matrix. It
// qualifies the four generic connector families (http/openapi, db-readonly,
// file/s3, webhook) to the frozen GA contracts (Product Pack v1, Secret Handles,
// isolated host, ActionReceipt/ObservationReceipt) and proves each runs
// IDENTICALLY through BOTH execution topologies — the central worker
// (worker.ProcessDispatch) and the outbound Connector Agent
// (agent.ProcessDispatch) — over the SAME real isolated host.Supervisor, real
// actions.Service (MemoryStore + signed-receipt verifier), real ed25519 receipt
// signer and real secrets.Client over an in-process Secret Provider. The
// BindingResolver and ObservationProducer are TEST seams (exactly like the
// existing worker/agent unit tests), standing in for the deferred Postgres
// resolver and evidence producer — never a shipped pass-stub.
//
// Run with: go test ./internal/connectors/runtime/ -run TestConformance

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	sdkruntime "github.com/astraclawteam/agentnexus/sdk/go/runtime"
	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/agent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	runtime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
	"gopkg.in/yaml.v3"
)

const (
	confTenant       = "tenant-1"
	confCallerToken  = "task7-caller-token"
	confMasterCanary = "MASTER-CANARY-DO-NOT-LEAK-task7-9f2c"
	confCredRef      = "secret:task7:connector-token"
	confConnectorRef = "conn_private_instance_task7"
	confEndpointURL  = "https://connector.internal.example:8443/reserved-path"
)

// coords is the server-side resolved operation the test BindingResolver returns.
type coords struct {
	capability string
	resource   string
	operation  string
	action     string
	needs      int
}

// runResult is one topology's outcome for one driven ActionRequest.
type runResult struct {
	outcome  worker.Outcome
	receipt  *sdkruntime.ActionReceipt
	obs      []sdkruntime.ObservationReceipt
	action   actions.Action
	obsErr   error
	provider *secretprovider.LocalProvider
}

// ---------------------------------------------------------------------------
// fixture loading
// ---------------------------------------------------------------------------

// parsePack loads a Product Pack v1 YAML fixture via yaml -> map[string]any ->
// json.Marshal -> connector.ParseProductPack. The SDK structs are json-tagged
// only, so the map/json bridge is mandatory: a direct yaml.Unmarshal into the
// struct would silently miss every json-tagged member.
func parsePack(t *testing.T, name string) connector.ProductPack {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "connectors", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("yaml unmarshal %s: %v", name, err)
	}
	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json marshal %s: %v", name, err)
	}
	pack, err := connector.ParseProductPack(jsonBytes)
	if err != nil {
		t.Fatalf("ParseProductPack %s: %v", name, err)
	}
	if err := connector.ValidateDevelopmentPack(pack); err != nil {
		t.Fatalf("ValidateDevelopmentPack %s: %v", name, err)
	}
	pack.Digest = connector.PackContentDigest(pack)
	return pack
}

// buildBinding builds a CustomerBinding pinning the pack's content digest and
// mapping the capability to the resolved resource, with one declared endpoint
// and one secret reference.
func buildBinding(pack connector.ProductPack, capability, resource, endpointName string) connector.CustomerBinding {
	return connector.CustomerBinding{
		SchemaVersion:    connector.CustomerBindingSchemaVersion,
		BindingKey:       "task7-binding",
		Customer:         connector.CustomerRef{Name: "acme"},
		Product:          connector.ProductRef{ProductKey: pack.ProductKey, Version: pack.Version, Digest: pack.Digest},
		Endpoints:        []connector.Endpoint{{Name: endpointName, URL: confEndpointURL}},
		Secrets:          []connector.SecretRef{{Name: "connector-token", Ref: "secretref://vault/acme/connector"}},
		ResourceMappings: []connector.ResourceMapping{{Capability: capability, Resource: resource}},
	}
}

// ---------------------------------------------------------------------------
// test seams (BindingResolver + ObservationProducer) — the deferred concrete
// deps, mirrored exactly like the worker/agent unit-test fakes.
// ---------------------------------------------------------------------------

type fixedResolver struct{ binding worker.ResolvedBinding }

func (r fixedResolver) Resolve(context.Context, string, string) (worker.ResolvedBinding, error) {
	return r.binding, nil
}

// testObservations is the pack-aware ObservationProducer test seam. It mints a
// valid signed ObservationReceipt binding the requested VerificationBinding with
// the pack postcondition probe's source-authority/version-semantics/freshness,
// and returns worker.ErrObservationRejected for a need whose postcondition is
// not a declared probe (fail closed, never fabricate). It never runs a write —
// the observation is the declared READ probe, run separately from the write.
type testObservations struct {
	pack  connector.ProductPack
	mu    sync.Mutex
	count int
}

func newTestObservations(pack connector.ProductPack) *testObservations {
	return &testObservations{pack: pack}
}

func (o *testObservations) probeFor(postconditionID string) (connector.PostconditionProbe, bool) {
	for _, c := range o.pack.Capabilities {
		for _, p := range c.PostconditionProbes {
			if p.ProbeID == postconditionID {
				return p, true
			}
		}
	}
	return connector.PostconditionProbe{}, false
}

func (o *testObservations) Observe(_ context.Context, _ string, b sdkruntime.VerificationBinding) (sdkruntime.ObservationReceipt, error) {
	probe, ok := o.probeFor(b.PostconditionID)
	if !ok {
		return sdkruntime.ObservationReceipt{}, worker.ErrObservationRejected
	}
	o.mu.Lock()
	o.count++
	o.mu.Unlock()
	at := time.Unix(1_700_000_000, 0).UTC()
	sum := sha256.Sum256([]byte(b.VerificationNeedID))
	return sdkruntime.ObservationReceipt{
		ObservationRef:     "obs_0123456789abcdef",
		ActionRef:          b.ActionRef,
		ParameterHash:      b.ParameterHash,
		PostconditionID:    b.PostconditionID,
		VerificationNeedID: b.VerificationNeedID,
		Source:             b.DataClass,
		SourceVersion:      1,
		Authority:          string(probe.SourceAuthority),
		ObservedAt:         at,
		FreshUntil:         at.Add(time.Duration(probe.FreshnessBoundSeconds) * time.Second),
		ObservationHash:    "sha256:" + hex.EncodeToString(sum[:]),
		EvidenceRef:        "evd_0123456789abcdef",
		AuditRefID:         "aud_obs_1",
		Signature:          sdkruntime.Signature{Algorithm: sdkruntime.SignatureAlgorithmEd25519, KeyID: "obs-1", Value: "BBBB"},
	}, nil
}

// ---------------------------------------------------------------------------
// signing / actions / request builders
// ---------------------------------------------------------------------------

func newReceiptSigner(t *testing.T, id string) (*audit.Ed25519AuditSigner, sdkaudit.SigningKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := audit.NewEd25519AuditSigner(id, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, sdkaudit.SigningKey{KeyID: id, Algorithm: sdkruntime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyActive}
}

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

func requesterPrincipal() sdkruntime.PrincipalContext {
	now := time.Now().UTC()
	return sdkruntime.PrincipalContext{
		TenantRef: confTenant, PrincipalRef: "agent-1", AgentClientRef: "agc_client-1", AgentReleaseRef: "rel-1",
		TrustClass: sdkruntime.TrustFirstParty, OrgSnapshotRef: "org-1", VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func connectorIdentity() worker.Identity {
	return worker.Identity{PrincipalRef: "connector-system", AgentClientRef: "agc_connector", AgentReleaseRef: "rel-1", OrgSnapshotRef: "org-system"}
}

func newActionRequest(t *testing.T, capability string, needs int) sdkruntime.ActionRequest {
	t.Helper()
	params, hash, err := sdkruntime.BuildParameters(map[string]any{"amount": 100})
	if err != nil {
		t.Fatalf("build parameters: %v", err)
	}
	now := time.Now().UTC()
	req := sdkruntime.ActionRequest{
		RequestID:          "req-task7",
		BusinessContextRef: "wc_0123456789abcdef",
		Capability:         capability,
		Parameters:         params,
		ParameterHash:      hash,
		Purpose:            "execute",
		RiskDecision: sdkruntime.RiskDecision{
			DecisionID: "dec-1", Authority: "acme-risk", RiskLevel: sdkruntime.RiskMedium,
			Capability: capability, ParameterHash: hash, BusinessContextRef: "wc_0123456789abcdef",
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			Signature: sdkruntime.Signature{Algorithm: sdkruntime.SignatureAlgorithmEd25519, KeyID: "k1", Value: "AAAA"},
		},
		IdempotencyKey:        "idempotency-key-task7-0001",
		ExpiresAt:             now.Add(30 * time.Minute),
		ExpectedReceiptSchema: "connector.receipt.v1",
	}
	for i := 0; i < needs; i++ {
		req.Postconditions = append(req.Postconditions, sdkruntime.PostconditionSpec{PostconditionID: "post_send_state", Kind: "state", Reference: "webhook.notify.state"})
		req.VerificationNeeds = append(req.VerificationNeeds, sdkruntime.VerificationNeed{NeedID: "n1", PostconditionID: "post_send_state", DataClass: "webhook_delivery_status"})
	}
	return req
}

// seededProvider builds an in-process Secret Provider seeded with the master
// canary (which must never leak) for the credential reference.
func seededProvider(t *testing.T) *secretprovider.LocalProvider {
	t.Helper()
	provider := secretprovider.NewLocalProvider(secretprovider.WithCallerToken(confCallerToken))
	if _, err := provider.SetMaster(confCredRef, confMasterCanary); err != nil {
		t.Fatalf("SetMaster: %v", err)
	}
	return provider
}

// buildSupervisor wires the runtime-backed host adapter (family + injected fake
// client + secret redeemer) into a REAL isolated host.Supervisor. The same
// secrets.Client is the supervisor's Secret broker (AcquireHandle) AND the
// connector's redeemer (Redeem) — one acquire + one redeem per operation.
func buildSupervisor(t *testing.T, pack connector.ProductPack, binding connector.CustomerBinding, fam runtime.FamilyAdapter, provider *secretprovider.LocalProvider) *host.Supervisor {
	t.Helper()
	broker := secrets.NewClient(provider, confCallerToken)
	adapter := runtime.NewConnectorHostAdapter(fam, broker, pack, binding)
	sup, err := host.NewSupervisor(host.Config{Pack: pack, Binding: binding, Adapter: adapter, Secrets: broker})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}
	return sup
}

// dispatchOne drives request -> grant -> dispatch -> republish and returns the
// durable dispatch message exactly as the outbox would publish it.
func dispatchOne(t *testing.T, svc *actions.Service, publisher *recordingPublisher, req sdkruntime.ActionRequest) (actions.Action, actions.DispatchMessage) {
	t.Helper()
	ctx := context.Background()
	principal := requesterPrincipal()
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if _, err := svc.RepublishPending(ctx, principal.TenantRef); err != nil {
		t.Fatalf("RepublishPending: %v", err)
	}
	msgs := publisher.messages()
	stored, err := svc.GetAction(ctx, principal, action.ActionRef)
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	return stored, msgs[len(msgs)-1]
}

type recordingPublisher struct {
	mu   sync.Mutex
	sent []actions.DispatchMessage
}

func (p *recordingPublisher) PublishDispatch(_ context.Context, m actions.DispatchMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, m)
	return nil
}

func (p *recordingPublisher) messages() []actions.DispatchMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]actions.DispatchMessage(nil), p.sent...)
}

func newActionsService(t *testing.T, key sdkaudit.SigningKey) (*actions.Service, *recordingPublisher) {
	t.Helper()
	publisher := &recordingPublisher{}
	svc, err := actions.NewService(actions.NewMemoryStore(), actions.NewMemoryAuditSink(),
		actions.WithIDGenerator(sequentialIDs()),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(sdkaudit.NewKeySet(key))),
		actions.WithPublisher(publisher),
	)
	if err != nil {
		t.Fatalf("actions.NewService: %v", err)
	}
	return svc, publisher
}

// ---------------------------------------------------------------------------
// topology drivers — the SAME ActionRequest, one through the central worker and
// one through the outbound agent, over the shared isolated host.
// ---------------------------------------------------------------------------

func driveWorker(t *testing.T, pack connector.ProductPack, binding connector.CustomerBinding, c coords, fam runtime.FamilyAdapter) runResult {
	t.Helper()
	signer, key := newReceiptSigner(t, "connector-worker-1")
	svc, publisher := newActionsService(t, key)
	provider := seededProvider(t)
	sup := buildSupervisor(t, pack, binding, fam, provider)
	resolver := fixedResolver{binding: worker.ResolvedBinding{Host: sup, Resource: c.resource, Operation: c.operation, OperationAction: c.action, CredentialRef: confCredRef, ConnectorRef: confConnectorRef}}
	obs := newTestObservations(pack)
	w, err := worker.New(worker.Config{Actions: svc, Resolver: resolver, Signer: signer, Observations: obs, Identity: connectorIdentity()}, worker.WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}
	action, msg := dispatchOne(t, svc, publisher, newActionRequest(t, c.capability, c.needs))
	res, err := w.ProcessDispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("worker.ProcessDispatch: %v", err)
	}
	final, err := svc.GetAction(context.Background(), requesterPrincipal(), action.ActionRef)
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	return runResult{outcome: res.Outcome, receipt: res.ActionReceipt, obs: res.ObservationReceipts, action: final, obsErr: res.ObservationErr, provider: provider}
}

func driveAgent(t *testing.T, pack connector.ProductPack, binding connector.CustomerBinding, c coords, fam runtime.FamilyAdapter) runResult {
	t.Helper()
	signer, key := newReceiptSigner(t, "connector-agent-1")
	svc, publisher := newActionsService(t, key)
	provider := seededProvider(t)
	sup := buildSupervisor(t, pack, binding, fam, provider)
	resolver := fixedResolver{binding: worker.ResolvedBinding{Host: sup, Resource: c.resource, Operation: c.operation, OperationAction: c.action, CredentialRef: confCredRef, ConnectorRef: confConnectorRef}}
	obs := newTestObservations(pack)
	s, err := agent.New(agent.Config{
		ActionPlane: svc, Resolver: resolver, Signer: signer, Observations: obs, Journal: newMemJournal(),
		Identity: connectorIdentity(), Pin: agent.Pin{TenantRef: confTenant, Capabilities: []string{c.capability}},
		Version: "1.0.0", IdentityURI: "agentnexus://enterprise/acme/service/connector-agent/installation/agent-7",
	}, agent.WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	action, msg := dispatchOne(t, svc, publisher, newActionRequest(t, c.capability, c.needs))
	res, err := s.ProcessDispatch(context.Background(), msg)
	if err != nil {
		t.Fatalf("agent.ProcessDispatch: %v", err)
	}
	final, err := svc.GetAction(context.Background(), requesterPrincipal(), action.ActionRef)
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	return runResult{outcome: res.Outcome, receipt: res.ActionReceipt, obs: res.ObservationReceipts, action: final, obsErr: res.ObservationErr, provider: provider}
}

// driveHost runs one operation directly through the isolated host so the test
// can inspect the bounded host.Result (and, critically, its topology-free
// Output bytes that the ActionReceipt only hash-binds).
func driveHost(t *testing.T, pack connector.ProductPack, binding connector.CustomerBinding, c coords, fam runtime.FamilyAdapter) host.Result {
	t.Helper()
	provider := seededProvider(t)
	sup := buildSupervisor(t, pack, binding, fam, provider)
	return sup.Run(context.Background(), host.Operation{
		RequestID: "dispatch-task7", Capability: c.capability, Resource: c.resource, Operation: c.operation, Action: c.action, CredentialRef: confCredRef,
	})
}

// ---------------------------------------------------------------------------
// equivalence + safety assertions
// ---------------------------------------------------------------------------

// assertEquivalent proves the two topologies produced the equivalent outcome:
// same terminal outcome, and (on a completion) the same ActionReceipt technical
// facts (status/capability/parameter_hash/result_hash) and the same deduplicated
// ObservationReceipt set. Signatures and opaque refs legitimately differ (each
// topology signs with its own key and mints its own refs) and are excluded.
func assertEquivalent(t *testing.T, w, a runResult) {
	t.Helper()
	if w.outcome != a.outcome {
		t.Fatalf("outcome mismatch: worker=%q agent=%q", w.outcome, a.outcome)
	}
	if (w.receipt == nil) != (a.receipt == nil) {
		t.Fatalf("receipt presence mismatch: worker=%v agent=%v", w.receipt != nil, a.receipt != nil)
	}
	if w.receipt != nil {
		if w.receipt.Status != a.receipt.Status || w.receipt.Capability != a.receipt.Capability ||
			w.receipt.ParameterHash != a.receipt.ParameterHash || w.receipt.ResultHash != a.receipt.ResultHash {
			t.Fatalf("ActionReceipt technical facts diverge:\n worker: status=%s cap=%s ph=%s rh=%s\n  agent: status=%s cap=%s ph=%s rh=%s",
				w.receipt.Status, w.receipt.Capability, w.receipt.ParameterHash, w.receipt.ResultHash,
				a.receipt.Status, a.receipt.Capability, a.receipt.ParameterHash, a.receipt.ResultHash)
		}
	}
	if !sameObservationSet(w.obs, a.obs) {
		t.Fatalf("ObservationReceipt sets diverge:\n worker=%s\n  agent=%s", obsDigest(w.obs), obsDigest(a.obs))
	}
}

func sameObservationSet(w, a []sdkruntime.ObservationReceipt) bool {
	return obsDigest(w) == obsDigest(a)
}

// obsDigest is a stable digest of the SEMANTIC observation set (need,
// postcondition, source, authority, version, freshness window) — the fields the
// two topologies must agree on. Opaque refs and signatures are excluded.
func obsDigest(obs []sdkruntime.ObservationReceipt) string {
	parts := make([]string, 0, len(obs))
	for _, o := range obs {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%s|%d|%s", o.VerificationNeedID, o.PostconditionID, o.Source, o.Authority, o.SourceVersion, o.FreshUntil.Sub(o.ObservedAt)))
	}
	// insertion order is deterministic across topologies (same declared needs).
	return strings.Join(parts, ";")
}

// topologySecrets is the set of unambiguous connector topology/credentials that
// must never reach an Agent-facing surface: the credential ref, the master, the
// connector instance id, and the endpoint URL/host. Semantic labels (the
// capability, a source authority, a declared endpoint NAME) are Agent-facing by
// design and are NOT in this set.
func topologySecrets() []string {
	return []string{confCredRef, confMasterCanary, confConnectorRef, confEndpointURL, "connector.internal.example"}
}

// assertNoTopologyLeak proves the connector's Output carries no connector
// topology/credential. Callers pass any additional internal coordinates (e.g. a
// read's resolved resource name) that must also be absent.
func assertNoTopologyLeak(t *testing.T, output []byte, extra ...string) {
	t.Helper()
	rendered := string(output)
	for _, forbidden := range append(topologySecrets(), extra...) {
		if forbidden == "" {
			continue
		}
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("connector Output leaked topology %q: %s", forbidden, rendered)
		}
	}
}

// assertReceiptClean proves the Agent-facing ActionReceipt carries no connector
// topology/credential in any populated field, and that the result payload is
// hash-bound only (never embedded).
func assertReceiptClean(t *testing.T, r *sdkruntime.ActionReceipt) {
	t.Helper()
	if r == nil {
		return
	}
	if len(r.Result) != 0 {
		t.Fatalf("ActionReceipt embedded the result payload (%s); it must be hash-bound only", string(r.Result))
	}
	for _, s := range []string{r.ReceiptRef, r.ActionRef, string(r.Status), r.Capability, r.ParameterHash, r.ReceiptSchema, r.ResultHash} {
		for _, forbidden := range topologySecrets() {
			if strings.Contains(s, forbidden) {
				t.Fatalf("ActionReceipt field %q leaked topology %q", s, forbidden)
			}
		}
	}
}

// masterHMAC is the HMAC a hostile connector would produce if it signed with the
// MASTER credential instead of derived material; the test proves the real
// signature never equals it.
func masterHMAC(payload []byte) string {
	mac := hmac.New(sha256.New, []byte(confMasterCanary))
	mac.Write(payload)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// decodeReadOutput decodes a read family's topology-free output.
func decodeReadOutput(t *testing.T, output []byte) readOutputView {
	t.Helper()
	var out readOutputView
	if err := json.Unmarshal(output, &out); err != nil {
		t.Fatalf("decode read output: %v (raw %s)", err, string(output))
	}
	return out
}

type readOutputView struct {
	Records       []map[string]any `json:"records"`
	Source        string           `json:"source"`
	SourceVersion int64            `json:"source_version"`
	Authority     string           `json:"authority"`
	FreshUntil    time.Time        `json:"fresh_until"`
	ObjectVersion string           `json:"object_version"`
}

func mustSucceed(t *testing.T, r runResult, label string) {
	t.Helper()
	if r.outcome != worker.OutcomeCompleted || r.receipt == nil || r.receipt.Status != sdkruntime.StatusSucceeded {
		t.Fatalf("%s: outcome=%q receipt=%+v, want completed+succeeded", label, r.outcome, r.receipt)
	}
	if r.action.Status != actions.StatusSucceeded {
		t.Fatalf("%s: action status=%q, want succeeded", label, r.action.Status)
	}
}

func mustFailedReceipt(t *testing.T, r runResult, label string) {
	t.Helper()
	if r.outcome != worker.OutcomeCompleted || r.receipt == nil || r.receipt.Status != sdkruntime.StatusFailed {
		t.Fatalf("%s: outcome=%q receipt=%+v, want completed+FAILED receipt", label, r.outcome, r.receipt)
	}
	if r.action.Status != actions.StatusFailed {
		t.Fatalf("%s: action status=%q, want failed", label, r.action.Status)
	}
}

// ---------------------------------------------------------------------------
// memJournal — in-memory EdgeJournal for the agent topology (the concrete
// durable edge store is deferred to a later task).
// ---------------------------------------------------------------------------

type memJournal struct {
	mu       sync.Mutex
	receipts map[string]sdkruntime.ActionReceipt
	obs      map[string]sdkruntime.ObservationReceipt
}

func newMemJournal() *memJournal {
	return &memJournal{receipts: map[string]sdkruntime.ActionReceipt{}, obs: map[string]sdkruntime.ObservationReceipt{}}
}

func (j *memJournal) LoadReceipt(_ context.Context, tenant, action, dispatch string) (sdkruntime.ActionReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.receipts[tenant+"|"+action+"|"+dispatch]
	return r, ok, nil
}

func (j *memJournal) RecordReceipt(_ context.Context, tenant, action, dispatch string, r sdkruntime.ActionReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.receipts[tenant+"|"+action+"|"+dispatch] = r
	return nil
}

func (j *memJournal) LoadObservation(_ context.Context, tenant, action, need string) (sdkruntime.ObservationReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.obs[tenant+"|"+action+"|"+need]
	return r, ok, nil
}

func (j *memJournal) RecordObservation(_ context.Context, tenant, action, need string, r sdkruntime.ObservationReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.obs[tenant+"|"+action+"|"+need] = r
	return nil
}

// ===========================================================================
// http/openapi read family
// ===========================================================================

type httpStep struct {
	page runtime.HTTPPage
	err  error
}

type fakeHTTP struct {
	mu    sync.Mutex
	steps []httpStep
	idx   int
	auths []string
	calls int
}

func (f *fakeHTTP) Fetch(_ context.Context, req runtime.HTTPFetch) (runtime.HTTPPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.auths = append(f.auths, req.Auth)
	if f.idx >= len(f.steps) {
		return runtime.HTTPPage{}, errors.New("fakeHTTP: no scripted response")
	}
	step := f.steps[f.idx]
	f.idx++
	return step.page, step.err
}

func httpRecord(email string) map[string]any {
	return map[string]any{"order_id": "ORD-1", "total": 100, "customer_email": email}
}

func httpPage(next string, records ...map[string]any) runtime.HTTPPage {
	return runtime.HTTPPage{StatusCode: 200, NextPageToken: next, Records: records, Source: "system_of_record", SourceVersion: 7, Authority: "system_of_record"}
}

func httpCoords() coords {
	return coords{capability: "httpapi.orders.read", resource: "erp_orders_internal_tbl", operation: "list", action: "read", needs: 0}
}

func TestConformanceHTTPOpenAPI(t *testing.T) {
	pack := parsePack(t, "http-openapi-pack.yaml")
	c := httpCoords()
	binding := buildBinding(pack, c.capability, c.resource, "api")

	// Happy path across BOTH topologies: pagination is consumed, the sensitive
	// field is masked, credential redeemed via handle, no topology leak, and the
	// two topologies produce the equivalent ActionReceipt.
	t.Run("dual_topology_read_pagination_masking", func(t *testing.T) {
		mk := func() *fakeHTTP {
			return &fakeHTTP{steps: []httpStep{
				{page: httpPage("page2", httpRecord("a@x.example"))},
				{page: httpPage("", httpRecord("b@x.example"))},
			}}
		}
		wClient, aClient := mk(), mk()
		w := driveWorker(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(wClient))
		a := driveAgent(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(aClient))
		mustSucceed(t, w, "worker")
		mustSucceed(t, a, "agent")
		assertEquivalent(t, w, a)
		assertReceiptClean(t, w.receipt)

		if wClient.calls != 2 || aClient.calls != 2 {
			t.Fatalf("pagination not fully consumed: worker calls=%d agent calls=%d, want 2 each", wClient.calls, aClient.calls)
		}
		// The injected client received DERIVED material, never the master.
		for _, auth := range append(append([]string{}, wClient.auths...), aClient.auths...) {
			if auth == "" || auth == confMasterCanary || strings.Contains(auth, confMasterCanary) {
				t.Fatalf("http client received %q, want derived (non-master) material", auth)
			}
		}

		hostRes := driveHost(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(mk()))
		if hostRes.Status != host.StatusSucceeded {
			t.Fatalf("host status=%s, want succeeded", hostRes.Status)
		}
		assertNoTopologyLeak(t, hostRes.Output, c.resource)
		out := decodeReadOutput(t, hostRes.Output)
		if len(out.Records) != 2 {
			t.Fatalf("records=%d, want 2 aggregated across pages", len(out.Records))
		}
		for _, rec := range out.Records {
			if _, present := rec["customer_email"]; present {
				t.Fatalf("field masking failed: sensitive customer_email present in %v", rec)
			}
			if _, present := rec["order_id"]; !present {
				t.Fatalf("declared field order_id missing from %v", rec)
			}
		}
		if out.Source == "" || out.SourceVersion == 0 || out.Authority == "" || !out.FreshUntil.After(time.Unix(0, 0)) {
			t.Fatalf("source/version/authority/freshness not surfaced: %+v", out)
		}
	})

	// 429 -> Retry-After honored with bounded retries, then success.
	t.Run("rate_limit_retry_after", func(t *testing.T) {
		mk := func() *fakeHTTP {
			return &fakeHTTP{steps: []httpStep{
				{page: runtime.HTTPPage{StatusCode: 429, RetryAfter: time.Millisecond}},
				{page: httpPage("", httpRecord("a@x.example"))},
			}}
		}
		wClient, aClient := mk(), mk()
		w := driveWorker(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(wClient))
		a := driveAgent(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(aClient))
		mustSucceed(t, w, "worker")
		mustSucceed(t, a, "agent")
		assertEquivalent(t, w, a)
		if wClient.calls != 2 {
			t.Fatalf("429 retry not honored: calls=%d, want 2 (one 429 + one success)", wClient.calls)
		}
	})

	// ACL/deletion (403) -> fail closed, no stale data.
	t.Run("acl_deletion_fail_closed", func(t *testing.T) {
		mk := func() *fakeHTTP {
			return &fakeHTTP{steps: []httpStep{{page: runtime.HTTPPage{StatusCode: 403}}}}
		}
		w := driveWorker(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(mk()))
		a := driveAgent(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(mk()))
		mustFailedReceipt(t, w, "worker")
		mustFailedReceipt(t, a, "agent")
		assertEquivalent(t, w, a)
	})

	// Schema-invalid response (an undeclared field) -> bounded failure.
	t.Run("schema_invalid_response", func(t *testing.T) {
		mk := func() *fakeHTTP {
			return &fakeHTTP{steps: []httpStep{{page: httpPage("", map[string]any{"order_id": "x", "total": 1, "surprise": "leak"})}}}
		}
		w := driveWorker(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(mk()))
		a := driveAgent(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(mk()))
		mustFailedReceipt(t, w, "worker")
		mustFailedReceipt(t, a, "agent")
		assertEquivalent(t, w, a)
	})

	// ctx deadline -> bounded failure (not a hang, not a fabricated success).
	t.Run("deadline_bounded_failure", func(t *testing.T) {
		mk := func() *fakeHTTP {
			return &fakeHTTP{steps: []httpStep{{err: context.DeadlineExceeded}}}
		}
		w := driveWorker(t, pack, binding, c, runtime.NewHTTPOpenAPIAdapter(mk()))
		mustFailedReceipt(t, w, "worker")
	})
}

// ===========================================================================
// db read-only family
// ===========================================================================

type dbStep struct {
	page runtime.DBRowPage
	err  error
}

type fakeDB struct {
	mu    sync.Mutex
	steps []dbStep
	idx   int
	calls int
	auths []string
}

func (f *fakeDB) Query(_ context.Context, q runtime.DBQuery) (runtime.DBRowPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.auths = append(f.auths, q.Auth)
	if f.idx >= len(f.steps) {
		return runtime.DBRowPage{}, errors.New("fakeDB: no scripted response")
	}
	step := f.steps[f.idx]
	f.idx++
	return step.page, step.err
}

func dbRow(holder string) map[string]any {
	return map[string]any{"entry_id": "E-1", "amount": 42, "account_holder": holder}
}

func dbPage(next string, rows ...map[string]any) runtime.DBRowPage {
	return runtime.DBRowPage{NextKeyset: next, Rows: rows, Source: "system_of_record", SourceVersion: 3, Authority: "system_of_record"}
}

func dbCoords() coords {
	return coords{capability: "db.ledger.read", resource: "ledger_internal_rows", operation: "select", action: "read", needs: 0}
}

func TestConformanceDBReadonly(t *testing.T) {
	pack := parsePack(t, "db-readonly-pack.yaml")
	c := dbCoords()
	binding := buildBinding(pack, c.capability, c.resource, "db")

	t.Run("dual_topology_read_pagination_masking", func(t *testing.T) {
		mk := func() *fakeDB {
			return &fakeDB{steps: []dbStep{
				{page: dbPage("k2", dbRow("Alice"))},
				{page: dbPage("", dbRow("Bob"))},
			}}
		}
		wClient, aClient := mk(), mk()
		w := driveWorker(t, pack, binding, c, runtime.NewDBReadonlyAdapter(wClient))
		a := driveAgent(t, pack, binding, c, runtime.NewDBReadonlyAdapter(aClient))
		mustSucceed(t, w, "worker")
		mustSucceed(t, a, "agent")
		assertEquivalent(t, w, a)

		hostRes := driveHost(t, pack, binding, c, runtime.NewDBReadonlyAdapter(mk()))
		assertNoTopologyLeak(t, hostRes.Output, c.resource)
		out := decodeReadOutput(t, hostRes.Output)
		if len(out.Records) != 2 {
			t.Fatalf("records=%d, want 2", len(out.Records))
		}
		for _, rec := range out.Records {
			if _, present := rec["account_holder"]; present {
				t.Fatalf("masking failed: account_holder present in %v", rec)
			}
		}
	})

	// SQL write rejection: a write action is refused before any query runs,
	// identically at the center and the edge — the family is strictly read-only.
	t.Run("write_rejected_read_only", func(t *testing.T) {
		wc := coords{capability: c.capability, resource: c.resource, operation: "update", action: "write", needs: 0}
		mk := func() *fakeDB { return &fakeDB{steps: []dbStep{{page: dbPage("", dbRow("Alice"))}}} }
		wClient, aClient := mk(), mk()
		w := driveWorker(t, pack, binding, wc, runtime.NewDBReadonlyAdapter(wClient))
		a := driveAgent(t, pack, binding, wc, runtime.NewDBReadonlyAdapter(aClient))
		mustFailedReceipt(t, w, "worker")
		mustFailedReceipt(t, a, "agent")
		assertEquivalent(t, w, a)
		if wClient.calls != 0 || aClient.calls != 0 {
			t.Fatalf("read-only family EXECUTED a write: worker calls=%d agent calls=%d, want 0", wClient.calls, aClient.calls)
		}
	})

	// A write-verb operation with a read action is also refused (defense in depth).
	t.Run("write_verb_operation_rejected", func(t *testing.T) {
		wc := coords{capability: c.capability, resource: c.resource, operation: "delete from ledger", action: "read", needs: 0}
		client := &fakeDB{steps: []dbStep{{page: dbPage("", dbRow("Alice"))}}}
		w := driveWorker(t, pack, binding, wc, runtime.NewDBReadonlyAdapter(client))
		mustFailedReceipt(t, w, "worker")
		if client.calls != 0 {
			t.Fatalf("read-only family ran a write-verb operation: calls=%d, want 0", client.calls)
		}
	})

	t.Run("acl_deletion_fail_closed", func(t *testing.T) {
		mk := func() *fakeDB { return &fakeDB{steps: []dbStep{{page: runtime.DBRowPage{Denied: true}}}} }
		w := driveWorker(t, pack, binding, c, runtime.NewDBReadonlyAdapter(mk()))
		a := driveAgent(t, pack, binding, c, runtime.NewDBReadonlyAdapter(mk()))
		mustFailedReceipt(t, w, "worker")
		mustFailedReceipt(t, a, "agent")
		assertEquivalent(t, w, a)
	})
}

// ===========================================================================
// file/s3 read family
// ===========================================================================

type objStep struct {
	page runtime.ObjectPage
	err  error
}

type fakeStore struct {
	mu    sync.Mutex
	steps []objStep
	idx   int
	calls int
	auths []string
}

func (f *fakeStore) List(_ context.Context, req runtime.ObjectFetch) (runtime.ObjectPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.auths = append(f.auths, req.Auth)
	if f.idx >= len(f.steps) {
		return runtime.ObjectPage{}, errors.New("fakeStore: no scripted response")
	}
	step := f.steps[f.idx]
	f.idx++
	return step.page, step.err
}

func objRecord(owner string) map[string]any {
	return map[string]any{"object_key": "doc-1", "title": "Q3 report", "owner_email": owner}
}

func objPage(next string, records ...map[string]any) runtime.ObjectPage {
	return runtime.ObjectPage{NextPageToken: next, Objects: records, Source: "system_of_record", SourceVersion: 5, Authority: "system_of_record", ObjectVersion: "etag-abc-123"}
}

func fileCoords() coords {
	return coords{capability: "filestore.documents.read", resource: "docs_internal_prefix", operation: "list", action: "read", needs: 0}
}

func TestConformanceFileStorage(t *testing.T) {
	pack := parsePack(t, "file-s3-pack.yaml")
	c := fileCoords()
	binding := buildBinding(pack, c.capability, c.resource, "store")

	t.Run("dual_topology_read_object_version", func(t *testing.T) {
		mk := func() *fakeStore {
			return &fakeStore{steps: []objStep{
				{page: objPage("p2", objRecord("a@x.example"))},
				{page: objPage("", objRecord("b@x.example"))},
			}}
		}
		wClient, aClient := mk(), mk()
		w := driveWorker(t, pack, binding, c, runtime.NewFileStorageAdapter(wClient))
		a := driveAgent(t, pack, binding, c, runtime.NewFileStorageAdapter(aClient))
		mustSucceed(t, w, "worker")
		mustSucceed(t, a, "agent")
		assertEquivalent(t, w, a)

		hostRes := driveHost(t, pack, binding, c, runtime.NewFileStorageAdapter(mk()))
		assertNoTopologyLeak(t, hostRes.Output, c.resource)
		out := decodeReadOutput(t, hostRes.Output)
		if out.ObjectVersion != "etag-abc-123" {
			t.Fatalf("object version/ETag not surfaced as source version: %q", out.ObjectVersion)
		}
		for _, rec := range out.Records {
			if _, present := rec["owner_email"]; present {
				t.Fatalf("masking failed: owner_email present in %v", rec)
			}
		}
	})

	// Path traversal is refused before any fetch, identically at both topologies.
	t.Run("path_traversal_denied", func(t *testing.T) {
		tc := coords{capability: c.capability, resource: "..", operation: "list", action: "read", needs: 0}
		mk := func() *fakeStore { return &fakeStore{steps: []objStep{{page: objPage("", objRecord("a@x.example"))}}} }
		wClient, aClient := mk(), mk()
		w := driveWorker(t, pack, binding, tc, runtime.NewFileStorageAdapter(wClient))
		a := driveAgent(t, pack, binding, tc, runtime.NewFileStorageAdapter(aClient))
		mustFailedReceipt(t, w, "worker")
		mustFailedReceipt(t, a, "agent")
		assertEquivalent(t, w, a)
		if wClient.calls != 0 || aClient.calls != 0 {
			t.Fatalf("file family fetched a traversal key: worker calls=%d agent calls=%d, want 0", wClient.calls, aClient.calls)
		}
	})

	// Richer traversal cases at the family level (a scope-valid resource would
	// otherwise be preempted by the Secret Handle scope check).
	t.Run("traversal_variants_denied", func(t *testing.T) {
		for _, key := range []string{"../secret", "a/../../b", "/abs/path", "C:\\evil", "docs\\..\\secret"} {
			fam := runtime.NewFileStorageAdapter(&fakeStore{steps: []objStep{{page: objPage("", objRecord("a@x.example"))}}})
			resp, err := fam.Execute(context.Background(), runtime.FamilyRequest{
				Capability: pack.Capabilities[0], FieldPolicy: pack.FieldPolicy, Resource: key, Operation: "list", Action: "read",
			})
			if err != nil {
				t.Fatalf("traversal %q returned transport error %v, want a bounded denial", key, err)
			}
			if resp.Status != host.StatusDenied {
				t.Fatalf("traversal %q status=%s, want denied", key, resp.Status)
			}
		}
	})

	t.Run("forbidden_object_fail_closed", func(t *testing.T) {
		mk := func() *fakeStore { return &fakeStore{steps: []objStep{{page: runtime.ObjectPage{Forbidden: true}}}} }
		w := driveWorker(t, pack, binding, c, runtime.NewFileStorageAdapter(mk()))
		a := driveAgent(t, pack, binding, c, runtime.NewFileStorageAdapter(mk()))
		mustFailedReceipt(t, w, "worker")
		mustFailedReceipt(t, a, "agent")
		assertEquivalent(t, w, a)
	})
}

// ===========================================================================
// webhook write family
// ===========================================================================

type whStep struct {
	result runtime.WebhookResult
	err    error
}

type fakeSender struct {
	mu         sync.Mutex
	steps      []whStep
	idx        int
	calls      int
	deliveries []runtime.WebhookDelivery
}

func (f *fakeSender) Send(_ context.Context, d runtime.WebhookDelivery) (runtime.WebhookResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.deliveries = append(f.deliveries, d)
	if f.idx >= len(f.steps) {
		return runtime.WebhookResult{}, errors.New("fakeSender: no scripted response")
	}
	step := f.steps[f.idx]
	f.idx++
	return step.result, step.err
}

func okSend() whStep {
	return whStep{result: runtime.WebhookResult{StatusCode: 200, ExternalReceiptID: "ext-123"}}
}

func webhookCoords() coords {
	return coords{capability: "webhook.notify.send", resource: "notify", operation: "send", action: "write", needs: 1}
}

type webhookOutputView struct {
	ExecutionReceipt struct {
		EndpointRef       string `json:"endpoint_ref"`
		IdempotencyKey    string `json:"idempotency_key"`
		ExternalReceiptID string `json:"external_receipt_id"`
		Delivered         bool   `json:"delivered"`
	} `json:"execution_receipt"`
	ReceiptSignature  string `json:"receipt_signature"`
	DeliverySignature string `json:"delivery_signature_algorithm"`
}

func TestConformanceWebhook(t *testing.T) {
	pack := parsePack(t, "webhook-pack.yaml")
	c := webhookCoords()
	binding := buildBinding(pack, c.capability, c.resource, "notify")

	// Happy path across BOTH topologies: exactly one signed delivery to the
	// declared endpoint, a signed execution receipt as Output, a separately
	// minted ObservationReceipt (the declared READ probe) with the probe's
	// source/authority/freshness, and no topology leak. Equivalent across
	// topologies.
	t.Run("dual_topology_signed_write_and_observation", func(t *testing.T) {
		mk := func() *fakeSender { return &fakeSender{steps: []whStep{okSend()}} }
		wSender, aSender := mk(), mk()
		w := driveWorker(t, pack, binding, c, runtime.NewWebhookAdapter(wSender))
		a := driveAgent(t, pack, binding, c, runtime.NewWebhookAdapter(aSender))
		mustSucceed(t, w, "worker")
		mustSucceed(t, a, "agent")
		assertEquivalent(t, w, a)
		assertReceiptClean(t, w.receipt)

		// Exactly one write (no second write as verification), to the declared
		// endpoint, signed with DERIVED material (never the master).
		if wSender.calls != 1 || aSender.calls != 1 {
			t.Fatalf("webhook wrote %d/%d times, want exactly 1 (its probe is a separate READ, never a second write)", wSender.calls, aSender.calls)
		}
		del := wSender.deliveries[0]
		if del.EndpointRef != "notify" {
			t.Fatalf("delivery endpoint_ref=%q, want the declared endpoint 'notify'", del.EndpointRef)
		}
		if del.Signature == "" || !strings.HasPrefix(del.Signature, "hmac-sha256:") {
			t.Fatalf("outbound delivery is not signed: %q", del.Signature)
		}
		if del.Signature == masterHMAC(del.Payload) {
			t.Fatalf("outbound delivery was signed with the MASTER credential, not derived material")
		}
		if strings.Contains(string(del.Payload), confMasterCanary) {
			t.Fatalf("delivery payload leaked the master credential")
		}

		// Exactly one ObservationReceipt (the declared postcondition read probe),
		// carrying the probe's authority and freshness.
		if len(w.obs) != 1 || w.obs[0].VerificationNeedID != "n1" {
			t.Fatalf("observation set=%+v, want exactly need n1 (the declared read probe)", w.obs)
		}
		if w.obs[0].Authority != "system_of_record" {
			t.Fatalf("observation authority=%q, want the probe's system_of_record", w.obs[0].Authority)
		}
		if w.obs[0].FreshUntil.Sub(w.obs[0].ObservedAt) != 120*time.Second {
			t.Fatalf("observation freshness window=%s, want the probe's 120s", w.obs[0].FreshUntil.Sub(w.obs[0].ObservedAt))
		}

		hostRes := driveHost(t, pack, binding, c, runtime.NewWebhookAdapter(mk()))
		if hostRes.Status != host.StatusSucceeded {
			t.Fatalf("host status=%s, want succeeded", hostRes.Status)
		}
		assertNoTopologyLeak(t, hostRes.Output)
		var out webhookOutputView
		if err := json.Unmarshal(hostRes.Output, &out); err != nil {
			t.Fatalf("decode webhook output: %v (raw %s)", err, string(hostRes.Output))
		}
		if !out.ExecutionReceipt.Delivered || out.ExecutionReceipt.ExternalReceiptID != "ext-123" {
			t.Fatalf("execution receipt not present/delivered: %+v", out)
		}
		if out.ReceiptSignature == "" {
			t.Fatalf("execution receipt is not signed: %+v", out)
		}
	})

	// Undeclared endpoint: the webhook writes ONLY to declared endpoints — an
	// undeclared target is refused before any send, at both topologies.
	t.Run("undeclared_endpoint_denied", func(t *testing.T) {
		uc := coords{capability: c.capability, resource: "rogue", operation: "send", action: "write", needs: 1}
		mk := func() *fakeSender { return &fakeSender{steps: []whStep{okSend()}} }
		wSender, aSender := mk(), mk()
		w := driveWorker(t, pack, binding, uc, runtime.NewWebhookAdapter(wSender))
		a := driveAgent(t, pack, binding, uc, runtime.NewWebhookAdapter(aSender))
		mustFailedReceipt(t, w, "worker")
		mustFailedReceipt(t, a, "agent")
		assertEquivalent(t, w, a)
		if wSender.calls != 0 || aSender.calls != 0 {
			t.Fatalf("webhook wrote to an UNDECLARED endpoint: worker calls=%d agent calls=%d, want 0", wSender.calls, aSender.calls)
		}
	})

	// 429 -> Retry-After honored with bounded retries, then a single committed write.
	t.Run("rate_limit_retry_after", func(t *testing.T) {
		mk := func() *fakeSender {
			return &fakeSender{steps: []whStep{
				{result: runtime.WebhookResult{StatusCode: 429, RetryAfter: time.Millisecond}},
				okSend(),
			}}
		}
		wSender := mk()
		w := driveWorker(t, pack, binding, c, runtime.NewWebhookAdapter(wSender))
		mustSucceed(t, w, "worker")
		if wSender.calls != 2 {
			t.Fatalf("429 retry not honored: sends=%d, want 2", wSender.calls)
		}
	})
}
