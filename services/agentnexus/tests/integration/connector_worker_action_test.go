package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// TestConnectorWorkerExecutesDurableActionWithRedelivery is the GA Task 5
// gold-standard integration: a real PostgreSQL actions store, a real NATS
// JetStream dispatch transport and a deliberate broker-level redelivery. It
// proves exactly ONE logical Action yields ONE authoritative signed ActionReceipt
// and the EXACT deduplicated ObservationReceipt set declared by its
// VerificationNeeds, and that a genuinely redelivered dispatch executes the
// external side effect exactly once (durable inbox dedup). DSN- and NATS-gated.
func TestConnectorWorkerExecutesDurableActionWithRedelivery(t *testing.T) {
	natsURL := os.Getenv("AGENTNEXUS_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("set AGENTNEXUS_TEST_NATS_URL to run the connector-worker integration test")
	}
	pool := workerIntegrationPool(t)
	ctx := context.Background()

	// --- durable action plane (real PostgreSQL store) -----------------------
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := audit.NewEd25519AuditSigner("connector-worker-int-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	keys := sdkaudit.NewKeySet(sdkaudit.SigningKey{KeyID: "connector-worker-int-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyActive})

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	publisher, err := actions.NewNATSPublisher(nc)
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}

	svc, err := actions.NewService(actions.NewPostgresStore(pool), actions.NewMemoryAuditSink(),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(keys)),
		actions.WithPublisher(publisher))
	if err != nil {
		t.Fatalf("actions.NewService: %v", err)
	}

	// --- worker with a fixed private binding + a deterministic host ---------
	hostRunner := &countingHost{output: []byte(`{"po_id":"po-1"}`)}
	resolver := fixedResolver{binding: worker.ResolvedBinding{Host: hostRunner, Resource: "purchase_orders", Operation: "approve", OperationAction: "write", ConnectorRef: "conn_private_1", CredentialRef: "secretref://vault/acme/erp"}}
	obs := &fakeObservationProducer{}
	w, err := worker.New(worker.Config{
		Actions: svc, Resolver: resolver, Signer: signer, Observations: obs,
		Identity: worker.Identity{PrincipalRef: "connector-worker", AgentClientRef: "agc_worker", AgentReleaseRef: "rel-1", OrgSnapshotRef: "org-system"},
	})
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}
	if err := w.CheckReady(ctx); err != nil {
		t.Fatalf("worker not ready: %v", err)
	}

	// --- drive one Action to dispatched, publish the durable intent ---------
	principal := workerIntegrationPrincipal()
	req := workerIntegrationRequest(t)
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

	// --- publish the dispatch to a fresh JetStream stream -------------------
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	stream := fmt.Sprintf("AGENTNEXUS_ACTION_DISPATCH_%d", time.Now().UnixNano())
	if _, err := js.AddStream(&nats.StreamConfig{Name: stream, Subjects: []string{actions.SubjectActionDispatch}}); err != nil {
		t.Fatalf("add stream: %v", err)
	}
	defer js.DeleteStream(stream)

	if _, err := svc.RepublishPending(ctx, principal.TenantRef); err != nil {
		t.Fatalf("RepublishPending: %v", err)
	}

	// --- durable pull with a deliberate, genuine redelivery -----------------
	const ackWait = 300 * time.Millisecond
	sub, err := js.PullSubscribe(actions.SubjectActionDispatch, worker.DurableName, nats.BindStream(stream), nats.AckWait(ackWait))
	if err != nil {
		t.Fatalf("pull subscribe: %v", err)
	}

	first, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
	if err != nil || len(first) != 1 {
		t.Fatalf("first fetch: msgs=%d err=%v", len(first), err)
	}
	firstMeta, _ := first[0].Metadata()
	// Do NOT ack the first delivery; wait past AckWait so JetStream redelivers the
	// SAME tracked message (real broker-level at-least-once), then process both.
	time.Sleep(ackWait + 400*time.Millisecond)
	second, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
	if err != nil || len(second) != 1 {
		t.Fatalf("redelivery fetch: msgs=%d err=%v", len(second), err)
	}
	secondMeta, _ := second[0].Metadata()
	if secondMeta.Sequence.Stream != firstMeta.Sequence.Stream || secondMeta.NumDelivered < 2 {
		t.Fatalf("second fetch is not a genuine redelivery of the same message (stream seq %d/%d, delivered %d)", secondMeta.Sequence.Stream, firstMeta.Sequence.Stream, secondMeta.NumDelivered)
	}

	var lastReceiptRef string
	var observationCount int
	for _, delivery := range [][]*nats.Msg{first, second} {
		var msg actions.DispatchMessage
		if err := json.Unmarshal(delivery[0].Data, &msg); err != nil {
			t.Fatalf("decode dispatch message: %v", err)
		}
		res, err := w.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("ProcessDispatch: %v", err)
		}
		if res.ActionReceipt != nil {
			lastReceiptRef = res.ActionReceipt.ReceiptRef
		}
		if len(res.ObservationReceipts) > observationCount {
			observationCount = len(res.ObservationReceipts)
		}
		_ = delivery[0].Ack()
	}

	// --- exactly-once side effect + one authoritative receipt ---------------
	if hostRunner.runs() != 1 {
		t.Fatalf("connector host executed %d times, want exactly once (durable inbox dedup of a redelivered dispatch)", hostRunner.runs())
	}
	final, err := svc.GetAction(ctx, principal, action.ActionRef)
	if err != nil || final.Status != actions.StatusSucceeded {
		t.Fatalf("final action = %+v err=%v, want succeeded", final, err)
	}
	if final.ReceiptRef == "" || (lastReceiptRef != "" && final.ReceiptRef != lastReceiptRef) {
		t.Fatalf("action receipt ref = %q, produced = %q", final.ReceiptRef, lastReceiptRef)
	}
	var inboxCount, receiptCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM action_inbox WHERE action_ref=$1`, action.ActionRef).Scan(&inboxCount); err != nil {
		t.Fatalf("inbox count: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM action_receipts WHERE action_ref=$1`, action.ActionRef).Scan(&receiptCount); err != nil {
		t.Fatalf("receipt count: %v", err)
	}
	if inboxCount != 1 || receiptCount != 1 {
		t.Fatalf("inbox rows=%d receipt rows=%d, want exactly 1 each (one authoritative ActionReceipt)", inboxCount, receiptCount)
	}

	// --- exact deduplicated ObservationReceipt set --------------------------
	if observationCount != 2 {
		t.Fatalf("observation receipts = %d, want exactly the 2 declared verification needs", observationCount)
	}
	if got := obs.distinctNeeds(); len(got) != 2 || !got["n1"] || !got["n2"] {
		t.Fatalf("observed needs = %v, want exactly {n1,n2}", got)
	}
}

// TestConnectorWorkerFixtureIsValid guards the integration fixture in the DEFAULT
// suite (no backends). The durable integration test above is env-gated and skips
// without PostgreSQL+NATS, so an invalid ActionRequest/PrincipalContext fixture
// would otherwise rot silently — exactly how a too-short idempotency_key once hid
// until the test was run against real backends. This guard runs everywhere and
// fails fast on any runtime validation error, so the gold-standard integration
// test never fails at setup again.
func TestConnectorWorkerFixtureIsValid(t *testing.T) {
	if err := workerIntegrationPrincipal().Validate(); err != nil {
		t.Fatalf("integration principal fixture is invalid: %v", err)
	}
	if err := workerIntegrationRequest(t).Validate(); err != nil {
		t.Fatalf("integration ActionRequest fixture is invalid: %v", err)
	}
}

// --- test doubles -----------------------------------------------------------

type fixedResolver struct{ binding worker.ResolvedBinding }

func (r fixedResolver) Resolve(context.Context, string, string) (worker.ResolvedBinding, error) {
	return r.binding, nil
}

type countingHost struct {
	output []byte
	mu     sync.Mutex
	n      int
}

func (h *countingHost) Run(context.Context, host.Operation) host.Result {
	h.mu.Lock()
	h.n++
	h.mu.Unlock()
	sum := sha256.Sum256(h.output)
	return host.Result{Status: host.StatusSucceeded, Output: h.output, OutputHash: "sha256:" + hex.EncodeToString(sum[:])}
}

func (h *countingHost) runs() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

type fakeObservationProducer struct {
	mu    sync.Mutex
	needs map[string]bool
}

func (o *fakeObservationProducer) Observe(_ context.Context, _ string, binding runtime.VerificationBinding) (runtime.ObservationReceipt, error) {
	o.mu.Lock()
	if o.needs == nil {
		o.needs = map[string]bool{}
	}
	o.needs[binding.VerificationNeedID] = true
	o.mu.Unlock()
	now := time.Now().UTC()
	sum := sha256.Sum256([]byte(binding.VerificationNeedID))
	return runtime.ObservationReceipt{
		ObservationRef: "obs_0123456789abcdef", ActionRef: binding.ActionRef, ParameterHash: binding.ParameterHash,
		PostconditionID: binding.PostconditionID, VerificationNeedID: binding.VerificationNeedID,
		Source: binding.DataClass, SourceVersion: 1, Authority: "system_of_record",
		ObservedAt: now, FreshUntil: now.Add(time.Hour), ObservationHash: "sha256:" + hex.EncodeToString(sum[:]),
		EvidenceRef: "evd_0123456789abcdef", AuditRefID: "aud_1",
		Signature: runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "obs", Value: "BBBB"},
	}, nil
}

func (o *fakeObservationProducer) distinctNeeds() map[string]bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string]bool{}
	for k, v := range o.needs {
		out[k] = v
	}
	return out
}

// --- request + principal ----------------------------------------------------

func workerIntegrationPrincipal() runtime.PrincipalContext {
	now := time.Now().UTC()
	return runtime.PrincipalContext{
		TenantRef: "tenant-1", PrincipalRef: "agent-1", AgentClientRef: "agc_client-1", AgentReleaseRef: "rel-1",
		TrustClass: runtime.TrustFirstParty, OrgSnapshotRef: "org-1", VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func workerIntegrationRequest(t *testing.T) runtime.ActionRequest {
	t.Helper()
	params, hash, err := runtime.BuildParameters(map[string]any{"amount": 100})
	if err != nil {
		t.Fatalf("build parameters: %v", err)
	}
	now := time.Now().UTC()
	return runtime.ActionRequest{
		RequestID: "req-int-1", BusinessContextRef: "wc_0123456789abcdef", Capability: "erp.purchase_order.approve",
		Parameters: params, ParameterHash: hash, Purpose: "execute",
		RiskDecision: runtime.RiskDecision{
			DecisionID: "dec-1", Authority: "acme-risk", RiskLevel: runtime.RiskMedium,
			Capability: "erp.purchase_order.approve", ParameterHash: hash, BusinessContextRef: "wc_0123456789abcdef",
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			Signature: runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "k1", Value: "AAAA"},
		},
		IdempotencyKey: "idem-worker-int-0001", ExpiresAt: now.Add(30 * time.Minute), ExpectedReceiptSchema: "erp.receipt.v1",
		Postconditions: []runtime.PostconditionSpec{
			{PostconditionID: "pc1", Kind: "state", Reference: "po.status"},
			{PostconditionID: "pc2", Kind: "state", Reference: "po.total"},
		},
		VerificationNeeds: []runtime.VerificationNeed{
			{NeedID: "n1", PostconditionID: "pc1", DataClass: "purchase_order_status"},
			{NeedID: "n2", PostconditionID: "pc2", DataClass: "purchase_order_total"},
		},
	}
}

// --- postgres harness (mirrors internal/actions/postgres_integration_test.go) --

func workerIntegrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN (or AGENTNEXUS_POSTGRES_DSN) to run the connector-worker integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	schema := fmt.Sprintf("agentnexus_worker_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("parse dsn: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatalf("connect schema pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, _ = admin.Exec(cleanupCtx, `DROP SCHEMA IF EXISTS `+pgx.Identifier{schema}.Sanitize()+` CASCADE`)
		admin.Close()
	})
	applyWorkerMigrations(t, pool)
	return pool
}

func applyWorkerMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	dir := filepath.Clean(filepath.Join("..", "..", "db", "migrations"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		up := gooseUp(string(raw))
		if _, err := pool.Exec(ctx, up); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
}

func gooseUp(text string) string {
	start := strings.Index(text, "-- +goose Up")
	if start < 0 {
		return text
	}
	segment := text[start:]
	if down := strings.Index(segment, "-- +goose Down"); down >= 0 {
		segment = segment[:down]
	}
	segment = strings.ReplaceAll(segment, "-- +goose StatementBegin", "")
	segment = strings.ReplaceAll(segment, "-- +goose StatementEnd", "")
	return strings.TrimPrefix(segment, "-- +goose Up")
}
