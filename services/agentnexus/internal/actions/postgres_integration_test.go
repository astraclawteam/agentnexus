package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	stdruntime "runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// Integration tests are DSN-gated: they run only when a PostgreSQL DSN is
// provided and skip cleanly otherwise. The durability, crash-replay, reconcile
// and one-use-grant-trigger invariants MUST run on the real database. Each test
// runs in a freshly-created isolated schema with the FULL migration chain
// applied in sorted filename order (so 000010 applies before 000012 with no
// conflict — see the migration-ordering note in 000010_durable_actions.sql).
//
// WARNING: point AGENTNEXUS_E2E_POSTGRES_DSN at a disposable database.

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN (or AGENTNEXUS_POSTGRES_DSN) to run the actions postgres integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	schema := fmt.Sprintf("agentnexus_act_%d", time.Now().UnixNano())
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
	applyAllMigrations(t, pool)
	return pool
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := stdruntime.Caller(0)
	if !ok {
		t.Fatal("cannot locate migrations directory")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations"))
}

func gooseBlock(t *testing.T, name, direction string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(migrationsDir(t), name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	text := string(raw)
	marker := "-- +goose " + direction
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("migration %s is missing %q", name, marker)
	}
	segment := text[start:]
	if direction == "Up" {
		if down := strings.Index(segment, "-- +goose Down"); down >= 0 {
			segment = segment[:down]
		}
	}
	segment = strings.ReplaceAll(segment, "-- +goose StatementBegin", "")
	segment = strings.ReplaceAll(segment, "-- +goose StatementEnd", "")
	return strings.TrimPrefix(segment, marker)
}

func applyAllMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir(t))
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
		if _, err := pool.Exec(ctx, gooseBlock(t, name, "Up")); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
}

func newPostgresService(t *testing.T, pool *pgxpool.Pool, opts ...Option) *Service {
	t.Helper()
	svc, _ := newPostgresServiceWithAudit(t, pool, opts...)
	return svc
}

// newPostgresServiceWithAudit builds a PostgresStore-backed service over a
// MemoryAuditSink and RETURNS the sink, so tests can assert the exact count of
// action-transition lineage events the service emitted (the dimension GA Task
// 0G signs and independently verifies).
func newPostgresServiceWithAudit(t *testing.T, pool *pgxpool.Pool, opts ...Option) (*Service, *MemoryAuditSink) {
	t.Helper()
	audit := NewMemoryAuditSink()
	// Default accepting receipt verifier so completion succeeds for tests that
	// are not about receipt authenticity; overridable via opts (later wins).
	base := []Option{WithIDGenerator(sequentialIDs()), WithReceiptVerifier(&fakeReceiptVerifier{})}
	svc, err := NewService(NewPostgresStore(pool), audit, append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, audit
}

func TestActionPostgresLifecycleAndTriggers(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	svc := newPostgresService(t, pool)
	principal := testPrincipal(runtime.TrustFirstParty)

	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	// Idempotent re-request returns the same durable Action.
	again, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil || again.ActionRef != action.ActionRef {
		t.Fatalf("idempotent re-request = %+v err=%v", again, err)
	}

	granted, err := svc.Grant(ctx, principal, action.ActionRef)
	if err != nil || granted.Status != StatusGranted || granted.GrantRef == "" {
		t.Fatalf("Grant = %+v err=%v", granted, err)
	}
	dispatched, err := svc.Dispatch(ctx, principal, action.ActionRef)
	if err != nil || dispatched.Status != StatusDispatched {
		t.Fatalf("Dispatch = %+v err=%v", dispatched, err)
	}
	if _, err := svc.MarkExecuting(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	receipt := testReceipt(action, runtime.StatusSucceeded)
	done, err := svc.IngestReceipt(ctx, principal, "res-1", receipt)
	if err != nil || done.Status != StatusSucceeded {
		t.Fatalf("IngestReceipt = %+v err=%v", done, err)
	}
	fetched, err := svc.GetReceipt(ctx, principal, receipt.ReceiptRef)
	if err != nil || fetched.ActionRef != action.ActionRef {
		t.Fatalf("GetReceipt = %+v err=%v", fetched, err)
	}

	// Database triggers reject: a forbidden transition, a binding mutation, a
	// delete, and a second grant-consumption stamp.
	if _, err := pool.Exec(ctx, `UPDATE actions SET status='requested' WHERE action_ref=$1`, action.ActionRef); err == nil {
		t.Fatal("status regression to requested accepted by the database")
	}
	if _, err := pool.Exec(ctx, `UPDATE actions SET capability='erp.invoice.pay' WHERE action_ref=$1`, action.ActionRef); err == nil {
		t.Fatal("binding mutation accepted by the database")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM actions WHERE action_ref=$1`, action.ActionRef); err == nil {
		t.Fatal("action delete accepted by the database")
	}
	if _, err := pool.Exec(ctx, `UPDATE action_grants SET consumed_at=now() WHERE action_ref=$1`, action.ActionRef); err == nil {
		t.Fatal("second grant consumption stamp accepted by the database (one-use gate broken)")
	}
}

// TestActionPostgresReceiptCompletesDispatchedWithoutExplicitExecuting drives
// the ONLY path the wired system exercises today: RequestAction -> Grant ->
// Dispatch -> IngestReceipt, WITHOUT ever calling MarkExecuting. Nothing in the
// wired gateway, the composition root or any connector-host component calls
// MarkExecuting — dispatched->executing has no real driver anywhere in this
// codebase. The documented production contract (gateway-runtime.yaml
// ingestRuntimeActionReceipt: "the connector host reports the execution
// result of a dispatched action") is exactly this path, so a verified receipt
// must complete a DISPATCHED action directly to its declared TECHNICAL
// terminal status (mirrors the existing executing->{succeeded,failed} edges;
// both are legitimate — a future connector-host may still call MarkExecuting
// explicitly before reporting).
func TestActionPostgresReceiptCompletesDispatchedWithoutExplicitExecuting(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	svc := newPostgresService(t, pool)
	principal := testPrincipal(runtime.TrustFirstParty)
	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	receipt := testReceipt(action, runtime.StatusSucceeded)
	done, err := svc.IngestReceipt(ctx, principal, "res-no-executing", receipt)
	if err != nil {
		t.Fatalf("IngestReceipt directly from dispatched (no MarkExecuting): %v", err)
	}
	if done.Status != StatusSucceeded || done.ReceiptRef != receipt.ReceiptRef {
		t.Fatalf("completed = %+v, want succeeded with the receipt ref", done)
	}
}

// TestActionPostgresOutOfOrderReceiptForTerminalActionRejected proves a
// DIFFERENT result_id/receipt arriving for an action already in a terminal
// state is REJECTED, never silently re-applied or allowed to overwrite the
// first receipt: only an EXACT-DUPLICATE result_id is deduped through the
// inbox (see TestActionDuplicateReceiptDeduped); a genuinely new/out-of-order
// receipt for an already-succeeded action has no forward edge to take
// (canTransition(succeeded, *) has no outgoing succeeded/failed edge).
func TestActionPostgresOutOfOrderReceiptForTerminalActionRejected(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	svc, audit := newPostgresServiceWithAudit(t, pool)
	principal := testPrincipal(runtime.TrustFirstParty)
	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	first := testReceipt(action, runtime.StatusSucceeded)
	done, err := svc.IngestReceipt(ctx, principal, "res-first", first)
	if err != nil || done.Status != StatusSucceeded {
		t.Fatalf("first IngestReceipt = %+v err=%v", done, err)
	}
	// A SECOND, genuinely different receipt (different receipt_ref, different
	// result_id — not a redelivery of the same result) arrives out of order for
	// the now-terminal action.
	second := testReceipt(action, runtime.StatusSucceeded)
	second.ReceiptRef = "rcp_0123456789abcdeg"
	if _, err := svc.IngestReceipt(ctx, principal, "res-second-out-of-order", second); !errors.Is(err, ErrForbiddenTransition) {
		t.Fatalf("out-of-order receipt err = %v, want ErrForbiddenTransition", err)
	}
	// The FIRST receipt is preserved; the out-of-order second was never applied.
	final, err := svc.GetAction(ctx, principal, action.ActionRef)
	if err != nil || final.ReceiptRef != first.ReceiptRef {
		t.Fatalf("final action = %+v err=%v, want the FIRST receipt preserved", final, err)
	}
	// The rejected out-of-order receipt must NOT have left a signed audit lie:
	// exactly one action.completed event (the genuine first completion) exists.
	if n := completionAuditCount(audit, action.ActionRef); n != 1 {
		t.Fatalf("action.completed audit events = %d, want exactly 1 (the rejected receipt must not be audited)", n)
	}
}

func TestActionPostgresGrantOneUseDoubleConsumeRejected(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	svc := newPostgresService(t, pool)
	principal := testPrincipal(runtime.TrustFirstParty)
	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	// A second dispatch cannot re-consume the one-use grant (the durable
	// consumed_at gate).
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err == nil {
		t.Fatal("second dispatch consumed the one-use grant twice")
	}
	var consumed *time.Time
	if err := pool.QueryRow(ctx, `SELECT consumed_at FROM action_grants WHERE action_ref=$1`, action.ActionRef).Scan(&consumed); err != nil {
		t.Fatalf("scan consumed_at: %v", err)
	}
	if consumed == nil {
		t.Fatal("grant not marked consumed after dispatch")
	}
}

func TestActionPostgresCrashAfterDispatchReplaysOutbox(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	recorder := &recordingPublisher{}
	// The dispatching service never reaches a publisher: that is the crash
	// window between the outbox commit and the publish, and the only thing the
	// pump exists for. An ordinary dispatch publishes itself — see
	// TestActionPostgresDispatchPublishesAfterCommit.
	svc := newPostgresService(t, pool)
	principal := testPrincipal(runtime.TrustFirstParty)
	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	// A fresh service over the SAME durable pool finds the pending outbox row
	// and republishes it exactly once.
	recovered := newPostgresService(t, pool, WithPublisher(recorder))
	n, err := recovered.RepublishPending(ctx, principal.TenantRef)
	if err != nil || n != 1 {
		t.Fatalf("RepublishPending = %d err=%v, want 1", n, err)
	}
	if len(recorder.messages()) != 1 || recorder.messages()[0].ActionRef != action.ActionRef {
		t.Fatalf("republished messages = %+v, want exactly the pending dispatch", recorder.messages())
	}
	// A second pump run finds nothing pending (published exactly once).
	n2, err := recovered.RepublishPending(ctx, principal.TenantRef)
	if err != nil || n2 != 0 {
		t.Fatalf("second RepublishPending = %d err=%v, want 0", n2, err)
	}
}

func TestActionPostgresTimeoutResultUnknownForbidsBlindRetry(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	svc := newPostgresService(t, pool)
	principal := testPrincipal(runtime.TrustFirstParty)
	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if _, err := svc.MarkExecuting(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	unknown, err := svc.MarkResultUnknown(ctx, principal, action.ActionRef)
	if err != nil || unknown.Status != StatusResultUnknown {
		t.Fatalf("MarkResultUnknown = %+v err=%v", unknown, err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); !errors.Is(err, ErrBlindRetryForbidden) {
		t.Fatalf("blind re-dispatch err = %v, want ErrBlindRetryForbidden", err)
	}
	// The database trigger also rejects a raw re-dispatch of a result_unknown row.
	if _, err := pool.Exec(ctx, `UPDATE actions SET status='dispatched' WHERE action_ref=$1`, action.ActionRef); err == nil {
		t.Fatal("raw re-dispatch of a result_unknown action accepted by the database")
	}

	reconciling, err := svc.BeginReconciliation(ctx, principal, action.ActionRef)
	if err != nil || reconciling.Status != StatusReconciling {
		t.Fatalf("BeginReconciliation = %+v err=%v", reconciling, err)
	}
	recovered := testReceipt(action, runtime.StatusSucceeded)
	resolved, err := svc.ResolveReconciliation(ctx, principal, action.ActionRef, runtime.StatusSucceeded, &recovered)
	if err != nil || resolved.Status != StatusSucceeded {
		t.Fatalf("ResolveReconciliation = %+v err=%v", resolved, err)
	}
}

// TestActionPostgresApprovalEvidenceConsumedOnce drives the durable one-shot
// approval-evidence consumption (the approvaltransport ConsumeEvidence store
// path added by Task 0F): a validated evidence record is consumed exactly once,
// and a second consume fails closed against the 000009 consumed_at trigger.
func TestActionPostgresApprovalEvidenceConsumedOnce(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	approvalStore := approvaltransport.NewPostgresStore(pool)
	channel := approvaltransport.NewMemoryChannel()
	approvalSvc, err := approvaltransport.NewService(approvalStore, channel, approvaltransport.NewMemoryAuditSink())
	if err != nil {
		t.Fatalf("approval NewService: %v", err)
	}
	principal := testPrincipal(runtime.TrustFirstParty)
	principal.VerifiedAt = time.Now().UTC().Add(-time.Minute)
	principal.ExpiresAt = time.Now().UTC().Add(time.Hour)

	req := testApprovalRequest(t)
	transmit := runtime.ApprovalRequest{
		RequestID:          "areq-1",
		BusinessContextRef: req.BusinessContextRef,
		Capability:         req.Capability,
		ParameterHash:      req.ParameterHash,
		Purpose:            req.Purpose,
		Plan:               *req.ApprovalPlanRef,
		ExpiresAt:          time.Now().UTC().Add(30 * time.Minute),
	}
	if _, err := approvalSvc.Transmit(ctx, principal, transmit); err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	evidence := runtime.ApprovalEvidence{
		ApprovalRef:       "apv_evidence00000001",
		PlanRef:           req.ApprovalPlanRef.PlanRef,
		PlanHash:          req.ApprovalPlanRef.PlanHash,
		Capability:        req.Capability,
		ParameterHash:     req.ParameterHash,
		Decision:          runtime.ApprovalApproved,
		ApproverAuthority: req.ApprovalPlanRef.Authority,
		DecidedAt:         time.Now().UTC(),
		Attestation:       testSignature(),
	}
	if _, err := approvalSvc.RecordEvidence(ctx, principal, evidence); err != nil {
		t.Fatalf("RecordEvidence: %v", err)
	}

	// The actions service consumes the evidence one-shot and mints the grant.
	svc := newPostgresService(t, pool, WithEvidenceConsumer(evidenceConsumerAdapter{store: approvalStore}))
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if action.Status != StatusAwaitingApproval {
		t.Fatalf("status = %q, want awaiting_approval", action.Status)
	}
	granted, err := svc.Grant(ctx, principal, action.ActionRef)
	if err != nil || granted.Status != StatusGranted {
		t.Fatalf("Grant = %+v err=%v", granted, err)
	}
	// The durable consumed_at gate: a second consume of the same evidence fails.
	if _, err := approvalStore.ConsumeEvidence(ctx, principal.TenantRef, req.ApprovalPlanRef.PlanRef, time.Now().UTC()); !errors.Is(err, approvaltransport.ErrEvidenceConsumed) {
		t.Fatalf("second ConsumeEvidence err = %v, want ErrEvidenceConsumed", err)
	}
}

// evidenceConsumerAdapter bridges the approvaltransport ConsumeEvidence store
// path to the actions EvidenceConsumer port (the same adapter the composition
// root wires in production).
type evidenceConsumerAdapter struct{ store *approvaltransport.PostgresStore }

func (a evidenceConsumerAdapter) ConsumeApprovalEvidence(ctx context.Context, tenantRef, planRef string, at time.Time) (ConsumedEvidence, error) {
	consumed, err := a.store.ConsumeEvidence(ctx, tenantRef, planRef, at)
	if err != nil {
		switch {
		case errors.Is(err, approvaltransport.ErrEvidenceConsumed):
			return ConsumedEvidence{}, ErrEvidenceConsumed
		case errors.Is(err, approvaltransport.ErrNotFound):
			return ConsumedEvidence{}, ErrNotFound
		case errors.Is(err, approvaltransport.ErrTransmissionRevoked):
			return ConsumedEvidence{}, ErrEvidenceRejected
		}
		return ConsumedEvidence{}, ErrUnavailable
	}
	return ConsumedEvidence{
		ApprovalRef:   consumed.ApprovalRef,
		PlanRef:       consumed.PlanRef,
		Capability:    consumed.Capability,
		ParameterHash: consumed.ParameterHash,
		Decision:      consumed.Decision,
	}, nil
}

// TestActionNATSRedeliveryInboxDedup proves a GENUINE broker-level JetStream
// redelivery of the SAME tracked message (at-least-once delivery: the first
// delivery's ack is never sent, so the broker redelivers it after AckWait
// expires) is deduped by the durable inbox and applied exactly once. This is
// deliberately NOT two independently published messages that happen to share
// a result_id — the test asserts on JetStream's own delivery metadata
// (Sequence.Stream / NumDelivered) that the second fetch is a REDELIVERY of
// the first message, not a different one. It is DSN- AND NATS-gated.
func TestActionNATSRedeliveryInboxDedup(t *testing.T) {
	natsURL := os.Getenv("AGENTNEXUS_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("AGENTNEXUS_TEST_NATS_URL is not set")
	}
	pool := integrationPool(t)
	ctx := context.Background()
	svc, audit := newPostgresServiceWithAudit(t, pool)
	principal := testPrincipal(runtime.TrustFirstParty)
	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if _, err := svc.MarkExecuting(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	stream := fmt.Sprintf("AGENTNEXUS_ACTION_RESULTS_%d", time.Now().UnixNano())
	subject := "agentnexus.actions.results"
	if _, err := js.AddStream(&nats.StreamConfig{Name: stream, Subjects: []string{subject}}); err != nil {
		t.Fatalf("add stream: %v", err)
	}
	defer js.DeleteStream(stream)

	// The connector publishes ONE result.
	type resultEnvelope struct {
		ResultID string                `json:"result_id"`
		Receipt  runtime.ActionReceipt `json:"receipt"`
	}
	envelope := resultEnvelope{ResultID: "connector-result-1", Receipt: testReceipt(action, runtime.StatusSucceeded)}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := js.Publish(subject, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// A short AckWait makes the broker genuinely REDELIVER the SAME tracked
	// message if it is not acked in time — real broker-level at-least-once
	// redelivery, never a second independently published message.
	const ackWait = 300 * time.Millisecond
	sub, err := js.PullSubscribe(subject, "results-worker", nats.BindStream(stream), nats.AckWait(ackWait))
	if err != nil {
		t.Fatalf("pull subscribe: %v", err)
	}

	first, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
	if err != nil || len(first) != 1 {
		t.Fatalf("first fetch: msgs=%d err=%v", len(first), err)
	}
	firstMeta, err := first[0].Metadata()
	if err != nil {
		t.Fatalf("first metadata: %v", err)
	}
	// Deliberately do NOT ack the first delivery — wait past AckWait so
	// JetStream redelivers the SAME message (a bounded, one-shot wait for the
	// broker's own redelivery timer, not a retry-loop poll).
	time.Sleep(ackWait + 400*time.Millisecond)

	second, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
	if err != nil || len(second) != 1 {
		t.Fatalf("redelivery fetch: msgs=%d err=%v", len(second), err)
	}
	secondMeta, err := second[0].Metadata()
	if err != nil {
		t.Fatalf("second metadata: %v", err)
	}
	if secondMeta.Sequence.Stream != firstMeta.Sequence.Stream {
		t.Fatalf("second fetch delivered a DIFFERENT message (stream seq %d != %d); this test requires genuine redelivery of the SAME message", secondMeta.Sequence.Stream, firstMeta.Sequence.Stream)
	}
	if secondMeta.NumDelivered < 2 {
		t.Fatalf("redelivery count = %d, want >= 2 (the broker must have genuinely redelivered)", secondMeta.NumDelivered)
	}

	// The connector host applies BOTH deliveries of the redelivered message (it
	// cannot know in advance that the first ack was merely delayed, not lost);
	// the durable inbox must dedup so the result is applied exactly once.
	applied := 0
	for _, delivery := range [][]*nats.Msg{first, second} {
		msg := delivery[0]
		var got resultEnvelope
		if err := json.Unmarshal(msg.Data, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		before, _ := svc.GetAction(ctx, principal, action.ActionRef)
		if _, err := svc.IngestReceipt(ctx, principal, got.ResultID, got.Receipt); err != nil {
			t.Fatalf("IngestReceipt: %v", err)
		}
		after, _ := svc.GetAction(ctx, principal, action.ActionRef)
		if before.Status != StatusSucceeded && after.Status == StatusSucceeded {
			applied++
		}
		_ = msg.Ack()
	}
	if applied != 1 {
		t.Fatalf("connector result applied %d times, want exactly once (inbox dedup of a genuinely redelivered message)", applied)
	}
	var inboxCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM action_inbox WHERE action_ref=$1`, action.ActionRef).Scan(&inboxCount); err != nil {
		t.Fatalf("inbox count: %v", err)
	}
	if inboxCount != 1 {
		t.Fatalf("inbox rows = %d, want 1 (deduped)", inboxCount)
	}
	// The audit chain (which 0G signs) must match the inbox's exactly-once state:
	// the genuinely redelivered message is recorded as ONE completion, not two.
	if n := completionAuditCount(audit, action.ActionRef); n != 1 {
		t.Fatalf("action.completed audit events = %d, want exactly 1 (the redelivered message must not re-audit the completion)", n)
	}
}
