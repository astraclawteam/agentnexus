package actions

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

const (
	testWorkCase = "wc_0123456789abcdef"
	testPlanRef  = "apl_0123456789abcdef"
	testPlanHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

func testPrincipal(trust runtime.TrustClass) runtime.PrincipalContext {
	now := time.Now().UTC()
	return runtime.PrincipalContext{
		TenantRef:       "tenant-1",
		PrincipalRef:    "prin-1",
		AgentClientRef:  "agc_client-1",
		AgentReleaseRef: "rel-1",
		TrustClass:      trust,
		OrgSnapshotRef:  "org-1",
		VerifiedAt:      now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
}

func testSignature() runtime.Signature {
	return runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "k1", Value: "AAAA"}
}

func testRequest(t *testing.T) runtime.ActionRequest {
	t.Helper()
	params, hash, err := runtime.BuildParameters(map[string]any{"amount": 100})
	if err != nil {
		t.Fatalf("build parameters: %v", err)
	}
	now := time.Now().UTC()
	return runtime.ActionRequest{
		RequestID:          "req-1",
		BusinessContextRef: testWorkCase,
		Capability:         "erp.purchase_order.approve",
		Parameters:         params,
		ParameterHash:      hash,
		Purpose:            "approve PO",
		RiskDecision: runtime.RiskDecision{
			DecisionID:         "dec-1",
			Authority:          "acme-risk",
			RiskLevel:          runtime.RiskMedium,
			Capability:         "erp.purchase_order.approve",
			ParameterHash:      hash,
			BusinessContextRef: testWorkCase,
			IssuedAt:           now.Add(-time.Minute),
			ExpiresAt:          now.Add(time.Hour),
			Signature:          testSignature(),
		},
		IdempotencyKey:        "idem-0123456789abcd",
		ExpiresAt:             now.Add(30 * time.Minute),
		ExpectedReceiptSchema: "erp.receipt.v1",
	}
}

func testApprovalRequest(t *testing.T) runtime.ActionRequest {
	t.Helper()
	req := testRequest(t)
	req.ApprovalPlanRef = &runtime.ApprovalPlanRef{PlanRef: testPlanRef, PlanHash: testPlanHash, Authority: "acme-approvals"}
	return req
}

func testReceipt(action Action, status runtime.ActionStatus) runtime.ActionReceipt {
	result, hash, _ := runtime.BuildParameters(map[string]any{"po_id": "po-1"})
	return runtime.ActionReceipt{
		ReceiptRef:    "rcp_0123456789abcdef",
		ActionRef:     action.ActionRef,
		Status:        status,
		Capability:    action.Capability,
		ParameterHash: action.ParameterHash,
		ReceiptSchema: action.ExpectedReceiptSchema,
		Result:        result,
		ResultHash:    hash,
		IssuedAt:      time.Now().UTC(),
	}
}

// sequentialIDs mints deterministic opaque handles for test assertions.
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

func newTestService(t *testing.T, opts ...Option) (*Service, *MemoryStore, *MemoryAuditSink) {
	t.Helper()
	store := NewMemoryStore()
	audit := NewMemoryAuditSink()
	// The completion gate fails closed without a verifier, so tests that are not
	// about receipt authenticity wire a default accepting verifier; receipt-
	// security tests override it via opts (later options win).
	base := []Option{WithIDGenerator(sequentialIDs()), WithReceiptVerifier(&fakeReceiptVerifier{})}
	svc, err := NewService(store, audit, append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store, audit
}

// mustRequestGranted drives a first-party action from request through grant to
// the dispatched-ready granted state (no approval plan).
func mustGranted(t *testing.T, svc *Service, principal runtime.PrincipalContext, req runtime.ActionRequest) Action {
	t.Helper()
	ctx := context.Background()
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	granted, err := svc.Grant(ctx, principal, action.ActionRef)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return granted
}

func TestActionRequestPersistsOneLogicalActionAndIsIdempotent(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	req := testRequest(t)
	ctx := context.Background()

	first, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if first.Status != StatusRequested {
		t.Fatalf("status = %q, want requested", first.Status)
	}
	if first.ActionRef == "" || first.Capability != req.Capability || first.ParameterHash != req.ParameterHash {
		t.Fatalf("action not bound to the request: %+v", first)
	}
	// A duplicate request under the same idempotency key returns the SAME Action
	// and never creates a second side effect.
	again, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("idempotent re-request: %v", err)
	}
	if again.ActionRef != first.ActionRef {
		t.Fatalf("idempotent re-request minted a new action %q != %q", again.ActionRef, first.ActionRef)
	}
}

func TestActionIdempotencyKeyConflictRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	req := testRequest(t)
	if _, err := svc.RequestAction(ctx, principal, req); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// Same idempotency key, DIFFERENT operation: rejected, never silently reused.
	other := testRequest(t)
	params, hash, _ := runtime.BuildParameters(map[string]any{"amount": 999})
	other.Parameters = params
	other.ParameterHash = hash
	other.RiskDecision.ParameterHash = hash
	if _, err := svc.RequestAction(ctx, principal, other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting idempotency key err = %v, want ErrIdempotencyConflict", err)
	}
}

func TestActionRequestWithApprovalPlanWaitsForApproval(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	action, err := svc.RequestAction(context.Background(), principal, testApprovalRequest(t))
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if action.Status != StatusAwaitingApproval {
		t.Fatalf("status = %q, want awaiting_approval", action.Status)
	}
}

func TestActionGrantConsumesApprovalEvidenceOnceAndMintsOneUseGrant(t *testing.T) {
	consumer := NewMemoryEvidenceConsumer()
	svc, store, _ := newTestService(t, WithEvidenceConsumer(consumer))
	principal := testPrincipal(runtime.TrustFirstParty)
	req := testApprovalRequest(t)
	consumer.Seed(principal.TenantRef, ConsumedEvidence{ApprovalRef: "apv_evidence00000001", PlanRef: testPlanRef, Capability: req.Capability, ParameterHash: req.ParameterHash, Decision: runtime.ApprovalApproved})
	ctx := context.Background()

	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	granted, err := svc.Grant(ctx, principal, action.ActionRef)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if granted.Status != StatusGranted || granted.GrantRef == "" {
		t.Fatalf("granted = %+v, want status granted with a grant_ref", granted)
	}
	grants := store.Grants()
	if len(grants) != 1 || !grants[0].OneUse || grants[0].Capability != req.Capability || grants[0].ParameterHash != req.ParameterHash {
		t.Fatalf("minted grant = %+v, want one one-use grant bound to the exact operation", grants)
	}
	// Step Grant double consumption: the one-shot approval evidence cannot be
	// consumed twice, so a second grant is rejected.
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err == nil {
		t.Fatal("second grant succeeded; approval evidence must be one-shot")
	}
}

func TestActionApprovalEvidenceMismatchRejected(t *testing.T) {
	consumer := NewMemoryEvidenceConsumer()
	svc, _, _ := newTestService(t, WithEvidenceConsumer(consumer))
	principal := testPrincipal(runtime.TrustFirstParty)
	req := testApprovalRequest(t)
	// Evidence approves a DIFFERENT capability than the action requested.
	consumer.Seed(principal.TenantRef, ConsumedEvidence{ApprovalRef: "apv_evidence00000001", PlanRef: testPlanRef, Capability: "erp.invoice.pay", ParameterHash: req.ParameterHash, Decision: runtime.ApprovalApproved})
	ctx := context.Background()
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); !errors.Is(err, ErrEvidenceRejected) {
		t.Fatalf("mismatched evidence err = %v, want ErrEvidenceRejected", err)
	}
}

func TestActionDispatchConsumesGrantOnceAndWritesOutbox(t *testing.T) {
	svc, store, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	granted := mustGranted(t, svc, principal, testRequest(t))
	ctx := context.Background()

	dispatched, err := svc.Dispatch(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if dispatched.Status != StatusDispatched {
		t.Fatalf("status = %q, want dispatched", dispatched.Status)
	}
	pending, err := store.PendingDispatches(ctx, principal.TenantRef, 0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending outbox = %+v err=%v, want exactly one durable dispatch row", pending, err)
	}
	grants := store.Grants()
	if len(grants) != 1 || grants[0].ConsumedAt.IsZero() {
		t.Fatalf("grant not consumed on dispatch: %+v", grants)
	}
	// Second dispatch cannot re-consume the one-use grant.
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err == nil {
		t.Fatal("second dispatch succeeded; the one-use grant must be consumed exactly once")
	}
}

func TestActionReceiptCompletesOnlyWithExactBinding(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	executing, err := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	// A receipt bound to a DIFFERENT parameter hash cannot complete the action.
	bad := testReceipt(executing, runtime.StatusSucceeded)
	bad.ParameterHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	bad.ResultHash = ""
	bad.Result = nil
	if _, err := svc.IngestReceipt(ctx, principal, "res-bad", bad); !errors.Is(err, ErrReceiptRejected) {
		t.Fatalf("mismatched receipt err = %v, want ErrReceiptRejected", err)
	}
	// A receipt whose schema differs from the declared ExpectedReceiptSchema is
	// rejected.
	wrongSchema := testReceipt(executing, runtime.StatusSucceeded)
	wrongSchema.ReceiptSchema = "erp.receipt.v2"
	if _, err := svc.IngestReceipt(ctx, principal, "res-schema", wrongSchema); !errors.Is(err, ErrReceiptRejected) {
		t.Fatalf("wrong-schema receipt err = %v, want ErrReceiptRejected", err)
	}
	// The exact receipt completes the action to the technical succeeded status.
	good := testReceipt(executing, runtime.StatusSucceeded)
	done, err := svc.IngestReceipt(ctx, principal, "res-ok", good)
	if err != nil {
		t.Fatalf("IngestReceipt: %v", err)
	}
	if done.Status != StatusSucceeded || done.ReceiptRef != good.ReceiptRef {
		t.Fatalf("completed = %+v, want succeeded with the receipt ref", done)
	}
}

// fakeReceiptVerifier is a wired ReceiptVerifier for the completion-seam tests:
// it records the calls and returns a configured error (mirrors
// fakeDecisionProvider in trust_test.go).
type fakeReceiptVerifier struct {
	err   error
	calls int
}

func (f *fakeReceiptVerifier) VerifyReceipt(_ context.Context, _ string, _ runtime.ActionReceipt) error {
	f.calls++
	return f.err
}

// A wired ReceiptVerifier that DENIES a structurally-valid, exactly-bound
// receipt propagates as ErrReceiptRejected: "only a verified signed
// ActionReceipt completes an Action" — a wired rejection is never overridden
// by the passing local structural checks.
func TestActionReceiptVerifierWiredDenyRejectsStructurallyValidReceipt(t *testing.T) {
	verifier := &fakeReceiptVerifier{err: errors.New("signature does not verify against the registered connector key")}
	svc, _, _ := newTestService(t, WithReceiptVerifier(verifier))
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	executing, err := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	// The receipt binds the exact action, matches the declared schema and has a
	// terminal technical status: it passes every LOCAL structural check.
	receipt := testReceipt(executing, runtime.StatusSucceeded)
	if _, err := svc.IngestReceipt(ctx, principal, "res-verifier-deny", receipt); !errors.Is(err, ErrReceiptRejected) {
		t.Fatalf("wired-deny receipt err = %v, want ErrReceiptRejected", err)
	}
	if verifier.calls == 0 {
		t.Fatal("wired ReceiptVerifier was never consulted")
	}
	// The action never completed: it stays in executing, not succeeded.
	after, err := svc.GetAction(ctx, principal, granted.ActionRef)
	if err != nil || after.Status != StatusExecuting {
		t.Fatalf("action after denied receipt = %+v err=%v, want it to stay executing (never completed)", after, err)
	}
}

func TestActionReceiptRejectsNonTerminalCompletion(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	_, _ = svc.Dispatch(ctx, principal, granted.ActionRef)
	executing, _ := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	// `succeeded` is the declared TECHNICAL execution only. A receipt whose
	// status is not a terminal technical outcome (succeeded/failed) may never
	// complete an action — the runtime never invents a business Outcome.
	receipt := testReceipt(executing, StatusExecuting)
	if _, err := svc.IngestReceipt(ctx, principal, "res-nonterminal", receipt); !errors.Is(err, ErrReceiptRejected) {
		t.Fatalf("non-terminal receipt err = %v, want ErrReceiptRejected", err)
	}
}

func TestActionDuplicateReceiptDeduped(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	_, _ = svc.Dispatch(ctx, principal, granted.ActionRef)
	executing, _ := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	receipt := testReceipt(executing, runtime.StatusSucceeded)
	if _, err := svc.IngestReceipt(ctx, principal, "res-1", receipt); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	// A redelivered/duplicate result with the same result id is applied once and
	// never re-completes the action.
	done, err := svc.IngestReceipt(ctx, principal, "res-1", receipt)
	if err != nil {
		t.Fatalf("duplicate ingest err = %v, want a clean idempotent no-op", err)
	}
	if done.Status != StatusSucceeded {
		t.Fatalf("duplicate ingest status = %q, want succeeded", done.Status)
	}
}

// completionAuditCount counts the action.completed lineage events emitted for
// one action. The audit chain is exactly what GA Task 0G signs and
// independently verifies, so a completion must be recorded EXACTLY ONCE per
// genuine completion — never for a deduped redelivery or a rejected receipt.
func completionAuditCount(audit *MemoryAuditSink, actionRef string) int {
	count := 0
	for _, event := range audit.Events() {
		if event.Action == auditActionCompleted && event.ActionRef == actionRef {
			count++
		}
	}
	return count
}

// A duplicate redelivery (same result_id, already applied) is an idempotent
// no-op that must emit ZERO additional completion audit events: the inbox
// dedups the STATE exactly-once, and the AUDIT dimension (which 0G signs) must
// match — one genuine completion, one action.completed event, no matter how
// many times the connector retries or NATS redelivers.
func TestActionDuplicateReceiptEmitsExactlyOneCompletionAudit(t *testing.T) {
	svc, _, audit := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	executing, err := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	receipt := testReceipt(executing, runtime.StatusSucceeded)
	if _, err := svc.IngestReceipt(ctx, principal, "res-dup", receipt); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	// Three redeliveries of the same result_id (connector retry / at-least-once).
	for i := 0; i < 3; i++ {
		if _, err := svc.IngestReceipt(ctx, principal, "res-dup", receipt); err != nil {
			t.Fatalf("redelivery %d: %v", i, err)
		}
	}
	if n := completionAuditCount(audit, granted.ActionRef); n != 1 {
		t.Fatalf("action.completed audit events = %d, want exactly 1 (redeliveries must not re-audit the completion)", n)
	}
}

// A genuinely different receipt (different result_id) arriving out of order for
// an already-terminal action is rejected and must emit ZERO completion audit
// events: no signed audit lie for a receipt that never took effect.
func TestActionOutOfOrderReceiptEmitsNoCompletionAudit(t *testing.T) {
	svc, _, audit := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	executing, err := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	first := testReceipt(executing, runtime.StatusSucceeded)
	if _, err := svc.IngestReceipt(ctx, principal, "res-first", first); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	second := testReceipt(executing, runtime.StatusSucceeded)
	second.ReceiptRef = "rcp_0123456789abcdeh"
	if _, err := svc.IngestReceipt(ctx, principal, "res-second-out-of-order", second); !errors.Is(err, ErrForbiddenTransition) {
		t.Fatalf("out-of-order receipt err = %v, want ErrForbiddenTransition", err)
	}
	if n := completionAuditCount(audit, granted.ActionRef); n != 1 {
		t.Fatalf("action.completed audit events = %d, want exactly 1 (the rejected out-of-order receipt must NOT be audited)", n)
	}
}

func TestActionTimeoutAfterExecutionBecomesResultUnknownAndForbidsBlindRetry(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	_, _ = svc.Dispatch(ctx, principal, granted.ActionRef)
	executing, _ := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	unknown, err := svc.MarkResultUnknown(ctx, principal, executing.ActionRef)
	if err != nil {
		t.Fatalf("MarkResultUnknown: %v", err)
	}
	if unknown.Status != StatusResultUnknown {
		t.Fatalf("status = %q, want result_unknown", unknown.Status)
	}
	// Blind retry is forbidden: a dispatched side effect whose result is unknown
	// must reconcile, never re-dispatch.
	if _, err := svc.Dispatch(ctx, principal, executing.ActionRef); !errors.Is(err, ErrBlindRetryForbidden) && !errors.Is(err, ErrForbiddenTransition) {
		t.Fatalf("blind re-dispatch err = %v, want a forbidden/blind-retry rejection", err)
	}
}

func TestActionReconciliationSuccessAndFailure(t *testing.T) {
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()

	drive := func(resolve runtime.ActionStatus, withReceipt bool) Action {
		svc, _, _ := newTestService(t)
		granted := mustGranted(t, svc, principal, testRequest(t))
		_, _ = svc.Dispatch(ctx, principal, granted.ActionRef)
		executing, _ := svc.MarkExecuting(ctx, principal, granted.ActionRef)
		if _, err := svc.MarkResultUnknown(ctx, principal, executing.ActionRef); err != nil {
			t.Fatalf("MarkResultUnknown: %v", err)
		}
		reconciling, err := svc.BeginReconciliation(ctx, principal, executing.ActionRef)
		if err != nil {
			t.Fatalf("BeginReconciliation: %v", err)
		}
		if reconciling.Status != StatusReconciling {
			t.Fatalf("status = %q, want reconciling", reconciling.Status)
		}
		var receipt *runtime.ActionReceipt
		if withReceipt {
			r := testReceipt(reconciling, resolve)
			receipt = &r
		}
		resolved, err := svc.ResolveReconciliation(ctx, principal, executing.ActionRef, resolve, receipt)
		if err != nil {
			t.Fatalf("ResolveReconciliation(%s): %v", resolve, err)
		}
		return resolved
	}

	if done := drive(StatusSucceeded, true); done.Status != StatusSucceeded {
		t.Fatalf("reconcile-success status = %q", done.Status)
	}
	if done := drive(StatusFailed, false); done.Status != StatusFailed {
		t.Fatalf("reconcile-failure status = %q", done.Status)
	}
}

func TestActionCompensationIsSeparatelyAuthorized(t *testing.T) {
	svc, store, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	req := testRequest(t)
	req.CompensationRef = "erp.purchase_order.void"
	granted := mustGranted(t, svc, principal, req)
	_, _ = svc.Dispatch(ctx, principal, granted.ActionRef)
	executing, _ := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	receipt := testReceipt(executing, runtime.StatusSucceeded)
	if _, err := svc.IngestReceipt(ctx, principal, "res-ok", receipt); err != nil {
		t.Fatalf("IngestReceipt: %v", err)
	}

	compensation, err := svc.Compensate(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("Compensate: %v", err)
	}
	// Compensation is a SEPARATE governed Action with its own action_ref and its
	// own capability (the declared compensation), not a magic rollback.
	if compensation.ActionRef == granted.ActionRef {
		t.Fatal("compensation reused the original action_ref")
	}
	if compensation.CompensationOf != granted.ActionRef || compensation.Capability != req.CompensationRef {
		t.Fatalf("compensation = %+v, want a new action of the declared compensation capability bound to the original", compensation)
	}
	original, err := store.GetAction(ctx, principal.TenantRef, granted.ActionRef)
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	if original.Status != StatusCompensating {
		t.Fatalf("original status = %q, want compensating", original.Status)
	}

	// An action that declared NO compensation reference cannot be compensated.
	svc2, _, _ := newTestService(t)
	plain := mustGranted(t, svc2, principal, testRequest(t))
	_, _ = svc2.Dispatch(ctx, principal, plain.ActionRef)
	ex2, _ := svc2.MarkExecuting(ctx, principal, plain.ActionRef)
	if _, err := svc2.IngestReceipt(ctx, principal, "res-plain", testReceipt(ex2, runtime.StatusSucceeded)); err != nil {
		t.Fatalf("ingest plain: %v", err)
	}
	if _, err := svc2.Compensate(ctx, principal, plain.ActionRef); !errors.Is(err, ErrCompensationUndeclared) {
		t.Fatalf("undeclared compensation err = %v, want ErrCompensationUndeclared", err)
	}
}

func TestActionHumanTakeoverFromLiveState(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	taken, err := svc.HumanTakeover(ctx, principal, granted.ActionRef, "operator intervened")
	if err != nil {
		t.Fatalf("HumanTakeover: %v", err)
	}
	if taken.Status != StatusHumanTakeover {
		t.Fatalf("status = %q, want human_takeover", taken.Status)
	}
}

func TestActionCancellationAfterDispatchEscalates(t *testing.T) {
	svc, _, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	// A cancellation AFTER dispatch cannot guarantee the side effect did not run,
	// so it escalates to human takeover rather than silently "cancelling".
	cancelled, err := svc.Cancel(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancelled.Status != StatusHumanTakeover {
		t.Fatalf("cancel-after-dispatch status = %q, want human_takeover", cancelled.Status)
	}
}

func TestActionCrashBeforePublishReplaysOutbox(t *testing.T) {
	// Simulate a crash BETWEEN the outbox commit and the publish by dispatching
	// through a service that never reaches a publisher at all, then recovering
	// over the SAME durable store with one wired. This is the ONLY window the
	// pump exists for — an ordinary dispatch publishes itself, which
	// TestActionDispatchPublishesWithoutWaitingForTheRecoveryPump pins.
	crashed, store, audit := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, crashed, principal, testRequest(t))
	if _, err := crashed.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	pending, _ := store.PendingDispatches(ctx, principal.TenantRef, 0)
	if len(pending) != 1 {
		t.Fatalf("pending before replay = %d, want 1", len(pending))
	}
	recorder := &recordingPublisher{}
	svc, err := NewService(store, audit, WithIDGenerator(sequentialIDs()), WithReceiptVerifier(&fakeReceiptVerifier{}), WithPublisher(recorder))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	// Recovery republishes the durable intent exactly once and marks it published.
	n, err := svc.RepublishPending(ctx, principal.TenantRef)
	if err != nil || n != 1 {
		t.Fatalf("RepublishPending = %d err=%v, want 1", n, err)
	}
	if len(recorder.messages()) != 1 {
		t.Fatalf("published %d messages, want 1", len(recorder.messages()))
	}
	after, _ := store.PendingDispatches(ctx, principal.TenantRef, 0)
	if len(after) != 0 {
		t.Fatalf("pending after replay = %d, want 0 (published)", len(after))
	}
}

type recordingPublisher struct {
	mu   sync.Mutex
	sent []DispatchMessage
}

func (p *recordingPublisher) PublishDispatch(_ context.Context, message DispatchMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, message)
	return nil
}

func (p *recordingPublisher) messages() []DispatchMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]DispatchMessage(nil), p.sent...)
}
