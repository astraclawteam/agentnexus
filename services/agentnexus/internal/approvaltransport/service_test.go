package approvaltransport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

var testBase = time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

const (
	testPlanRef     = "apl_0123456789abcdef"
	testWorkCase    = "wc_0123456789abcdef"
	testApprovalRef = "apv_0123456789abcdef"
	testPlanHash    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testParamHash   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func testPrincipal(class runtime.TrustClass) runtime.PrincipalContext {
	return runtime.PrincipalContext{
		TenantRef:       "ent-1",
		PrincipalRef:    "user-1",
		AgentClientRef:  "agc_0123456789abcdef",
		AgentReleaseRef: "rel-1",
		TrustClass:      class,
		OrgSnapshotRef:  "orgv:12",
		VerifiedAt:      testBase.Add(-time.Minute),
		ExpiresAt:       testBase.Add(time.Hour),
	}
}

func testApprovalRequest() runtime.ApprovalRequest {
	return runtime.ApprovalRequest{
		RequestID:          "req-1",
		BusinessContextRef: testWorkCase,
		Capability:         "erp.purchase_order.approve",
		ParameterHash:      testParamHash,
		Purpose:            "approve purchase order 42",
		Plan:               runtime.ApprovalPlanRef{PlanRef: testPlanRef, PlanHash: testPlanHash, Authority: "agentatlas"},
		ExpiresAt:          testBase.Add(30 * time.Minute),
	}
}

func testEvidence() runtime.ApprovalEvidence {
	return runtime.ApprovalEvidence{
		ApprovalRef:       testApprovalRef,
		PlanRef:           testPlanRef,
		PlanHash:          testPlanHash,
		Capability:        "erp.purchase_order.approve",
		ParameterHash:     testParamHash,
		Decision:          runtime.ApprovalApproved,
		ApproverAuthority: "agentatlas",
		DecidedAt:         testBase,
		Attestation:       runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "atlas-key-1", Value: "c2lnbmF0dXJl"},
	}
}

type transportHarness struct {
	service *Service
	store   *MemoryStore
	channel *MemoryChannel
	audit   *MemoryAuditSink
	now     *time.Time
}

func newTransportHarness(t *testing.T, opts ...Option) *transportHarness {
	t.Helper()
	now := new(time.Time)
	*now = testBase
	store := NewMemoryStore()
	channel := NewMemoryChannel()
	audit := NewMemoryAuditSink()
	options := append([]Option{WithClock(func() time.Time { return *now })}, opts...)
	service, err := NewService(store, channel, audit, options...)
	if err != nil {
		t.Fatal(err)
	}
	return &transportHarness{service: service, store: store, channel: channel, audit: audit, now: now}
}

func TestApprovalTransportConstructionFailsClosed(t *testing.T) {
	t.Parallel()
	store, channel, audit := NewMemoryStore(), NewMemoryChannel(), NewMemoryAuditSink()
	if _, err := NewService(nil, channel, audit); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewService(store, nil, audit); err == nil {
		t.Fatal("nil channel accepted: an approval transmission service without a configured channel must fail closed at construction")
	}
	if _, err := NewService(store, channel, nil); err == nil {
		t.Fatal("nil audit sink accepted")
	}
}

func TestApprovalTransportTransmitsPlanUnchanged(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	request := testApprovalRequest()
	transmission, err := h.service.Transmit(context.Background(), testPrincipal(runtime.TrustFirstParty), request)
	if err != nil {
		t.Fatal(err)
	}
	if transmission.Status != StatusDelivered || transmission.TenantRef != "ent-1" || transmission.PlanRef != testPlanRef || transmission.DeliveryAttempts != 1 || transmission.LastDeliveryOutcome != DeliveryDelivered {
		t.Fatalf("transmission=%+v", transmission)
	}
	deliveries := h.channel.Deliveries()
	if len(deliveries) != 1 {
		t.Fatalf("deliveries=%d", len(deliveries))
	}
	// The caller's signed plan reference and exact operation binding cross the
	// channel UNCHANGED: AgentNexus adds correlation only and never rewrites,
	// narrows or augments the plan.
	delivered := deliveries[0]
	if delivered.TenantRef != "ent-1" || delivered.PlanRef != request.Plan.PlanRef || delivered.PlanHash != request.Plan.PlanHash || delivered.Authority != request.Plan.Authority ||
		delivered.BusinessContextRef != request.BusinessContextRef || delivered.Capability != request.Capability || delivered.ParameterHash != request.ParameterHash ||
		delivered.Purpose != request.Purpose || !delivered.ExpiresAt.Equal(request.ExpiresAt) || delivered.Attempt != 1 {
		t.Fatalf("delivered=%+v request=%+v", delivered, request)
	}
	events := h.audit.Events()
	if len(events) == 0 || events[0].Action != "approval.plan.transmit" || events[0].TenantRef != "ent-1" || events[0].PrincipalRef != "user-1" || events[0].PlanRef != testPlanRef {
		t.Fatalf("audit events=%+v", events)
	}
	status, err := h.service.GetStatus(context.Background(), testPrincipal(runtime.TrustFirstParty), testPlanRef)
	if err != nil || status.Status != StatusDelivered || status.Decision != "" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestApprovalTransportDuplicateTransmitIsIdempotent(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	second, err := h.service.Transmit(context.Background(), principal, testApprovalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != StatusDelivered || second.DeliveryAttempts != 1 {
		t.Fatalf("duplicate transmit=%+v", second)
	}
	if deliveries := h.channel.Deliveries(); len(deliveries) != 1 {
		t.Fatalf("duplicate transmit re-delivered: %d deliveries", len(deliveries))
	}
}

func TestApprovalTransportConflictingPlanBindingRejected(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	conflicting := testApprovalRequest()
	conflicting.ParameterHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	if _, err := h.service.Transmit(context.Background(), principal, conflicting); !errors.Is(err, ErrPlanConflict) {
		t.Fatalf("conflicting rebinding err=%v want ErrPlanConflict", err)
	}
}

func TestApprovalTransportChannelOutageStaysPendingAndRetries(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	h.channel.SetFailure(errors.New("bpm endpoint unreachable"))
	transmission, err := h.service.Transmit(context.Background(), principal, testApprovalRequest())
	if err != nil {
		t.Fatalf("channel outage must keep the accepted transmission pending, not fail the request: %v", err)
	}
	if transmission.Status != StatusPending || transmission.DeliveryAttempts != 1 || transmission.LastDeliveryOutcome != DeliveryFailed {
		t.Fatalf("outage transmission=%+v", transmission)
	}
	// A transport failure cannot create ANY approval progress: no evidence, no
	// decision, and the frozen status vocabulary has no grant state at all.
	status, err := h.service.GetStatus(context.Background(), principal, testPlanRef)
	if err != nil || status.Status != StatusPending || status.Decision != "" || !status.DecidedAt.IsZero() {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	// Provider retry: a later transmit of the SAME plan re-attempts delivery.
	h.channel.SetFailure(nil)
	retried, err := h.service.Transmit(context.Background(), principal, testApprovalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if retried.Status != StatusDelivered || retried.DeliveryAttempts != 2 || retried.LastDeliveryOutcome != DeliveryDelivered {
		t.Fatalf("retried=%+v", retried)
	}
	if deliveries := h.channel.Deliveries(); len(deliveries) != 1 || deliveries[0].Attempt != 2 {
		t.Fatalf("retry deliveries=%+v", deliveries)
	}
}

func TestApprovalTransportValidatesDecisionProviderTrust(t *testing.T) {
	t.Parallel()
	t.Run("untrusted caller rejected before any persistence", func(t *testing.T) {
		h := newTransportHarness(t)
		if _, err := h.service.Transmit(context.Background(), testPrincipal(runtime.TrustUntrusted), testApprovalRequest()); !errors.Is(err, ErrCallerUntrusted) {
			t.Fatalf("err=%v want ErrCallerUntrusted", err)
		}
		if _, err := h.service.GetStatus(context.Background(), testPrincipal(runtime.TrustFirstParty), testPlanRef); !errors.Is(err, ErrNotFound) {
			t.Fatalf("untrusted transmit left a correlation row: %v", err)
		}
		if len(h.channel.Deliveries()) != 0 {
			t.Fatal("untrusted transmit reached the channel")
		}
	})
	t.Run("certified third party fails closed without a wired provider verifier", func(t *testing.T) {
		h := newTransportHarness(t)
		if _, err := h.service.Transmit(context.Background(), testPrincipal(runtime.TrustCertifiedThirdParty), testApprovalRequest()); !errors.Is(err, ErrCallerUntrusted) {
			t.Fatalf("err=%v want ErrCallerUntrusted (nil provider verifier must never behave as a pass-stub)", err)
		}
	})
	t.Run("wired provider verifier is consulted", func(t *testing.T) {
		verifier := &stubProviderVerifier{}
		h := newTransportHarness(t, WithDecisionProviderVerifier(verifier))
		if _, err := h.service.Transmit(context.Background(), testPrincipal(runtime.TrustCertifiedThirdParty), testApprovalRequest()); err != nil {
			t.Fatalf("certified provider rejected: %v", err)
		}
		if verifier.calls != 1 {
			t.Fatalf("provider verifier calls=%d", verifier.calls)
		}
		verifier.err = errors.New("no certified decision provider")
		denied := testApprovalRequest()
		denied.Plan.PlanRef = "apl_fedcba9876543210"
		if _, err := h.service.Transmit(context.Background(), testPrincipal(runtime.TrustCertifiedThirdParty), denied); !errors.Is(err, ErrCallerUntrusted) {
			t.Fatalf("err=%v want ErrCallerUntrusted", err)
		}
	})
	t.Run("invalid principal rejected", func(t *testing.T) {
		h := newTransportHarness(t)
		if _, err := h.service.Transmit(context.Background(), runtime.PrincipalContext{}, testApprovalRequest()); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("err=%v want ErrInvalidInput", err)
		}
	})
}

func TestApprovalTransportRecordsValidatedEvidence(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	record, err := h.service.RecordEvidence(context.Background(), principal, testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if record.TenantRef != "ent-1" || record.Evidence.ApprovalRef != testApprovalRef || record.AuditRefID == "" || record.EvidenceHash == "" {
		t.Fatalf("record=%+v", record)
	}
	status, err := h.service.GetStatus(context.Background(), principal, testPlanRef)
	if err != nil || status.Status != StatusEvidenceRecorded || status.Decision != runtime.ApprovalApproved || !status.DecidedAt.Equal(testEvidence().DecidedAt) {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	// The lineage separates the SUBMISSION act (pre-write) from the
	// ACCEPTANCE marker (post-write): both must exist for accepted evidence.
	var submitted, recorded bool
	for _, event := range h.audit.Events() {
		if event.PlanRef != testPlanRef {
			continue
		}
		switch event.Action {
		case "approval.evidence.submitted":
			submitted = true
		case "approval.evidence.recorded":
			recorded = true
		}
	}
	if !submitted || !recorded {
		t.Fatalf("evidence lineage submitted=%v recorded=%v events=%+v", submitted, recorded, h.audit.Events())
	}
}

func TestApprovalTransportRejectsMismatchedEvidence(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*runtime.ApprovalEvidence){
		"wrong capability": func(e *runtime.ApprovalEvidence) { e.Capability = "erp.purchase_order.reject" },
		"wrong parameter hash": func(e *runtime.ApprovalEvidence) {
			e.ParameterHash = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
		},
		"wrong plan hash": func(e *runtime.ApprovalEvidence) {
			e.PlanHash = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
		},
		"foreign authority": func(e *runtime.ApprovalEvidence) { e.ApproverAuthority = "someone-else" },
	}
	for name, mutate := range cases {
		evidence := testEvidence()
		mutate(&evidence)
		if _, err := h.service.RecordEvidence(context.Background(), principal, evidence); !errors.Is(err, ErrEvidenceRejected) {
			t.Errorf("%s: err=%v want ErrEvidenceRejected", name, err)
		}
	}
	unknown := testEvidence()
	unknown.PlanRef = "apl_fedcba9876543210"
	if _, err := h.service.RecordEvidence(context.Background(), principal, unknown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown plan err=%v want ErrNotFound", err)
	}
	status, err := h.service.GetStatus(context.Background(), principal, testPlanRef)
	if err != nil || status.Status != StatusDelivered {
		t.Fatalf("rejected evidence advanced status: %+v err=%v", status, err)
	}
}

func TestApprovalTransportRejectsExpiredEvidence(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	*h.now = testBase.Add(31 * time.Minute) // past the transmission expiry
	late := testEvidence()
	late.DecidedAt = testBase.Add(31 * time.Minute)
	if _, err := h.service.RecordEvidence(context.Background(), principal, late); !errors.Is(err, ErrEvidenceExpired) {
		t.Fatalf("expired window err=%v want ErrEvidenceExpired", err)
	}
	*h.now = testBase.Add(10 * time.Minute)
	decidedLate := testEvidence()
	decidedLate.DecidedAt = testBase.Add(40 * time.Minute)
	if _, err := h.service.RecordEvidence(context.Background(), principal, decidedLate); !errors.Is(err, ErrEvidenceRejected) {
		t.Fatalf("future decided_at err=%v want ErrEvidenceRejected", err)
	}
	if status, err := h.service.GetStatus(context.Background(), principal, testPlanRef); err != nil || status.Status != StatusDelivered {
		t.Fatalf("expired evidence advanced status: %+v err=%v", status, err)
	}
}

func TestApprovalTransportEvidenceDuplicateAndReplay(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	first, err := h.service.RecordEvidence(context.Background(), principal, testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate delivery of the identical evidence is idempotent.
	duplicate, err := h.service.RecordEvidence(context.Background(), principal, testEvidence())
	if err != nil {
		t.Fatalf("identical duplicate evidence rejected: %v", err)
	}
	if duplicate.EvidenceHash != first.EvidenceHash || duplicate.AuditRefID != first.AuditRefID {
		t.Fatalf("duplicate=%+v first=%+v", duplicate, first)
	}
	// A replayed approval_ref with DIFFERENT content is rejected.
	mutated := testEvidence()
	mutated.Decision = runtime.ApprovalDenied
	if _, err := h.service.RecordEvidence(context.Background(), principal, mutated); !errors.Is(err, ErrEvidenceReplay) {
		t.Fatalf("mutated replay err=%v want ErrEvidenceReplay", err)
	}
	// A second, differently-named decision for the same plan is rejected: one
	// transmitted plan carries exactly one validated decision for Task 0F.
	second := testEvidence()
	second.ApprovalRef = "apv_fedcba9876543210"
	second.Decision = runtime.ApprovalDenied
	if _, err := h.service.RecordEvidence(context.Background(), principal, second); !errors.Is(err, ErrEvidenceReplay) {
		t.Fatalf("second decision err=%v want ErrEvidenceReplay", err)
	}
	// The recorded approval_ref cannot be replayed against another plan.
	other := testApprovalRequest()
	other.Plan.PlanRef = "apl_fedcba9876543210"
	if _, err := h.service.Transmit(context.Background(), principal, other); err != nil {
		t.Fatal(err)
	}
	crossPlan := testEvidence()
	crossPlan.PlanRef = "apl_fedcba9876543210"
	if _, err := h.service.RecordEvidence(context.Background(), principal, crossPlan); !errors.Is(err, ErrEvidenceReplay) {
		t.Fatalf("cross-plan replay err=%v want ErrEvidenceReplay", err)
	}
}

func TestApprovalTransportOutOfOrderEvidenceDoesNotRegressStatus(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	h.channel.SetFailure(errors.New("bpm endpoint unreachable"))
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	// The external authority decided through its own path before our channel
	// ever confirmed delivery: the evidence is recorded and the status
	// advances.
	if _, err := h.service.RecordEvidence(context.Background(), principal, testEvidence()); err != nil {
		t.Fatalf("out-of-order evidence rejected: %v", err)
	}
	status, err := h.service.GetStatus(context.Background(), principal, testPlanRef)
	if err != nil || status.Status != StatusEvidenceRecorded {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	// A late delivery confirmation can never regress the recorded status.
	h.channel.SetFailure(nil)
	late, err := h.service.Transmit(context.Background(), principal, testApprovalRequest())
	if err != nil {
		t.Fatal(err)
	}
	if late.Status != StatusEvidenceRecorded {
		t.Fatalf("late delivery regressed status: %+v", late)
	}
}

func TestApprovalTransportRevokeIsTerminal(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	revoked, err := h.service.Revoke(context.Background(), principal, testPlanRef, "requester withdrew the change")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != StatusRevoked || revoked.RevokedAt.IsZero() || revoked.RevocationReason != "requester withdrew the change" {
		t.Fatalf("revoked=%+v", revoked)
	}
	if _, err := h.service.RecordEvidence(context.Background(), principal, testEvidence()); !errors.Is(err, ErrTransmissionRevoked) {
		t.Fatalf("evidence after revoke err=%v want ErrTransmissionRevoked", err)
	}
	again, err := h.service.Revoke(context.Background(), principal, testPlanRef, "different reason")
	if err != nil || again.RevocationReason != "requester withdrew the change" {
		t.Fatalf("revoke idempotency: %+v err=%v", again, err)
	}
	// A later transmit cannot resurrect a revoked plan or reach the channel.
	before := len(h.channel.Deliveries())
	resurrect, err := h.service.Transmit(context.Background(), principal, testApprovalRequest())
	if err != nil || resurrect.Status != StatusRevoked {
		t.Fatalf("resurrect=%+v err=%v", resurrect, err)
	}
	if len(h.channel.Deliveries()) != before {
		t.Fatal("revoked plan was re-delivered")
	}
	var audited bool
	for _, event := range h.audit.Events() {
		if event.Action == "approval.transmission.revoke" && event.PlanRef == testPlanRef {
			audited = true
		}
	}
	if !audited {
		t.Fatalf("revocation audit missing: %+v", h.audit.Events())
	}
}

func TestApprovalTransportAttestationVerifierSeam(t *testing.T) {
	t.Parallel()
	verifier := &stubAttestationVerifier{err: errors.New("attestation key unknown")}
	h := newTransportHarness(t, WithAttestationVerifier(verifier))
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.RecordEvidence(context.Background(), principal, testEvidence()); !errors.Is(err, ErrEvidenceRejected) {
		t.Fatalf("wired attestation verifier ignored: err=%v", err)
	}
	verifier.err = nil
	if _, err := h.service.RecordEvidence(context.Background(), principal, testEvidence()); err != nil {
		t.Fatalf("attestation verifier pass: %v", err)
	}
	if verifier.calls < 2 {
		t.Fatalf("attestation verifier calls=%d", verifier.calls)
	}
}

func TestApprovalTransportAuditFailuresFailClosed(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	h.audit.SetFailure(errors.New("audit store down"))
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("transmit without audit err=%v want ErrUnavailable", err)
	}
	if _, err := h.service.GetStatus(context.Background(), principal, testPlanRef); !errors.Is(err, ErrNotFound) {
		t.Fatal("unaudited transmit persisted a correlation row")
	}
	h.audit.SetFailure(nil)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	h.audit.SetFailure(errors.New("audit store down"))
	if _, err := h.service.RecordEvidence(context.Background(), principal, testEvidence()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("evidence without audit err=%v want ErrUnavailable", err)
	}
	if status, err := h.service.GetStatus(context.Background(), principal, testPlanRef); err != nil || status.Status != StatusDelivered {
		t.Fatalf("unaudited evidence advanced status: %+v err=%v", status, err)
	}
}

func TestApprovalTransportScopesTenants(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	if _, err := h.service.Transmit(context.Background(), testPrincipal(runtime.TrustFirstParty), testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	foreign := testPrincipal(runtime.TrustFirstParty)
	foreign.TenantRef = "ent-2"
	if _, err := h.service.GetStatus(context.Background(), foreign, testPlanRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant status err=%v want ErrNotFound", err)
	}
	if _, err := h.service.RecordEvidence(context.Background(), foreign, testEvidence()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant evidence err=%v want ErrNotFound", err)
	}
	if _, err := h.service.Revoke(context.Background(), foreign, testPlanRef, "not yours"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant revoke err=%v want ErrNotFound", err)
	}
}

func TestApprovalTransportRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	malformed := testApprovalRequest()
	malformed.Plan.Authority = "AgentNexus"
	if _, err := h.service.Transmit(context.Background(), principal, malformed); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("self-authored plan err=%v want ErrInvalidInput", err)
	}
	stale := testApprovalRequest()
	stale.ExpiresAt = testBase.Add(-time.Minute)
	if _, err := h.service.Transmit(context.Background(), principal, stale); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("already-expired plan err=%v want ErrInvalidInput", err)
	}
	if _, err := h.service.GetStatus(context.Background(), principal, "not-a-plan-handle"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("malformed handle err=%v want ErrInvalidInput", err)
	}
	if _, err := h.service.Revoke(context.Background(), principal, testPlanRef, strings.Repeat("r", 2000)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized reason err=%v want ErrInvalidInput", err)
	}
	invalid := testEvidence()
	invalid.Attestation = runtime.Signature{}
	if _, err := h.service.RecordEvidence(context.Background(), principal, invalid); !errors.Is(err, ErrEvidenceRejected) {
		t.Fatalf("unsigned evidence err=%v want ErrEvidenceRejected", err)
	}
}

type stubProviderVerifier struct {
	calls int
	err   error
}

func (s *stubProviderVerifier) VerifyDecisionProvider(_ context.Context, tenantRef string, principal runtime.PrincipalContext, plan runtime.ApprovalPlanRef) error {
	s.calls++
	if tenantRef == "" || principal.PrincipalRef == "" || plan.PlanRef == "" {
		return errors.New("verifier received an unbound request")
	}
	return s.err
}

type stubAttestationVerifier struct {
	calls int
	err   error
}

func (s *stubAttestationVerifier) VerifyEvidenceAttestation(_ context.Context, tenantRef string, evidence runtime.ApprovalEvidence) error {
	s.calls++
	if tenantRef == "" || evidence.ApprovalRef == "" {
		return errors.New("verifier received an unbound evidence record")
	}
	return s.err
}

func TestApprovalTransportRejectsPaddedPlanAuthority(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	padded := testApprovalRequest()
	padded.Plan.Authority = " agentatlas "
	// The SDK only requires a non-empty authority; the durable store CHECK
	// demands a canonical one. The service rejects the padded form as
	// invalid input so PostgreSQL never turns it into a 503 after audit.
	if _, err := h.service.Transmit(context.Background(), testPrincipal(runtime.TrustFirstParty), padded); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("padded authority err=%v want ErrInvalidInput", err)
	}
	if len(h.channel.Deliveries()) != 0 || len(h.audit.Events()) != 0 {
		t.Fatal("padded authority reached the channel or audit lineage")
	}
}

func TestApprovalTransportAcceptanceMarkerFailureFailsClosed(t *testing.T) {
	t.Parallel()
	h := newTransportHarness(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	if _, err := h.service.Transmit(context.Background(), principal, testApprovalRequest()); err != nil {
		t.Fatal(err)
	}
	// The post-persist acceptance marker cannot be appended: the call fails
	// closed, but the evidence row IS durably stored with its submission
	// lineage (documented Task 0G reconciliation edge).
	h.audit.SetFailureForAction("approval.evidence.recorded", errors.New("audit store down"))
	if _, err := h.service.RecordEvidence(context.Background(), principal, testEvidence()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("acceptance-marker failure err=%v want ErrUnavailable", err)
	}
	status, err := h.service.GetStatus(context.Background(), principal, testPlanRef)
	if err != nil || status.Status != StatusEvidenceRecorded {
		t.Fatalf("status=%+v err=%v (the persisted record must remain authoritative)", status, err)
	}
	// An identical resubmission lands on the idempotent duplicate path and
	// succeeds without a second acceptance marker.
	record, err := h.service.RecordEvidence(context.Background(), principal, testEvidence())
	if err != nil || record.EvidenceHash == "" {
		t.Fatalf("duplicate after marker failure: record=%+v err=%v", record, err)
	}
	var recordedMarkers int
	for _, event := range h.audit.Events() {
		if event.Action == "approval.evidence.recorded" {
			recordedMarkers++
		}
	}
	if recordedMarkers != 0 {
		t.Fatalf("acceptance markers=%d want 0 while the marker append is failing", recordedMarkers)
	}
}
