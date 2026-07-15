package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

type recordingAuditEvidenceSink struct {
	input AuditEvidenceInput
	err   error
}

func (s *recordingAuditEvidenceSink) AppendAuditEvidence(_ context.Context, input AuditEvidenceInput) (string, error) {
	s.input = input
	return "audit-1", s.err
}

func TestAuditEvidenceMapsCanonicalPayloadMismatchToConflict(t *testing.T) {
	sink := &recordingAuditEvidenceSink{err: ErrAuditIdempotencyConflict}
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), sink)
	rr := postAuditEvidence(t, router, strings.NewReader(`{"business_context_ref":"opaque-ticket","action":"dream_policy_created","resource_type":"dream_policy","resource_id":"pol-1"}`), true)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "idempotency_conflict") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

type stubServiceCredentials struct {
	secret string
}

func (s stubServiceCredentials) VerifyServiceCredential(_ context.Context, clientID, secret string) (trust.ServiceIdentity, error) {
	if clientID == "agentatlas" && secret == s.secret {
		return trust.ServiceIdentity{TenantRef: "ent-1", ClientRef: clientID, ReleaseRef: trust.UnregisteredReleaseRef}, nil
	}
	return trust.ServiceIdentity{}, trust.ErrCredentialRejected
}

// newAuditEvidenceTestRouter mounts the audit evidence handler behind the
// trust middleware with a service-credential source, mirroring production.
func newAuditEvidenceTestRouter(t *testing.T, tickets trust.AccessTicketVerifier, sink AuditEvidenceSink) http.Handler {
	t.Helper()
	audit := &recordingTrustAudit{}
	handler, err := newAuditEvidenceHandler("ent-1", tickets, sink, audit)
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef: "ent-1",
		Services:  stubServiceCredentials{secret: "secret"},
		Audit:     browserTrustAuditSink{sink: audit},
		Protected: func(r *http.Request) bool {
			return trustProtectedPath(r.URL.Path)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second)
}

func postAuditEvidence(t *testing.T, router http.Handler, body io.Reader, withBasic bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", body)
	req.Header.Set("Content-Type", "application/json")
	if withBasic {
		req.Header.Set("Idempotency-Key", "audit-handler-key-0001")
		req.SetBasicAuth("agentatlas", "secret")
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func auditTicketStub() *stubTicketActors {
	return &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-1", PrincipalRef: "u-1", TicketRef: "case-1", ExpiresAt: time.Now().Add(time.Hour)}}
}

func TestAuditEvidenceRecordsDreamPolicyCreateRequest(t *testing.T) {
	sink := &recordingAuditEvidenceSink{}
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), sink)
	rr := postAuditEvidence(t, router, strings.NewReader(`{"business_context_ref":"opaque-ticket","action":"dream_policy_create_requested","resource_type":"dream_policy","resource_id":"pol-1","trace_id":"trace-1","details":{"phase":"create_requested"}}`), true)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["audit_ref_id"] != "audit-1" || sink.input.IdempotencyKey != "audit-handler-key-0001" || sink.input.Action != AuditActionDreamPolicyCreateRequested || sink.input.EnterpriseID != "ent-1" || sink.input.ActorUserID != "u-1" || sink.input.CaseTicketID != "case-1" || sink.input.ResourceType != "dream_policy" || sink.input.ResourceID != "pol-1" {
		t.Fatalf("response=%v input=%+v", response, sink.input)
	}
}

func TestAuditEvidenceRejectsUnpersistedWorkflowRunID(t *testing.T) {
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), &recordingAuditEvidenceSink{})
	rr := postAuditEvidence(t, router, strings.NewReader(`{"business_context_ref":"opaque","action":"dream_policy_create_requested","resource_type":"dream_policy","resource_id":"pol-1","workflow_run_id":"run-1"}`), true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAuditActionValidationKeepsLegacyAndRejectsUnknown(t *testing.T) {
	if !ValidAuditEvidenceAction(AuditActionDreamPolicyCreated) {
		t.Fatal("legacy dream_policy_created rejected")
	}
	if !ValidAuditEvidenceAction(AuditActionDreamPolicyCreateRequested) {
		t.Fatal("requested action rejected")
	}
	if ValidAuditEvidenceAction("dream_policy_magic") {
		t.Fatal("unknown action accepted")
	}
}

func TestAuditEvidenceRejectsDetailsBeyondPublicBound(t *testing.T) {
	sink := &recordingAuditEvidenceSink{}
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), sink)
	details := map[string]any{}
	for i := 0; i < 101; i++ {
		details[string(rune('a'+i))] = i
	}
	body, _ := json.Marshal(map[string]any{"business_context_ref": "ticket-1", "action": "dream_policy_create_requested", "resource_type": "dream_policy", "resource_id": "pol-1", "details": details})
	rr := postAuditEvidence(t, router, bytes.NewReader(body), true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestAuditEvidenceRequiresTrustedServiceAndMapsTicketFailures(t *testing.T) {
	body := `{"business_context_ref":"opaque","action":"dream_policy_create_requested","resource_type":"dream_policy","resource_id":"pol-1"}`
	for _, tc := range []struct {
		name    string
		tickets *stubTicketActors
		basic   bool
		want    int
	}{
		{"missing basic", auditTicketStub(), false, 401},
		{"ticket unavailable", &stubTicketActors{err: trust.ErrSourceUnavailable}, true, 503},
		{"invalid ticket", &stubTicketActors{err: trust.ErrCredentialRejected}, true, 401},
		{"cross tenant ticket", &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-2", PrincipalRef: "u", TicketRef: "case"}}, true, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := newAuditEvidenceTestRouter(t, tc.tickets, &recordingAuditEvidenceSink{})
			rr := postAuditEvidence(t, router, strings.NewReader(body), tc.basic)
			if rr.Code != tc.want {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
	t.Run("bad service secret", func(t *testing.T) {
		router := newAuditEvidenceTestRouter(t, auditTicketStub(), &recordingAuditEvidenceSink{})
		req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("agentatlas", "wrong")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d", rr.Code)
		}
	})
	t.Run("browser session is not a service", func(t *testing.T) {
		// A non-service credential must not reach the trusted service
		// endpoint even when valid.
		audit := &recordingTrustAudit{}
		handler, err := newAuditEvidenceHandler("ent-1", auditTicketStub(), &recordingAuditEvidenceSink{}, audit)
		if err != nil {
			t.Fatal(err)
		}
		mux := newGatewayAPIMux("gateway-api", "test")
		handler.register(mux)
		resolver, err := trust.NewResolver(trust.ResolverConfig{
			TenantRef:    "ent-1",
			Sessions:     browserSessionTrustVerifier{sessions: validSessionStub()},
			OrgSnapshots: sealedOrgVersionResolver{source: authorizationPolicySource()},
			Audit:        browserTrustAuditSink{sink: audit},
			Protected: func(r *http.Request) bool {
				return trustProtectedPath(r.URL.Path)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		router := browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second)
		req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestDreamPolicyCreateRequestedRequiresBoundResource(t *testing.T) {
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), &recordingAuditEvidenceSink{})
	for _, body := range []string{
		`{"business_context_ref":"opaque","action":"dream_policy_create_requested","resource_type":"workflow","resource_id":"pol-1"}`,
		`{"business_context_ref":"opaque","action":"dream_policy_create_requested","resource_type":"dream_policy","resource_id":""}`,
	} {
		rr := postAuditEvidence(t, router, strings.NewReader(body), true)
		if rr.Code != 400 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
}

func TestAuditEvidenceBoundsUseUnicodeCodePoints(t *testing.T) {
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), &recordingAuditEvidenceSink{})
	for _, tc := range []struct {
		id   string
		want int
	}{{strings.Repeat("界", 128), 201}, {strings.Repeat("界", 129), 400}} {
		body, _ := json.Marshal(map[string]any{"business_context_ref": "opaque", "action": "dream_policy_create_requested", "resource_type": "dream_policy", "resource_id": tc.id, "details": map[string]any{"note": strings.Repeat("界", 1024)}})
		rr := postAuditEvidence(t, router, bytes.NewReader(body), true)
		if rr.Code != tc.want {
			t.Fatalf("runes=%d status=%d want=%d", len([]rune(tc.id)), rr.Code, tc.want)
		}
	}
}

func TestAuditDetailDepthAndStringBounds(t *testing.T) {
	if !validAuditDetailValue(map[string]any{"note": strings.Repeat("界", 1024)}, 0) {
		t.Fatal("valid unicode detail rejected")
	}
	for _, value := range []any{
		map[string]any{"note": strings.Repeat("界", 1025)},
		map[string]any{strings.Repeat("界", 129): "x"},
		map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": "too deep"}}}}},
	} {
		if validAuditDetailValue(value, 0) {
			t.Fatalf("invalid detail accepted: %#v", value)
		}
	}
}
