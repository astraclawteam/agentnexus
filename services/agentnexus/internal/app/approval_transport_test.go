package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const (
	transportPlanRef     = "apl_0123456789abcdef"
	transportWorkCase    = "wc_0123456789abcdef"
	transportApprovalRef = "apv_0123456789abcdef"
	transportPlanHash    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	transportParamHash   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// approvalTransportVersionSource resolves any principal to org version 12 so
// the ingress trust resolver can seal the caller's context in tests.
type approvalTransportVersionSource struct{}

func (approvalTransportVersionSource) LoadAccessSnapshot(_ context.Context, tenantRef, principalRef string) (policy.SealedAccessSnapshot, error) {
	if tenantRef == "" || principalRef == "" {
		return policy.SealedAccessSnapshot{}, policy.ErrPolicyUnavailable
	}
	return policy.SealedAccessSnapshot{TenantRef: tenantRef, OrgVersion: 12}, nil
}

func newApprovalTransportService(t *testing.T) *approvaltransport.Service {
	t.Helper()
	service, err := approvaltransport.NewService(approvaltransport.NewMemoryStore(), approvaltransport.NewMemoryChannel(), approvaltransport.NewMemoryAuditSink())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newApprovalTransportRouter(t *testing.T, sessions browserSessionResolver, tickets trust.AccessTicketVerifier, service ApprovalTransmissionService) http.Handler {
	t.Helper()
	audit := &recordingTrustAudit{}
	mux := newGatewayAPIMux("gateway-api", "test")
	if service != nil {
		handler, err := newApprovalTransportHandler("ent-1", service, audit, nil)
		if err != nil {
			t.Fatal(err)
		}
		handler.register(mux)
	}
	cfg := trust.ResolverConfig{
		TenantRef:    "ent-1",
		OrgSnapshots: sealedOrgVersionResolver{source: approvalTransportVersionSource{}},
		Audit:        browserTrustAuditSink{sink: audit},
		Protected: func(r *http.Request) bool {
			return trustProtectedPath(r.URL.Path)
		},
	}
	if sessions != nil {
		cfg.Sessions = browserSessionTrustVerifier{sessions: sessions}
	}
	cfg.AccessTickets = tickets
	resolver, err := trust.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second)
}

func transportSession(enterprise string) stubAuthorizationSessions {
	return stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: enterprise, UserID: "user-1", IdleExpiresAt: time.Now().Add(time.Hour)}}
}

func transmitBody(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`{"request_id":"req-transmit-1","business_context_ref":%q,"capability":"erp.purchase_order.approve","parameter_hash":%q,"purpose":"approve purchase order 42","plan":{"plan_ref":%q,"plan_hash":%q,"authority":"agentatlas"},"expires_at":%q}`,
		transportWorkCase, transportParamHash, transportPlanRef, transportPlanHash, time.Now().UTC().Add(30*time.Minute).Format(time.RFC3339))
}

func evidenceBody(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	evidence := map[string]any{
		"approval_ref":       transportApprovalRef,
		"plan_ref":           transportPlanRef,
		"plan_hash":          transportPlanHash,
		"capability":         "erp.purchase_order.approve",
		"parameter_hash":     transportParamHash,
		"decision":           "approved",
		"approver_authority": "agentatlas",
		"decided_at":         time.Now().UTC().Format(time.RFC3339),
		"attestation":        map[string]any{"algorithm": "ed25519", "key_id": "atlas-key-1", "value": "c2lnbmF0dXJl"},
	}
	if mutate != nil {
		mutate(evidence)
	}
	payload, err := json.Marshal(map[string]any{"request_id": "req-evidence-1", "evidence": evidence})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func transportRequest(t *testing.T, router http.Handler, method, path, body string, authenticate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticate != nil {
		authenticate(req)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func withTransportSessionCookie(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
}

func TestApprovalTransportPathsAreTrustProtected(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/v1/approvals/transmissions",
		"/v1/approvals/transmissions/" + transportPlanRef,
		"/v1/approvals/transmissions/" + transportPlanRef + "/revocations",
		"/v1/approvals/evidence",
	} {
		if !trustProtectedPath(path) {
			t.Errorf("%s must be trust-protected", path)
		}
	}
}

func TestApprovalTransportFlowsThroughGateway(t *testing.T) {
	t.Parallel()
	router := newApprovalTransportRouter(t, transportSession("ent-1"), nil, newApprovalTransportService(t))

	transmit := transportRequest(t, router, http.MethodPost, "/v1/approvals/transmissions", transmitBody(t), withTransportSessionCookie)
	if transmit.Code != http.StatusOK {
		t.Fatalf("transmit status=%d body=%s", transmit.Code, transmit.Body.String())
	}
	if transmit.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("transmit cache-control=%q", transmit.Header().Get("Cache-Control"))
	}
	var transmitted struct {
		PlanRef          string `json:"plan_ref"`
		Status           string `json:"status"`
		DeliveryAttempts int    `json:"delivery_attempts"`
	}
	if err := json.Unmarshal(transmit.Body.Bytes(), &transmitted); err != nil {
		t.Fatal(err)
	}
	if transmitted.PlanRef != transportPlanRef || transmitted.Status != "delivered" || transmitted.DeliveryAttempts != 1 {
		t.Fatalf("transmitted=%+v", transmitted)
	}

	status := transportRequest(t, router, http.MethodGet, "/v1/approvals/transmissions/"+transportPlanRef, "", withTransportSessionCookie)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"delivered"`) {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}

	evidence := transportRequest(t, router, http.MethodPost, "/v1/approvals/evidence", evidenceBody(t, nil), withTransportSessionCookie)
	if evidence.Code != http.StatusOK {
		t.Fatalf("evidence status=%d body=%s", evidence.Code, evidence.Body.String())
	}
	var recorded struct {
		Status   string `json:"status"`
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(evidence.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Status != "evidence_recorded" || recorded.Decision != "approved" {
		t.Fatalf("recorded=%+v", recorded)
	}

	revoke := transportRequest(t, router, http.MethodPost, "/v1/approvals/transmissions/"+transportPlanRef+"/revocations", `{"request_id":"req-revoke-1","reason":"withdrawn"}`, withTransportSessionCookie)
	if revoke.Code != http.StatusOK || !strings.Contains(revoke.Body.String(), `"revoked"`) {
		t.Fatalf("revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}
}

func TestApprovalTransportGatewayUsesCaseTicketActor(t *testing.T) {
	t.Parallel()
	tickets := &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-1", PrincipalRef: "ticket-user", TicketRef: "ct-1", ExpiresAt: time.Now().Add(time.Hour)}}
	router := newApprovalTransportRouter(t, stubAuthorizationSessions{}, tickets, newApprovalTransportService(t))
	transmit := transportRequest(t, router, http.MethodPost, "/v1/approvals/transmissions", transmitBody(t), func(req *http.Request) {
		req.Header.Set("Authorization", "CaseTicket opaque-ticket")
	})
	if transmit.Code != http.StatusOK {
		t.Fatalf("transmit status=%d body=%s", transmit.Code, transmit.Body.String())
	}
}

func TestApprovalTransportGatewayRejectsForgedIdentityAndUnknownFields(t *testing.T) {
	t.Parallel()
	router := newApprovalTransportRouter(t, transportSession("ent-1"), nil, newApprovalTransportService(t))
	cases := map[string]struct {
		path string
		body string
	}{
		"transmit forged enterprise": {path: "/v1/approvals/transmissions", body: strings.Replace(transmitBody(t), `"request_id"`, `"enterprise_id":"ent-forged","request_id"`, 1)},
		"transmit forged actor":      {path: "/v1/approvals/transmissions", body: strings.Replace(transmitBody(t), `"request_id"`, `"actor_user_id":"someone","request_id"`, 1)},
		"transmit unknown member":    {path: "/v1/approvals/transmissions", body: strings.Replace(transmitBody(t), `"request_id"`, `"reviewer":"someone","request_id"`, 1)},
		"transmit caller org facts":  {path: "/v1/approvals/transmissions", body: strings.Replace(transmitBody(t), `"request_id"`, `"org_version":12,"request_id"`, 1)},
		"evidence forged enterprise": {path: "/v1/approvals/evidence", body: strings.Replace(evidenceBody(t, nil), `"request_id"`, `"enterprise_id":"ent-forged","request_id"`, 1)},
		"evidence unknown member":    {path: "/v1/approvals/evidence", body: strings.Replace(evidenceBody(t, nil), `"request_id"`, `"reviewer_queue":"q","request_id"`, 1)},
	}
	for name, tc := range cases {
		rr := transportRequest(t, router, http.MethodPost, tc.path, tc.body, withTransportSessionCookie)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestApprovalTransportGatewayMapsServiceRejections(t *testing.T) {
	t.Parallel()
	router := newApprovalTransportRouter(t, transportSession("ent-1"), nil, newApprovalTransportService(t))
	if rr := transportRequest(t, router, http.MethodPost, "/v1/approvals/transmissions", transmitBody(t), withTransportSessionCookie); rr.Code != http.StatusOK {
		t.Fatalf("seed transmit status=%d", rr.Code)
	}
	wrongHash := transportRequest(t, router, http.MethodPost, "/v1/approvals/evidence", evidenceBody(t, func(evidence map[string]any) {
		evidence["parameter_hash"] = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	}), withTransportSessionCookie)
	if wrongHash.Code != http.StatusForbidden {
		t.Fatalf("wrong-hash evidence status=%d body=%s", wrongHash.Code, wrongHash.Body.String())
	}
	unknownPlan := transportRequest(t, router, http.MethodGet, "/v1/approvals/transmissions/apl_fedcba9876543210", "", withTransportSessionCookie)
	if unknownPlan.Code != http.StatusNotFound {
		t.Fatalf("unknown plan status=%d body=%s", unknownPlan.Code, unknownPlan.Body.String())
	}
}

func TestApprovalTransportGatewayFailsClosedWhenUnwired(t *testing.T) {
	t.Parallel()
	router := newApprovalTransportRouter(t, transportSession("ent-1"), nil, nil)
	// With no configured transmission service the endpoints are ABSENT: there
	// is no legacy resolution fallback of any kind.
	for _, probe := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/v1/approvals/transmissions", transmitBody(t)},
		{http.MethodGet, "/v1/approvals/transmissions/" + transportPlanRef, ""},
		{http.MethodPost, "/v1/approvals/transmissions/" + transportPlanRef + "/revocations", `{"request_id":"r","reason":"x"}`},
		{http.MethodPost, "/v1/approvals/evidence", evidenceBody(t, nil)},
		{http.MethodPost, "/v1/approvals/resolve", `{}`},
	} {
		rr := transportRequest(t, router, probe.method, probe.path, probe.body, withTransportSessionCookie)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s status=%d want 404", probe.method, probe.path, rr.Code)
		}
	}
}

func TestApprovalTransportGatewayRejectsCrossTenantSession(t *testing.T) {
	t.Parallel()
	router := newApprovalTransportRouter(t, transportSession("ent-2"), nil, newApprovalTransportService(t))
	rr := transportRequest(t, router, http.MethodPost, "/v1/approvals/transmissions", transmitBody(t), withTransportSessionCookie)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestApprovalTransportAuditAppendsChainedInternalEvent covers the
// production audit adapter path: transmission lineage rides the hash-chained
// internal audit ledger (NOT the public /v1/audit/evidence enum), binds the
// plan_ref and returns the minted audit id.
func TestApprovalTransportAuditAppendsChainedInternalEvent(t *testing.T) {
	t.Parallel()
	tx := &fakeAuditEvidenceTx{}
	database := &fakeAuditEvidenceDB{tx: tx, latest: "sha256:prev"}
	sink := newPostgresAuditEvidenceSinkWithDB(database, bytes.NewReader(make([]byte, 36)))
	id, err := sink.AppendApprovalTransmissionAudit(context.Background(), approvaltransport.AuditEvent{
		TenantRef:    "ent-1",
		PrincipalRef: "user-1",
		Action:       "approval.plan.transmit",
		PlanRef:      transportPlanRef,
		Decision:     "accepted",
		Details:      map[string]any{"capability": "erp.purchase_order.approve"},
	})
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	assertAuditEvidenceOrder(t, tx, "begin,lock,previous,append,commit,rollback")
	if tx.params.Action != "approval.plan.transmit" || tx.params.Decision != "accepted" || tx.params.ResourceType.String != "approval_transmission" || tx.params.ResourceID.String != transportPlanRef || tx.params.PrevHash.String != "sha256:prev" || tx.params.EventHash == "" {
		t.Fatalf("params=%+v", tx.params)
	}
	if tx.params.CaseTicketID.Valid {
		t.Fatal("approval transmission lineage must not fabricate a case ticket binding")
	}
	adapter := approvalTransportAuditSink{sink: sink}
	if _, err := adapter.AppendApprovalAudit(context.Background(), approvaltransport.AuditEvent{TenantRef: "ent-1", PrincipalRef: "user-1", Action: "approval.transmission.revoke", PlanRef: transportPlanRef, Decision: "revoked"}); err != nil {
		t.Fatalf("adapter append: %v", err)
	}
	if _, err := (approvalTransportAuditSink{}).AppendApprovalAudit(context.Background(), approvaltransport.AuditEvent{}); err == nil {
		t.Fatal("nil adapter sink must fail closed")
	}
	if _, err := sink.AppendApprovalTransmissionAudit(context.Background(), approvaltransport.AuditEvent{TenantRef: "ent-1"}); err == nil {
		t.Fatal("unbound approval audit event accepted")
	}
}
