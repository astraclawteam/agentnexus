package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

type runtimePrincipal = runtime.PrincipalContext

// recordingTrustAudit records trust rejections through the browser audit sink
// so cutover tests can prove forgeries are audited, not silently dropped.
type recordingTrustAudit struct {
	mu     sync.Mutex
	events []BrowserAuditEvent
}

func (a *recordingTrustAudit) AppendBrowserAudit(_ context.Context, event BrowserAuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func (a *recordingTrustAudit) LogoutBrowserSession(_ context.Context, _ string, event BrowserAuditEvent) (browserauth.BrowserSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return browserauth.BrowserSession{}, nil
}

func (a *recordingTrustAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

const legacyDecisionEnvelope = `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`
const credentialDecisionRequest = `{"request_id":"req-1","trace_id":"trace-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.update","purpose":"triage"}`

// TestIdentityCutoverLegacyEnvelopeIdentityIsNotTrusted proves the retired
// ParseRequestContext no longer exists: request context is built only from a
// verified principal, never from caller-supplied envelope identity values.
func TestIdentityCutoverLegacyEnvelopeIdentityIsNotTrusted(t *testing.T) {
	t.Parallel()
	// A zero (untrusted) context can never mint a request context.
	if _, err := NewRequestContext(trust.Context{}, "req-1", ""); err == nil {
		t.Fatal("request context minted without a verified principal")
	}
	// A verified principal binds correlation; identity comes from it, not the
	// (nonexistent) body identity fields.
	trustedCtx := trust.Context{Principal: validPrincipal(), Source: trust.SourceBrowserSession, OrgVersion: 12}
	rc, err := NewRequestContext(trustedCtx, "req-1", "trace-1")
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	if rc.Principal.TenantRef != "ent-1" || rc.Principal.PrincipalRef != "user-1" || rc.OrgVersion != 12 || rc.RequestID != "req-1" {
		t.Fatalf("request context = %+v", rc)
	}
}

func validPrincipal() runtimePrincipal {
	now := time.Now().UTC()
	return runtimePrincipal{
		TenantRef:       "ent-1",
		PrincipalRef:    "user-1",
		AgentClientRef:  "console",
		AgentReleaseRef: trust.UnregisteredReleaseRef,
		TrustClass:      "first_party_trusted",
		OrgSnapshotRef:  trust.OrgSnapshotRef(12),
		VerifiedAt:      now,
		ExpiresAt:       now.Add(time.Hour),
	}
}

func TestTrustedContextDecisionRejectsLegacyOrgFactEnvelope(t *testing.T) {
	t.Parallel()
	audit := &recordingTrustAudit{}
	router := newAuthorizationTestRouterWithAudit(t, validSessionStub(), nil, authorizationPolicySource(), nil, audit)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(legacyDecisionEnvelope))
	req.Header.Set("Content-Type", "application/json")
	addAuthorizationSession(req)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s: caller-supplied org_unit_id/org_version must be rejected", rr.Code, rr.Body.String())
	}
	if audit.count() == 0 {
		t.Fatal("rejected trusted-identity body fields must be audited")
	}
}

func TestTrustedContextDecisionAcceptsCredentialDerivedCapabilityRequest(t *testing.T) {
	t.Parallel()
	router := newAuthorizationTestRouter(t, validSessionStub(), nil, authorizationPolicySource())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(credentialDecisionRequest))
	req.Header.Set("Content-Type", "application/json")
	addAuthorizationSession(req)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	want := `{"decision":"allow","permissions":["edit"],"org_unit_ids":["root"],"mask_fields":[],"risk_level":"medium","org_version":12}` + "\n"
	if rr.Body.String() != want {
		t.Fatalf("body=%s want=%s", rr.Body.String(), want)
	}
}

func TestTrustedContextRejectsForgedIdentityHeaders(t *testing.T) {
	t.Parallel()
	for _, header := range []string{"X-Org-Version", "X-Trust-Class", "X-Client-Release", "X-Enterprise-Id", "X-Actor-User-Id"} {
		t.Run(header, func(t *testing.T) {
			audit := &recordingTrustAudit{}
			router := newAuthorizationTestRouterWithAudit(t, validSessionStub(), nil, authorizationPolicySource(), nil, audit)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(credentialDecisionRequest))
			req.Header.Set("Content-Type", "application/json")
			addAuthorizationSession(req)
			req.Header.Set(header, "forged")
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d: forged %s header must be rejected at ingress", rr.Code, header)
			}
			if audit.count() == 0 {
				t.Fatalf("forged %s header must be audited", header)
			}
		})
	}
}

func TestTrustedContextAstraClawOriginCannotReachConnectorCapability(t *testing.T) {
	t.Parallel()
	audit := &recordingTrustAudit{}
	router := newAuthorizationTestRouterWithAudit(t, validSessionStub(), nil, authorizationPolicySource(), nil, audit)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"request_id":"req-2","resource_type":"service","resource_id":"erp-1","capability":"connector.erp.read"}`))
	req.Header.Set("Content-Type", "application/json")
	addAuthorizationSession(req)
	req.Header.Set(trust.OriginHeader, "astraclaw")
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s: AstraClaw origin is trace metadata; the request stays well-formed", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"decision":"deny"`) || !strings.Contains(rr.Body.String(), `"risk_level":"high"`) {
		t.Fatalf("AstraClaw connector access must be a high-risk deny: %s", rr.Body.String())
	}
	if audit.count() == 0 {
		t.Fatal("AstraClaw connector denial must be audited")
	}
}

// --- step grant surface ---

type cutoverGrantService struct {
	mu          sync.Mutex
	actor       tickets.Actor
	createCalls int
}

func (s *cutoverGrantService) AuthorizeAndCreateGrant(_ context.Context, actor tickets.Actor, input tickets.CreateStepGrantInput) (tickets.StepGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actor = actor
	s.createCalls++
	return tickets.StepGrant{ID: "grant-1", Token: "opaque-grant", ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scopes: []string{"dream:evidence:read"}, ExpiresAt: time.Unix(1700000000, 0).UTC()}, nil
}

func (s *cutoverGrantService) VerifyGrant(_ context.Context, _ tickets.Actor, _ tickets.VerifyStepGrantInput) (tickets.StepGrant, error) {
	return tickets.StepGrant{}, nil
}

func (s *cutoverGrantService) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createCalls
}

func newGrantCutoverHarness(t *testing.T) (http.Handler, *cutoverGrantService, *recordingTrustAudit) {
	t.Helper()
	service := &cutoverGrantService{}
	audit := &recordingTrustAudit{}
	handler, err := newGrantHandler("ent-1", service, audit)
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	source := policy.NewMemorySnapshotSource()
	source.StoreSnapshot("ent-1", "user-1", policy.SealedAccessSnapshot{TenantRef: "ent-1", OrgVersion: 7, OrgUnits: []policy.SealedOrgUnit{{ID: "research"}}, Memberships: []policy.SealedMembership{{OrgUnitID: "research", Role: "approve_high_risk"}}})
	tickets := &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-1", PrincipalRef: "user-1", TicketRef: "ct-1", ExpiresAt: time.Now().Add(time.Hour)}}
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef:     "ent-1",
		AccessTickets: tickets,
		OrgSnapshots:  sealedOrgVersionResolver{source: source},
		Audit:         browserTrustAuditSink{sink: audit},
		Protected: func(r *http.Request) bool {
			return trustProtectedPath(r.URL.Path)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second), service, audit
}

func postGrantCutover(t *testing.T, router http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/step-grants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "CaseTicket opaque-ticket")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestTrustedContextGrantCreateRejectsCallerOrgFacts(t *testing.T) {
	t.Parallel()
	router, service, audit := newGrantCutoverHarness(t)
	rr := postGrantCutover(t, router, `{"case_ticket_id":"ct-1","org_unit_id":"research","org_version":7,"resource_type":"dream_evidence","resource_id":"res-9","action":"read","ttl_seconds":60}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s: caller-supplied org facts must be rejected", rr.Code, rr.Body.String())
	}
	if service.calls() != 0 {
		t.Fatal("service must not run for a forged-org-fact request")
	}
	if audit.count() == 0 {
		t.Fatal("rejected org facts must be audited")
	}
}

func TestTrustedContextGrantCreateBindsSealedContext(t *testing.T) {
	t.Parallel()
	router, service, _ := newGrantCutoverHarness(t)
	rr := postGrantCutover(t, router, `{"case_ticket_id":"ct-1","resource_type":"dream_evidence","resource_id":"res-9","action":"read","ttl_seconds":60}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if service.calls() != 1 || service.actor.EnterpriseID != "ent-1" || service.actor.UserID != "user-1" || service.actor.CaseTicketID != "ct-1" || service.actor.OrgVersion != 7 {
		t.Fatalf("actor=%+v calls=%d: grant identity and sealed version must be credential-derived", service.actor, service.calls())
	}
}

func TestTrustedContextGrantCreateAuditsLineageConflict(t *testing.T) {
	t.Parallel()
	router, service, audit := newGrantCutoverHarness(t)
	rr := postGrantCutover(t, router, `{"case_ticket_id":"ct-2","resource_type":"dream_evidence","resource_id":"res-9","action":"read","ttl_seconds":60}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s: a body case ticket conflicting with the credential lineage must lose", rr.Code, rr.Body.String())
	}
	if service.calls() != 0 {
		t.Fatal("conflicting lineage must be rejected before the service runs")
	}
	if audit.count() == 0 {
		t.Fatal("body/credential conflicts must be audited")
	}
}

// --- audit evidence surface ---

func TestTrustedContextAuditEvidenceRejectsBodyEnterpriseIdentity(t *testing.T) {
	t.Parallel()
	sink := &recordingAuditEvidenceSink{}
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), sink)
	rr := postAuditEvidence(t, router, strings.NewReader(`{"business_context_ref":"opaque-ticket","enterprise_id":"ent-1","action":"dream_job_run","resource_type":"dream_job","resource_id":"job-1","trace_id":"trace-1","details":{}}`), true)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s: body enterprise identity must be dead as a trust input", rr.Code, rr.Body.String())
	}
	if sink.input.EnterpriseID != "" {
		t.Fatal("no audit evidence may be appended for a rejected legacy envelope")
	}
}

func TestTrustedContextAuditEvidenceBindsTenantFromServiceCredential(t *testing.T) {
	t.Parallel()
	sink := &recordingAuditEvidenceSink{}
	router := newAuditEvidenceTestRouter(t, auditTicketStub(), sink)
	rr := postAuditEvidence(t, router, strings.NewReader(`{"request_id":"req-9","business_context_ref":"opaque-ticket","action":"dream_job_run","resource_type":"dream_job","resource_id":"job-1","trace_id":"trace-1","details":{"summary":"ok"}}`), true)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if sink.input.EnterpriseID != "ent-1" || sink.input.ActorUserID != "u-1" || sink.input.CaseTicketID != "case-1" {
		t.Fatalf("recorded=%+v: audit identity must derive from verified credentials", sink.input)
	}
}
