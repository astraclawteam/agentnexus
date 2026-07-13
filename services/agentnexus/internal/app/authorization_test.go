package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

type unavailableSnapshotSource struct{ err error }

func (s unavailableSnapshotSource) LoadAccessSnapshot(context.Context, string, string) (policy.SealedAccessSnapshot, error) {
	return policy.SealedAccessSnapshot{}, s.err
}

type stubAuthorizationSessions struct {
	session browserauth.BrowserSession
	err     error
	calls   *int
}

func (s stubAuthorizationSessions) GetSession(context.Context, string) (browserauth.BrowserSession, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.session, s.err
}

type stubTicketActors struct {
	identity trust.TicketIdentity
	err      error
	token    string
}

func (s *stubTicketActors) VerifyAccessTicket(_ context.Context, token string) (trust.TicketIdentity, error) {
	s.token = token
	if s.err != nil {
		return trust.TicketIdentity{}, s.err
	}
	return s.identity, nil
}

// failingCapabilityEvaluator simulates a policy outage AFTER ingress sealed
// the context (the ingress snapshot resolution succeeded).
type failingCapabilityEvaluator struct{ err error }

func (e failingCapabilityEvaluator) Evaluate(context.Context, policy.CapabilityRequest) (policy.PermissionDecision, error) {
	return policy.PermissionDecision{}, e.err
}

// newAuthorizationTestRouter mirrors the production chain: mux + handlers +
// trust resolver middleware + request deadline. Identity is resolved ONCE at
// ingress; the handler consumes the immutable context.
func newAuthorizationTestRouter(t *testing.T, sessions browserSessionResolver, ticketActors trust.AccessTicketVerifier, source policy.SnapshotSource) http.Handler {
	t.Helper()
	return newAuthorizationTestRouterWithAudit(t, sessions, ticketActors, source, nil, &recordingTrustAudit{})
}

func newAuthorizationTestRouterWithAudit(t *testing.T, sessions browserSessionResolver, ticketActors trust.AccessTicketVerifier, source policy.SnapshotSource, evaluator capabilityDecisionEvaluator, audit BrowserAuditSink) http.Handler {
	t.Helper()
	if evaluator == nil {
		evaluator = policy.NewCapabilityEvaluator(source)
	}
	handler, err := newAuthorizationHandler(authorizationDependencies{EnterpriseID: "ent-1", Evaluator: evaluator, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	resolver := newTestTrustResolver(t, sessions, ticketActors, source, audit)
	return browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second)
}

func newTestTrustResolver(t *testing.T, sessions browserSessionResolver, ticketActors trust.AccessTicketVerifier, source policy.SnapshotSource, audit BrowserAuditSink) *trust.Resolver {
	t.Helper()
	cfg := trust.ResolverConfig{
		TenantRef:    "ent-1",
		OrgSnapshots: sealedOrgVersionResolver{source: source},
		Audit:        browserTrustAuditSink{sink: audit},
		Protected: func(r *http.Request) bool {
			return trustProtectedPath(r.URL.Path)
		},
	}
	if sessions != nil {
		cfg.Sessions = browserSessionTrustVerifier{sessions: sessions}
	}
	cfg.AccessTickets = ticketActors
	resolver, err := trust.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func authorizationPolicySource() policy.SnapshotSource {
	source := policy.NewMemorySnapshotSource()
	source.StoreSnapshot("ent-1", "user-1", policy.SealedAccessSnapshot{TenantRef: "ent-1", OrgVersion: 12, OrgUnits: []policy.SealedOrgUnit{{ID: "child", ParentID: "root"}, {ID: "root"}}, Memberships: []policy.SealedMembership{{OrgUnitID: "root", Role: "edit"}, {OrgUnitID: "root", Role: "suggest"}}})
	return source
}

func addAuthorizationSession(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
}

func addAuthorizationTicket(req *http.Request) {
	req.Header.Set("Authorization", "CaseTicket opaque-ticket")
}

func validSessionStub() stubAuthorizationSessions {
	return stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1", IdleExpiresAt: time.Now().Add(time.Hour)}}
}

func decisionBody(resourceType, resourceID, capability string) string {
	return `{"request_id":"req-1","resource_type":"` + resourceType + `","resource_id":"` + resourceID + `","capability":"` + capability + `"}`
}

func TestAuthorizationSemanticRefusalsReturnCompleteDenyDecision(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		body     string
		wantRisk policy.CapabilityRisk
	}{
		{name: "unknown capability", body: decisionBody("knowledge", "article-1", "knowledge.unknown"), wantRisk: policy.CapabilityRiskHigh},
		{name: "resource mismatch", body: decisionBody("workflow", "article-1", "knowledge.suggest"), wantRisk: policy.CapabilityRiskHigh},
		{name: "no granting membership", body: decisionBody("workflow", "flow-1", "workflow.edit_advanced"), wantRisk: policy.CapabilityRiskHigh},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := newAuthorizationTestRouter(t, validSessionStub(), nil, authorizationPolicySource())
			req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")
			addAuthorizationSession(req)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			var decision policy.PermissionDecision
			if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &decision) != nil || decision.Decision != policy.DecisionDeny || decision.OrgVersion != 12 || decision.RiskLevel != test.wantRisk || decision.Permissions == nil || decision.OrgUnitIDs == nil || decision.MaskFields == nil {
				t.Fatalf("status=%d decision=%#v body=%s", rr.Code, decision, rr.Body.String())
			}
		})
	}
}

func TestAuthorizationUnavailablePolicyReturnsRetryableCompleteDeny(t *testing.T) {
	t.Parallel()
	// Ingress sealed the context at version 12; the evaluator then fails.
	// The 503 deny carries the SERVER-sealed version, never caller data.
	router := newAuthorizationTestRouterWithAudit(t, validSessionStub(), nil, authorizationPolicySource(), failingCapabilityEvaluator{err: errors.New("database offline")}, &recordingTrustAudit{})
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	req.Header.Set("Content-Type", "application/json")
	addAuthorizationSession(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	var decision policy.PermissionDecision
	if err := json.Unmarshal(rr.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode deny: %v body=%s", err, rr.Body.String())
	}
	if rr.Code != http.StatusServiceUnavailable || decision.Decision != policy.DecisionDeny || decision.OrgVersion != 12 || decision.RiskLevel != policy.CapabilityRiskHigh || decision.Permissions == nil || decision.OrgUnitIDs == nil || decision.MaskFields == nil {
		t.Fatalf("status=%d decision=%#v body=%s", rr.Code, decision, rr.Body.String())
	}
}

func TestAuthorizationSnapshotOutageAtIngressFailsClosed(t *testing.T) {
	t.Parallel()
	router := newAuthorizationTestRouter(t, validSessionStub(), nil, unavailableSnapshotSource{err: errors.New("database offline")})
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	req.Header.Set("Content-Type", "application/json")
	addAuthorizationSession(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAuthorizationDecisionUsesAuthenticatedSessionActor(t *testing.T) {
	t.Parallel()
	router := newAuthorizationTestRouter(t, validSessionStub(), nil, authorizationPolicySource())
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"request_id":"req-1","trace_id":"trace-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.update","purpose":"triage"}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	want := `{"decision":"allow","permissions":["edit"],"org_unit_ids":["root"],"mask_fields":[],"risk_level":"medium","org_version":12}` + "\n"
	if rr.Body.String() != want {
		t.Fatalf("body=%s want=%s", rr.Body.String(), want)
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers=%v", rr.Header())
	}
}

func TestAuthorizationDecisionUsesAuthenticatedTicketActor(t *testing.T) {
	t.Parallel()
	tickets := &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-1", PrincipalRef: "user-1", TicketRef: "ct-1", ExpiresAt: time.Now().Add(time.Hour)}}
	router := newAuthorizationTestRouter(t, stubAuthorizationSessions{err: browserauth.ErrInvalidSession}, tickets, authorizationPolicySource())
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "CaseTicket opaque-ticket")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"decision":"allow"`) || tickets.token != "opaque-ticket" {
		t.Fatalf("status=%d token=%q body=%s", rr.Code, tickets.token, rr.Body.String())
	}
}

func TestGatewayRouterRegistersAuthorizationDecision(t *testing.T) {
	t.Parallel()
	h := newBrowserHarness(t)
	token, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: token})
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"decision":"allow"`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestGatewayWiresStepGrantSource proves the fourth advertised trusted-context
// source is LIVE through the gateway: an `Authorization: StepGrant <token>`
// credential resolves a verified principal context and reaches the handler.
func TestGatewayWiresStepGrantSource(t *testing.T) {
	t.Parallel()
	h := newBrowserHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "StepGrant "+harnessStepGrantToken)
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"decision":"allow"`) {
		t.Fatalf("StepGrant source must resolve through the gateway: status=%d body=%s", rr.Code, rr.Body.String())
	}
	// An unknown StepGrant token is rejected (source live, credential bad).
	bad := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	bad.Header.Set("Content-Type", "application/json")
	bad.Header.Set("Authorization", "StepGrant unknown-grant-token-000000000000000000")
	badRR := httptest.NewRecorder()
	h.router.ServeHTTP(badRR, bad)
	if badRR.Code != http.StatusUnauthorized {
		t.Fatalf("unknown StepGrant token status=%d want 401", badRR.Code)
	}
}

// TestTrustProtectedPathsAreAllRegistered keeps the trustProtectedPath set and
// the registered runtime handlers in sync: every protected path must be a
// registered route (never a silent 404 that skips the trust guard), and a
// representative non-protected path must not be treated as protected.
func TestTrustProtectedPathsAreAllRegistered(t *testing.T) {
	t.Parallel()
	h := newBrowserHarness(t)
	for _, path := range []string{
		"/v1/authorization/decisions",
		"/v1/approvals/resolve",
		"/v1/step-grants",
		"/v1/tickets/verify",
		"/v1/audit/evidence",
	} {
		if !trustProtectedPath(path) {
			t.Errorf("%s must be trust-protected", path)
		}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.router.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound {
			t.Errorf("%s is trust-protected but not registered (404) — the guard would be skipped", path)
		}
	}
	for _, path := range []string{"/healthz", "/oauth2/token", "/v1/browser-sessions/me", "/v1/runtime/locate"} {
		if trustProtectedPath(path) {
			t.Errorf("%s must not be classified as a trust-protected runtime path", path)
		}
	}
}

func TestAuthorizationRejectsUnauthenticatedInvalidAndCrossEnterpriseActors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		sessions browserSessionResolver
		tickets  trust.AccessTicketVerifier
		setup    func(*http.Request)
		want     int
	}{
		{name: "unauthenticated", sessions: stubAuthorizationSessions{}, want: http.StatusUnauthorized},
		{name: "invalid session", sessions: stubAuthorizationSessions{err: browserauth.ErrInvalidSession}, setup: addAuthorizationSession, want: http.StatusUnauthorized},
		{name: "session unavailable", sessions: stubAuthorizationSessions{err: browserauth.ErrSessionUnavailable}, setup: addAuthorizationSession, want: http.StatusServiceUnavailable},
		{name: "cross enterprise session", sessions: stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-2", UserID: "user-1"}}, setup: addAuthorizationSession, want: http.StatusUnauthorized},
		{name: "missing ticket resolver", sessions: stubAuthorizationSessions{}, setup: addAuthorizationTicket, want: http.StatusUnauthorized},
		{name: "invalid or expired ticket", sessions: stubAuthorizationSessions{}, tickets: &stubTicketActors{err: trust.ErrCredentialRejected}, setup: addAuthorizationTicket, want: http.StatusUnauthorized},
		{name: "ticket unavailable", sessions: stubAuthorizationSessions{}, tickets: &stubTicketActors{err: trust.ErrSourceUnavailable}, setup: addAuthorizationTicket, want: http.StatusServiceUnavailable},
		{name: "cross enterprise ticket", sessions: stubAuthorizationSessions{}, tickets: &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-2", PrincipalRef: "user-1", TicketRef: "ct-9"}}, setup: addAuthorizationTicket, want: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := newAuthorizationTestRouter(t, test.sessions, test.tickets, authorizationPolicySource())
			req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
			req.Header.Set("Content-Type", "application/json")
			if test.setup != nil {
				test.setup(req)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, test.want, rr.Body.String())
			}
		})
	}
}

func TestAuthorizationRejectsDualCredentialsBeforeResolvingEither(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		sessions stubAuthorizationSessions
		tickets  *stubTicketActors
	}{
		{name: "valid session and valid ticket", sessions: validSessionStub(), tickets: &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-1", PrincipalRef: "user-1"}}},
		{name: "invalid session and unavailable ticket", sessions: stubAuthorizationSessions{err: browserauth.ErrInvalidSession}, tickets: &stubTicketActors{err: trust.ErrSourceUnavailable}},
		{name: "unavailable session and invalid ticket", sessions: stubAuthorizationSessions{err: browserauth.ErrSessionUnavailable}, tickets: &stubTicketActors{err: trust.ErrCredentialRejected}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sessionCalls := 0
			test.sessions.calls = &sessionCalls
			router := newAuthorizationTestRouter(t, test.sessions, test.tickets, authorizationPolicySource())
			req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
			req.Header.Set("Content-Type", "application/json")
			addAuthorizationSession(req)
			addAuthorizationTicket(req)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized || test.tickets.token != "" || sessionCalls != 0 {
				t.Fatalf("status=%d session calls=%d ticket token=%q body=%s", rr.Code, sessionCalls, test.tickets.token, rr.Body.String())
			}
		})
	}
}

func TestAuthorizationRejectsRepeatedAuthorizationHeader(t *testing.T) {
	t.Parallel()
	tickets := &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-1", PrincipalRef: "user-1"}}
	router := newAuthorizationTestRouter(t, stubAuthorizationSessions{}, tickets, authorizationPolicySource())
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "CaseTicket first")
	req.Header.Add("Authorization", "CaseTicket second")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || tickets.token != "" {
		t.Fatalf("status=%d token=%q", rr.Code, tickets.token)
	}
}

func TestAuthorizationRejectsRepeatedContentTypeHeader(t *testing.T) {
	t.Parallel()
	for _, values := range [][]string{{"application/json", "application/json"}, {"application/json", "text/plain"}} {
		router := newAuthorizationTestRouter(t, validSessionStub(), nil, authorizationPolicySource())
		req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
		for _, value := range values {
			req.Header.Add("Content-Type", value)
		}
		addAuthorizationSession(req)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("values=%#v status=%d body=%s", values, rr.Code, rr.Body.String())
		}
	}
}

func TestAuthorizationRejectsRepeatedSessionCookiesBeforeResolvers(t *testing.T) {
	t.Parallel()
	for _, withTicket := range []bool{false, true} {
		sessionCalls := 0
		tickets := &stubTicketActors{identity: trust.TicketIdentity{TenantRef: "ent-1", PrincipalRef: "user-1"}}
		sessions := validSessionStub()
		sessions.calls = &sessionCalls
		router := newAuthorizationTestRouter(t, sessions, tickets, authorizationPolicySource())
		req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session-one"})
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session-two"})
		if withTicket {
			addAuthorizationTicket(req)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized || sessionCalls != 0 || tickets.token != "" {
			t.Fatalf("ticket=%t status=%d sessionCalls=%d ticketToken=%q", withTicket, rr.Code, sessionCalls, tickets.token)
		}
	}
}

func TestAuthorizationStrictJSONAndContentType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		body        string
		want        int
	}{
		{name: "missing content type", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "wrong content type", contentType: "text/plain", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "null is not object", contentType: "application/json", body: `null`, want: http.StatusBadRequest},
		{name: "array not object", contentType: "application/json", body: `[]`, want: http.StatusBadRequest},
		{name: "forged enterprise identity", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.suggest","enterprise_id":"attacker"}`, want: http.StatusBadRequest},
		{name: "forged actor identity", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.suggest","actor_user_id":"victim"}`, want: http.StatusBadRequest},
		{name: "legacy org unit envelope", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.suggest","org_unit_id":"child"}`, want: http.StatusBadRequest},
		{name: "legacy org version envelope", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.suggest","org_version":12}`, want: http.StatusBadRequest},
		{name: "duplicate capability", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.suggest","capability":"knowledge.update"}`, want: http.StatusBadRequest},
		{name: "duplicate resource", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":"article-1","resource_id":"article-2","capability":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "missing request id", contentType: "application/json", body: `{"resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "unknown resource type", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"connector","resource_id":"article-1","capability":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "whitespace resource id", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":" ","capability":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "whitespace capability", contentType: "application/json", body: `{"request_id":"req-1","resource_type":"knowledge","resource_id":"article-1","capability":"knowledge.suggest "}`, want: http.StatusBadRequest},
		{name: "trailing json", contentType: "application/json", body: decisionBody("knowledge", "article-1", "knowledge.suggest") + `{}`, want: http.StatusBadRequest},
		{name: "oversized", contentType: "application/json", body: `{"unknown":"` + strings.Repeat("x", maxAuthorizationRequestBytes) + `"}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := newAuthorizationTestRouter(t, validSessionStub(), nil, authorizationPolicySource())
			req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(test.body))
			if test.contentType != "" {
				req.Header.Set("Content-Type", test.contentType)
			}
			addAuthorizationSession(req)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, test.want, rr.Body.String())
			}
		})
	}
}

type blockingSnapshotSource struct {
	canceled chan struct{}
}

func (s blockingSnapshotSource) LoadAccessSnapshot(ctx context.Context, _, _ string) (policy.SealedAccessSnapshot, error) {
	<-ctx.Done()
	close(s.canceled)
	return policy.SealedAccessSnapshot{}, ctx.Err()
}

func TestAuthorizationDecisionIsCoveredByRequestTimeout(t *testing.T) {
	t.Parallel()
	canceled := make(chan struct{})
	source := blockingSnapshotSource{canceled: canceled}
	audit := &recordingTrustAudit{}
	handler, err := newAuthorizationHandler(authorizationDependencies{EnterpriseID: "ent-1", Evaluator: policy.NewCapabilityEvaluator(source), Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	resolver := newTestTrustResolver(t, validSessionStub(), nil, source, audit)
	router := browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), 10*time.Millisecond)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(decisionBody("knowledge", "article-1", "knowledge.suggest")))
	req.Header.Set("Content-Type", "application/json")
	addAuthorizationSession(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	select {
	case <-canceled:
	default:
		t.Fatal("policy source did not observe request cancellation")
	}
}
