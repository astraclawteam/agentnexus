package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

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
	actor AuthorizationActor
	err   error
	token string
}

func (s *stubTicketActors) AuthenticateTicketActor(_ context.Context, token string) (AuthorizationActor, error) {
	s.token = token
	return s.actor, s.err
}

func TestAuthorizationDecisionUsesAuthenticatedSessionActor(t *testing.T) {
	t.Parallel()
	router := newAuthorizationTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, authorizationPolicySource())
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.update"}`))
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
	tickets := &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "user-1"}}
	router := newAuthorizationTestRouter(t, stubAuthorizationSessions{}, tickets, authorizationPolicySource())
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`))
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
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: token})
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"decision":"allow"`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAuthorizationRejectsUnauthenticatedInvalidAndCrossEnterpriseActors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		sessions authorizationSessionResolver
		tickets  TicketActorAuthenticator
		setup    func(*http.Request)
		want     int
	}{
		{name: "unauthenticated", sessions: stubAuthorizationSessions{}, want: http.StatusUnauthorized},
		{name: "invalid session", sessions: stubAuthorizationSessions{err: browserauth.ErrInvalidSession}, setup: addAuthorizationSession, want: http.StatusUnauthorized},
		{name: "session unavailable", sessions: stubAuthorizationSessions{err: browserauth.ErrSessionUnavailable}, setup: addAuthorizationSession, want: http.StatusServiceUnavailable},
		{name: "cross enterprise session", sessions: stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-2", UserID: "user-1"}}, setup: addAuthorizationSession, want: http.StatusUnauthorized},
		{name: "missing ticket resolver", sessions: stubAuthorizationSessions{}, setup: addAuthorizationTicket, want: http.StatusUnauthorized},
		{name: "invalid or expired ticket", sessions: stubAuthorizationSessions{}, tickets: &stubTicketActors{err: ErrInvalidTicketActor}, setup: addAuthorizationTicket, want: http.StatusUnauthorized},
		{name: "ticket unavailable", sessions: stubAuthorizationSessions{}, tickets: &stubTicketActors{err: ErrTicketActorUnavailable}, setup: addAuthorizationTicket, want: http.StatusServiceUnavailable},
		{name: "cross enterprise ticket", sessions: stubAuthorizationSessions{}, tickets: &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-2", UserID: "user-1"}}, setup: addAuthorizationTicket, want: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := newAuthorizationTestRouter(t, test.sessions, test.tickets, authorizationPolicySource())
			req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`))
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
		{name: "valid session and valid ticket", sessions: stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, tickets: &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "user-1"}}},
		{name: "invalid session and unavailable ticket", sessions: stubAuthorizationSessions{err: browserauth.ErrInvalidSession}, tickets: &stubTicketActors{err: ErrTicketActorUnavailable}},
		{name: "unavailable session and invalid ticket", sessions: stubAuthorizationSessions{err: browserauth.ErrSessionUnavailable}, tickets: &stubTicketActors{err: ErrInvalidTicketActor}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sessionCalls := 0
			test.sessions.calls = &sessionCalls
			router := newAuthorizationTestRouter(t, test.sessions, test.tickets, authorizationPolicySource())
			req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`))
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
	tickets := &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "user-1"}}
	router := newAuthorizationTestRouter(t, stubAuthorizationSessions{}, tickets, authorizationPolicySource())
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", "CaseTicket first")
	req.Header.Add("Authorization", "CaseTicket second")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || tickets.token != "" {
		t.Fatalf("status=%d token=%q", rr.Code, tickets.token)
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
		{name: "unknown field", contentType: "application/json", body: `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest","enterprise_id":"attacker"}`, want: http.StatusBadRequest},
		{name: "duplicate org version", contentType: "application/json", body: `{"org_unit_id":"child","org_version":11,"org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "duplicate resource", contentType: "application/json", body: `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","resource_id":"article-2","action":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "duplicate action", contentType: "application/json", body: `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest","action":"knowledge.update"}`, want: http.StatusBadRequest},
		{name: "whitespace org", contentType: "application/json", body: `{"org_unit_id":" child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "whitespace resource type", contentType: "application/json", body: `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge ","resource_id":"article-1","action":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "whitespace resource id", contentType: "application/json", body: `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":" ","action":"knowledge.suggest"}`, want: http.StatusBadRequest},
		{name: "whitespace action", contentType: "application/json", body: `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest "}`, want: http.StatusBadRequest},
		{name: "trailing json", contentType: "application/json", body: `{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}{}`, want: http.StatusBadRequest},
		{name: "oversized", contentType: "application/json", body: `{"unknown":"` + strings.Repeat("x", maxAuthorizationRequestBytes) + `"}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := newAuthorizationTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, authorizationPolicySource())
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

type blockingAtlasSource struct {
	canceled chan struct{}
}

func (s blockingAtlasSource) LoadAccessSnapshot(ctx context.Context, _, _ string) (policy.AtlasAccessSnapshot, error) {
	<-ctx.Done()
	close(s.canceled)
	return policy.AtlasAccessSnapshot{}, ctx.Err()
}

func TestAuthorizationDecisionIsCoveredByRequestTimeout(t *testing.T) {
	t.Parallel()
	canceled := make(chan struct{})
	deps := authorizationDependencies{EnterpriseID: "ent-1", Sessions: stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, Evaluator: policy.NewAgentAtlasEvaluator(blockingAtlasSource{canceled: canceled})}
	handler, err := newAuthorizationHandler(deps)
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	router := browserRequestDeadline(browserResponseHeaders(mux), 10*time.Millisecond)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/decisions", strings.NewReader(`{"org_unit_id":"child","org_version":12,"resource_type":"knowledge","resource_id":"article-1","action":"knowledge.suggest"}`))
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

func newAuthorizationTestRouter(t *testing.T, sessions authorizationSessionResolver, tickets TicketActorAuthenticator, source policy.AtlasPolicySource) http.Handler {
	t.Helper()
	handler, err := newAuthorizationHandler(authorizationDependencies{EnterpriseID: "ent-1", Sessions: sessions, TicketActors: tickets, Evaluator: policy.NewAgentAtlasEvaluator(source)})
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	return browserRequestDeadline(browserResponseHeaders(mux), time.Second)
}

func authorizationPolicySource() policy.AtlasPolicySource {
	source := policy.NewMemoryAtlasPolicySource()
	source.StoreSnapshot("ent-1", "user-1", policy.AtlasAccessSnapshot{EnterpriseID: "ent-1", OrgVersion: 12, OrgUnits: []policy.AtlasOrgUnit{{ID: "child", ParentID: "root"}, {ID: "root"}}, Memberships: []policy.AtlasMembership{{OrgUnitID: "root", Role: "edit"}, {OrgUnitID: "root", Role: "suggest"}}})
	return source
}

func addAuthorizationSession(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
}

func addAuthorizationTicket(req *http.Request) {
	req.Header.Set("Authorization", "CaseTicket opaque-ticket")
}
