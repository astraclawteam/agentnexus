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

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
)

type stubApprovalSource struct {
	loaded     LoadedApprovalSnapshot
	err        error
	enterprise string
	version    int64
	requester  string
}

func (s *stubApprovalSource) LoadApprovalSnapshot(_ context.Context, enterprise string, version int64, requester string) (LoadedApprovalSnapshot, error) {
	s.enterprise, s.version, s.requester = enterprise, version, requester
	return s.loaded, s.err
}

type capturingApprovalStore struct {
	req   approval.Request
	route approval.Route
	err   error
}

func (s *capturingApprovalStore) Record(_ context.Context, req approval.Request, route approval.Route) error {
	s.req, s.route = req, route
	return s.err
}

func TestApprovalResolveUsesAuthenticatedActorAndReturnsFrozenRoute(t *testing.T) {
	source := directApprovalSource(t, "ent-1", 12, "user-1")
	store := &capturingApprovalStore{}
	router := newApprovalTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, source, store)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(validApprovalBody()))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var route approval.Route
	if err := json.Unmarshal(rr.Body.Bytes(), &route); err != nil {
		t.Fatal(err)
	}
	if route.Mode != approval.ModeSingleConfirmation || route.AutoPublish || route.RiskReasons == nil || route.OrgPath == nil || store.req.RequesterUserID != "user-1" || source.requester != "user-1" {
		t.Fatalf("route=%+v request=%+v source=%+v", route, store.req, source)
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("headers=%v", rr.Header())
	}
}

func TestApprovalResolveUsesCaseTicketActor(t *testing.T) {
	tickets := &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "ticket-user"}}
	source := directApprovalSource(t, "ent-1", 12, "ticket-user")
	store := &capturingApprovalStore{}
	router := newApprovalTestRouter(t, stubAuthorizationSessions{}, tickets, source, store)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(validApprovalBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "CaseTicket opaque-ticket")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || store.req.RequesterUserID != "ticket-user" || tickets.token != "opaque-ticket" {
		t.Fatalf("status=%d requester=%q token=%q body=%s", rr.Code, store.req.RequesterUserID, tickets.token, rr.Body.String())
	}
}

func TestApprovalResolveRejectsStrictJSONAndRequesterOverride(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		status      int
	}{
		{name: "requester", body: strings.TrimSuffix(validApprovalBody(), "}") + `,"requester_user_id":"attacker"}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "duplicate", body: strings.TrimSuffix(validApprovalBody(), "}") + `,"action":"other"}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "null", body: strings.Replace(validApprovalBody(), `"resource_id":"workflow-1"`, `"resource_id":null`, 1), contentType: "application/json", status: http.StatusBadRequest},
		{name: "trailing", body: validApprovalBody() + `{}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "wrong content type", body: validApprovalBody(), contentType: "text/plain", status: http.StatusUnsupportedMediaType},
		{name: "noncanonical changed field", body: strings.Replace(validApprovalBody(), `"title"`, `" title"`, 1), contentType: "application/json", status: http.StatusBadRequest},
		{name: "oversized", body: `{"org_version":12,"org_unit_id":"team","resource_type":"workflow","resource_id":"` + strings.Repeat("x", maxApprovalRequestBytes) + `","action":"workflow.update"}`, contentType: "application/json", status: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newApprovalTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, directApprovalSource(t, "ent-1", 12, "user-1"), &capturingApprovalStore{})
			req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tt.status || strings.Contains(rr.Body.String(), "attacker") || strings.Contains(rr.Body.String(), "reviewer") {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestApprovalResolveFailsClosedWithoutLeakingCandidates(t *testing.T) {
	source := &stubApprovalSource{err: errors.New("candidate secret-user database unavailable")}
	router := newApprovalTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, source, &capturingApprovalStore{})
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(validApprovalBody()))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "secret-user") || strings.Contains(rr.Body.String(), "candidate") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestApprovalPathReceivesRequestTimeout(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		w.WriteHeader(http.StatusGatewayTimeout)
	})
	router := browserRequestDeadline(next, time.Millisecond)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", nil))
	if rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestBrowserHandlerRegistersApprovalAndExistingProtectedRoutes(t *testing.T) {
	handler := &browserAuthHandler{authorization: &authorizationHandler{}, approval: &approvalHandler{}}
	mux := http.NewServeMux()
	handler.register(mux)
	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/v1/browser-sessions/me"},
		{method: http.MethodGet, path: "/v1/authorization/decisions"},
		{method: http.MethodGet, path: "/v1/approvals/resolve"},
	} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s status=%d", tc.method, tc.path, rr.Code)
		}
	}
}

func newApprovalTestRouter(t *testing.T, sessions authorizationSessionResolver, tickets TicketActorAuthenticator, source ApprovalSnapshotSource, store ApprovalRouteStore) http.Handler {
	t.Helper()
	handler, err := newApprovalHandler(approvalDependencies{EnterpriseID: "ent-1", Sessions: sessions, TicketActors: tickets, Source: source, Store: store, Policy: approval.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.register(mux)
	return browserResponseHeaders(mux)
}

func directApprovalSource(t *testing.T, enterprise string, version int64, requester string) *stubApprovalSource {
	t.Helper()
	snapshot, err := approval.NewOrgSnapshot(enterprise, version, []approval.SnapshotUnit{{ID: "team"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	permissions := &fakeAppApprovalPermissions{allowedUser: requester}
	return &stubApprovalSource{loaded: LoadedApprovalSnapshot{Snapshot: snapshot, Permissions: permissions}}
}

type fakeAppApprovalPermissions struct{ allowedUser string }

func (f *fakeAppApprovalPermissions) Allows(_ context.Context, req approval.PermissionRequest) (bool, error) {
	return req.UserID == f.allowedUser && req.Permission == approval.PermissionPublishLowRisk, nil
}

func validApprovalBody() string {
	return `{"org_version":12,"org_unit_id":"team","resource_type":"workflow","resource_id":"workflow-1","action":"workflow.update","changed_fields":["title"],"impacted_org_unit_ids":["team"],"impacted_user_count":1,"published_behavior_change":false,"external_side_effect":false,"requested_risk":"low"}`
}
