package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
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
	req       approval.Request
	route     approval.Route
	err       error
	replay    *approval.Route
	lookupErr error
}

func (s *capturingApprovalStore) LookupResolution(context.Context, string, string, string) (approval.Route, bool, error) {
	if s.lookupErr != nil {
		return approval.Route{}, false, s.lookupErr
	}
	if s.replay != nil {
		return *s.replay, true, nil
	}
	return approval.Route{}, false, nil
}

func (s *capturingApprovalStore) RecordResolution(_ context.Context, req approval.Request, route approval.Route) (approval.Route, error) {
	s.req, s.route = req, route
	return route, s.err
}

func TestApprovalResolveUsesAuthenticatedActorAndReturnsFrozenRoute(t *testing.T) {
	source := directApprovalSource(t, "ent-1", 12, "user-1")
	store := &capturingApprovalStore{}
	router := newApprovalTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, source, store)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(validApprovalBody()))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	addApprovalHeaders(req)
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
	addApprovalHeaders(req)
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
		{name: "null", body: strings.Replace(validApprovalBody(), `"resource_id":"article-1"`, `"resource_id":null`, 1), contentType: "application/json", status: http.StatusBadRequest},
		{name: "trailing", body: validApprovalBody() + `{}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "wrong content type", body: validApprovalBody(), contentType: "text/plain", status: http.StatusUnsupportedMediaType},
		{name: "noncanonical changed field", body: strings.Replace(validApprovalBody(), `"title"`, `" title"`, 1), contentType: "application/json", status: http.StatusBadRequest},
		{name: "empty requested risk", body: strings.Replace(validApprovalBody(), `"requested_risk":"low"`, `"requested_risk":""`, 1), contentType: "application/json", status: http.StatusBadRequest},
		{name: "oversized", body: `{"org_version":12,"org_unit_id":"team","resource_type":"workflow","resource_id":"` + strings.Repeat("x", maxApprovalRequestBytes) + `","action":"workflow.update"}`, contentType: "application/json", status: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newApprovalTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, directApprovalSource(t, "ent-1", 12, "user-1"), &capturingApprovalStore{})
			req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			addApprovalHeaders(req)
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
	addApprovalHeaders(req)
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "secret-user") || strings.Contains(rr.Body.String(), "candidate") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestApprovalResolveRequiresCanonicalSingleSecurityHeaders(t *testing.T) {
	tests := []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", "second-123456789012") },
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "short") },
		func(r *http.Request) { r.Header.Del("X-Approval-Facts-Attestation") },
		func(r *http.Request) { r.Header.Add("X-Approval-Facts-Attestation", "second") },
	}
	for i, mutate := range tests {
		router := newApprovalTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, directApprovalSource(t, "ent-1", 12, "user-1"), &capturingApprovalStore{})
		req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(validApprovalBody()))
		req.Header.Set("Content-Type", "application/json")
		addApprovalHeaders(req)
		mutate(req)
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("case=%d status=%d", i, rr.Code)
		}
	}
}

func TestApprovalResolveMissingFactsRejectsAndUnknownOrUnverifiedFactsForceHigh(t *testing.T) {
	missing := strings.Replace(validApprovalBody(), `,"external_side_effect":false`, "", 1)
	router := newApprovalTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, directApprovalSource(t, "ent-1", 12, "user-1"), &capturingApprovalStore{})
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(missing))
	req.Header.Set("Content-Type", "application/json")
	addApprovalHeaders(req)
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing status=%d", rr.Code)
	}

	for _, tc := range []struct {
		body     string
		verifier ChangeFactsVerifier
		reason   approval.RiskReason
	}{
		{body: strings.Replace(validApprovalBody(), `"title"`, `"future_field"`, 1), verifier: trustingFactsVerifier{}, reason: approval.RiskReasonUnknownChangedField},
		{body: validApprovalBody(), verifier: RejectChangeFactsVerifier{}, reason: approval.RiskReasonUnverifiedChangeFacts},
	} {
		store := &capturingApprovalStore{}
		router = newApprovalTestRouterWithVerifier(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, directApprovalSource(t, "ent-1", 12, "user-1"), store, tc.verifier)
		req = httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		addApprovalHeaders(req)
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || store.route.RiskLevel != approval.RiskHigh || !slices.Contains(store.route.RiskReasons, tc.reason) {
			t.Fatalf("status=%d route=%+v", rr.Code, store.route)
		}
	}
}

type failingFactsVerifier struct{}

func (failingFactsVerifier) VerifyChangeFacts(context.Context, ChangeFactsVerificationInput) (approval.VerifiedChangeFacts, error) {
	return approval.VerifiedChangeFacts{}, errors.New("verifier must not run on replay")
}

func TestApprovalResolveReplaysBeforeExpiredVerificationOrUnavailableSource(t *testing.T) {
	route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: "user-1", OrgPath: []string{"team"}, PolicyVersion: 3}
	store := &capturingApprovalStore{replay: &route}
	source := &stubApprovalSource{err: errors.New("source unavailable after org version advanced")}
	router := newApprovalTestRouterWithVerifier(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, source, store, failingFactsVerifier{})
	body := strings.Replace(validApprovalBody(), `"facts_expires_at":"2026-07-11T00:05:00Z"`, `"facts_expires_at":"2020-01-01T00:05:00Z"`, 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addApprovalHeaders(req)
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || store.req.RequesterUserID != "" || source.requester != "" {
		t.Fatalf("status=%d store=%+v source=%+v body=%s", rr.Code, store, source, rr.Body.String())
	}

	store = &capturingApprovalStore{lookupErr: ErrApprovalIdempotencyConflict}
	router = newApprovalTestRouterWithVerifier(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent-1", UserID: "user-1"}}, nil, source, store, failingFactsVerifier{})
	req = httptest.NewRequest(http.MethodPost, "/v1/approvals/resolve", strings.NewReader(validApprovalBody()))
	req.Header.Set("Content-Type", "application/json")
	addApprovalHeaders(req)
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "opaque-session"})
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d", rr.Code)
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
	return newApprovalTestRouterWithVerifier(t, sessions, tickets, source, store, trustingFactsVerifier{})
}

func newApprovalTestRouterWithVerifier(t *testing.T, sessions authorizationSessionResolver, tickets TicketActorAuthenticator, source ApprovalSnapshotSource, store ApprovalRouteStore, verifier ChangeFactsVerifier) http.Handler {
	t.Helper()
	handler, err := newApprovalHandler(approvalDependencies{EnterpriseID: "ent-1", Sessions: sessions, TicketActors: tickets, Source: source, Store: store, FactsVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.register(mux)
	return browserResponseHeaders(mux)
}

func directApprovalSource(t *testing.T, enterprise string, version int64, requester string) *stubApprovalSource {
	t.Helper()
	snapshot, err := approval.NewOrgSnapshot(enterprise, version, []approval.SnapshotUnit{{ID: "team"}}, []approval.SnapshotMembership{{UserID: requester, OrgUnitID: "team", Role: string(approval.PermissionPublishLowRisk)}}, []approval.SnapshotUser{{ID: requester, DisplayName: "Requester"}})
	if err != nil {
		t.Fatal(err)
	}
	return &stubApprovalSource{loaded: LoadedApprovalSnapshot{Snapshot: snapshot, Policy: approval.DefaultPolicy(), PolicyVersion: 1}}
}

func validApprovalBody() string {
	return `{"org_version":12,"org_unit_id":"team","resource_type":"knowledge","resource_id":"article-1","action":"knowledge.publish_low_risk","changed_fields":["title"],"impacted_org_unit_ids":["team"],"impacted_user_count":1,"published_behavior_change":false,"external_side_effect":false,"requested_risk":"low","facts_issued_at":"2026-07-11T00:00:00Z","facts_expires_at":"2026-07-11T00:05:00Z","facts_nonce":"nonce-123456789012"}`
}

type trustingFactsVerifier struct{}

func (trustingFactsVerifier) VerifyChangeFacts(_ context.Context, input ChangeFactsVerificationInput) (approval.VerifiedChangeFacts, error) {
	return approval.NewVerifiedChangeFacts(approval.VerifiedChangeFactsInput{ChangedFields: input.ChangedFields, ImpactedOrgUnitIDs: input.ImpactedOrgUnitIDs, ImpactedUserCount: input.ImpactedUserCount, PublishedBehaviorChange: input.PublishedBehaviorChange, ExternalSideEffect: input.ExternalSideEffect, Digest: strings.Repeat("a", 64)}), nil
}

func addApprovalHeaders(req *http.Request) {
	req.Header.Set("Idempotency-Key", "idem-1234567890123456")
	req.Header.Set("X-Approval-Facts-Attestation", "test-attestation")
}
