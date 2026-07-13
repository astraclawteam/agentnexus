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
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

type fakeGrantService struct {
	actor       tickets.Actor
	verifyActor tickets.Actor
	create      tickets.CreateStepGrantInput
	verify      tickets.VerifyStepGrantInput
	err         error
}

func (f *fakeGrantService) AuthorizeAndCreateGrant(_ context.Context, actor tickets.Actor, input tickets.CreateStepGrantInput) (tickets.StepGrant, error) {
	f.actor, f.create = actor, input
	return tickets.StepGrant{ID: "grant_1", Token: "opaque", EnterpriseID: actor.EnterpriseID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scopes: []string{"dream:evidence:read"}, ExpiresAt: time.Date(2026, 7, 11, 10, 5, 0, 0, time.UTC)}, f.err
}
func (f *fakeGrantService) VerifyGrant(_ context.Context, actor tickets.Actor, input tickets.VerifyStepGrantInput) (tickets.StepGrant, error) {
	f.verifyActor, f.verify = actor, input
	return tickets.StepGrant{ID: "grant_1", EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scopes: []string{input.Scope}}, f.err
}

// newGrantTestRouter wires the grant handler behind the trust middleware
// exactly like production: identity is resolved once at ingress.
func newGrantTestRouter(t *testing.T, sessions browserSessionResolver, service grantService) http.Handler {
	t.Helper()
	audit := &recordingTrustAudit{}
	handler, err := newGrantHandler("ent_1", service, audit)
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	source := policy.NewMemorySnapshotSource()
	source.StoreSnapshot("ent_1", "user_1", policy.SealedAccessSnapshot{TenantRef: "ent_1", OrgVersion: 7, OrgUnits: []policy.SealedOrgUnit{{ID: "research"}}, Memberships: []policy.SealedMembership{{OrgUnitID: "research", Role: "approve_high_risk"}}})
	resolver := newGrantTestResolver(t, sessions, source, audit)
	return browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second)
}

func newGrantTestResolver(t *testing.T, sessions browserSessionResolver, source policy.SnapshotSource, audit BrowserAuditSink) *trust.Resolver {
	t.Helper()
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef:    "ent_1",
		Sessions:     browserSessionTrustVerifier{sessions: sessions},
		OrgSnapshots: sealedOrgVersionResolver{source: source},
		Audit:        browserTrustAuditSink{sink: audit},
		Protected: func(r *http.Request) bool {
			return trustProtectedPath(r.URL.Path)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestGrantRoutesUseAuthenticatedActorAndNoStore(t *testing.T) {
	token := "session-token"
	service := &fakeGrantService{}
	router := newGrantTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent_1", UserID: "user_1", IdleExpiresAt: time.Now().Add(time.Hour)}}, service)

	body := `{"case_ticket_id":"ticket_1","resource_type":"dream_evidence","resource_id":"ev-1","action":"read","ttl_seconds":600}`
	req := httptest.NewRequest(http.MethodPost, "/v1/step-grants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: token})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.actor.EnterpriseID != "ent_1" || service.actor.UserID != "user_1" || service.actor.OrgVersion != 7 {
		t.Fatalf("actor=%+v: identity and sealed org version must be credential-derived", service.actor)
	}
	if service.create.TTL != 10*time.Minute {
		t.Fatalf("ttl=%s", service.create.TTL)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache=%q", response.Header().Get("Cache-Control"))
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["token"] != "opaque" {
		t.Fatalf("payload=%v", payload)
	}

	verifyBody := `{"token":"opaque","resource_type":"dream_evidence","resource_id":"ev-1","action":"read","scope":"dream:evidence:read"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/v1/tickets/verify", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: token})
	verifyResponse := httptest.NewRecorder()
	router.ServeHTTP(verifyResponse, verifyReq)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyResponse.Code, verifyResponse.Body.String())
	}
	if service.verifyActor.EnterpriseID != "ent_1" || service.verifyActor.UserID != "user_1" {
		t.Fatalf("verify actor must be credential-derived: %+v", service.verifyActor)
	}
}

func TestGrantRoutesFailClosedWithConsistentErrors(t *testing.T) {
	service := &fakeGrantService{err: tickets.ErrGrantUnavailable}
	router := newGrantTestRouter(t, stubAuthorizationSessions{err: browserauth.ErrInvalidSession}, service)
	req := httptest.NewRequest(http.MethodPost, "/v1/step-grants", strings.NewReader(`{"unknown":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d", response.Code)
	}
	if !errors.Is(service.err, tickets.ErrGrantUnavailable) {
		t.Fatal(service.err)
	}
}

func TestGrantRouteRejectsOversizedJSONBeforeService(t *testing.T) {
	service := &fakeGrantService{}
	router := newGrantTestRouter(t, stubAuthorizationSessions{session: browserauth.BrowserSession{EnterpriseID: "ent_1", UserID: "user_1", IdleExpiresAt: time.Now().Add(time.Hour)}}, service)
	req := httptest.NewRequest(http.MethodPost, "/v1/step-grants", strings.NewReader(`{"padding":"`+strings.Repeat("x", maxGrantRequestBytes)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.actor.UserID != "" {
		t.Fatalf("service was called: %+v", service.actor)
	}
}
