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
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

type fakeGrantSessions struct {
	session browserauth.BrowserSession
	err     error
}

func (f fakeGrantSessions) GetSession(context.Context, string) (browserauth.BrowserSession, error) {
	return f.session, f.err
}

type fakeGrantService struct {
	actor  tickets.Actor
	create tickets.CreateStepGrantInput
	verify tickets.VerifyStepGrantInput
	err    error
}

func (f *fakeGrantService) AuthorizeAndCreateGrant(_ context.Context, actor tickets.Actor, input tickets.CreateStepGrantInput) (tickets.StepGrant, error) {
	f.actor, f.create = actor, input
	return tickets.StepGrant{ID: "grant_1", Token: "opaque", EnterpriseID: actor.EnterpriseID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scopes: []string{"dream:evidence:read"}, ExpiresAt: time.Date(2026, 7, 11, 10, 5, 0, 0, time.UTC)}, f.err
}
func (f *fakeGrantService) VerifyGrant(_ context.Context, input tickets.VerifyStepGrantInput) (tickets.StepGrant, error) {
	f.verify = input
	return tickets.StepGrant{ID: "grant_1", EnterpriseID: input.EnterpriseID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scopes: []string{input.Scope}}, f.err
}

func TestGrantRoutesUseAuthenticatedActorAndNoStore(t *testing.T) {
	token := "session-token"
	auth := &authorizationHandler{enterpriseID: "ent_1", sessions: fakeGrantSessions{session: browserauth.BrowserSession{EnterpriseID: "ent_1", UserID: "user_1"}}, ticketActors: RejectTicketActorAuthenticator{}}
	service := &fakeGrantService{}
	handler, err := newGrantHandler(auth, service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.register(mux)

	body := `{"case_ticket_id":"ticket_1","org_unit_id":"research","org_version":7,"resource_type":"dream_evidence","resource_id":"ev-1","action":"read","ttl_seconds":600}`
	req := httptest.NewRequest(http.MethodPost, "/v1/step-grants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: token})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.actor.EnterpriseID != "ent_1" || service.actor.UserID != "user_1" {
		t.Fatalf("actor=%+v", service.actor)
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
	mux.ServeHTTP(verifyResponse, verifyReq)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyResponse.Code, verifyResponse.Body.String())
	}
	if service.verify.EnterpriseID != "ent_1" || service.verify.ActorUserID != "user_1" {
		t.Fatalf("verify trusted body enterprise: %+v", service.verify)
	}
}

func TestGrantRoutesFailClosedWithConsistentErrors(t *testing.T) {
	auth := &authorizationHandler{enterpriseID: "ent_1", sessions: fakeGrantSessions{err: browserauth.ErrInvalidSession}, ticketActors: RejectTicketActorAuthenticator{}}
	service := &fakeGrantService{err: tickets.ErrGrantUnavailable}
	handler, err := newGrantHandler(auth, service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/step-grants", strings.NewReader(`{"unknown":true}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status=%d", response.Code)
	}
	if !errors.Is(service.err, tickets.ErrGrantUnavailable) {
		t.Fatal(service.err)
	}
}

func TestGrantRouteRejectsOversizedJSONBeforeService(t *testing.T) {
	auth := &authorizationHandler{enterpriseID: "ent_1", sessions: fakeGrantSessions{session: browserauth.BrowserSession{EnterpriseID: "ent_1", UserID: "user_1"}}, ticketActors: RejectTicketActorAuthenticator{}}
	service := &fakeGrantService{}
	handler, err := newGrantHandler(auth, service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.register(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/step-grants", strings.NewReader(`{"padding":"`+strings.Repeat("x", maxGrantRequestBytes)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session"})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.actor.UserID != "" {
		t.Fatalf("service was called: %+v", service.actor)
	}
}
