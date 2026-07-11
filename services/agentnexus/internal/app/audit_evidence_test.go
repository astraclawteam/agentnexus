package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recordingAuditEvidenceSink struct{ input AuditEvidenceInput }

func (s *recordingAuditEvidenceSink) AppendAuditEvidence(_ context.Context, input AuditEvidenceInput) (string, error) {
	s.input = input
	return "audit-1", nil
}

type stubServiceAuthenticator struct{ allow bool }

func (s stubServiceAuthenticator) AuthenticateService(string, string) bool { return s.allow }

func TestAuditEvidenceRecordsDreamPolicyCreateRequest(t *testing.T) {
	sink := &recordingAuditEvidenceSink{}
	h, err := newAuditEvidenceHandler("ent-1", &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u-1", CaseTicketID: "case-1"}}, sink, stubServiceAuthenticator{allow: true})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(`{"ticket_id":"opaque-ticket","enterprise_id":"ent-1","action":"dream_policy_create_requested","resource_type":"dream_policy","resource_id":"pol-1","trace_id":"trace-1","details":{"phase":"create_requested"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("agentatlas", "secret")
	rr := httptest.NewRecorder()
	h.append(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["audit_ref_id"] != "audit-1" || sink.input.Action != AuditActionDreamPolicyCreateRequested || sink.input.ActorUserID != "u-1" || sink.input.CaseTicketID != "case-1" || sink.input.ResourceType != "dream_policy" || sink.input.ResourceID != "pol-1" {
		t.Fatalf("response=%v input=%+v", response, sink.input)
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
	h, _ := newAuditEvidenceHandler("ent-1", &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u-1", CaseTicketID: "case-1"}}, sink, stubServiceAuthenticator{allow: true})
	details := map[string]any{}
	for i := 0; i < 101; i++ {
		details[string(rune('a'+i))] = i
	}
	body, _ := json.Marshal(map[string]any{"ticket_id": "ticket-1", "enterprise_id": "ent-1", "action": "dream_policy_create_requested", "resource_type": "dream_policy", "resource_id": "pol-1", "details": details})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(string(body)))
	req.SetBasicAuth("agentatlas", "secret")
	h.append(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestAuditEvidenceRequiresTrustedServiceAndMapsTicketFailures(t *testing.T) {
	body := `{"ticket_id":"opaque","enterprise_id":"ent-1","action":"dream_policy_create_requested","resource_type":"dream_policy","resource_id":"pol-1"}`
	for _, tc := range []struct {
		name    string
		auth    ServiceAuthenticator
		tickets *stubTicketActors
		basic   bool
		want    int
	}{
		{"missing basic", stubServiceAuthenticator{allow: true}, &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u", CaseTicketID: "case"}}, false, 401},
		{"bad service", stubServiceAuthenticator{}, &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u", CaseTicketID: "case"}}, true, 401},
		{"ticket unavailable", stubServiceAuthenticator{allow: true}, &stubTicketActors{err: ErrTicketActorUnavailable}, true, 503},
		{"invalid ticket", stubServiceAuthenticator{allow: true}, &stubTicketActors{err: ErrInvalidTicketActor}, true, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newAuditEvidenceHandler("ent-1", tc.tickets, &recordingAuditEvidenceSink{}, tc.auth)
			req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(body))
			if tc.basic {
				req.SetBasicAuth("agentatlas", "secret")
			}
			rr := httptest.NewRecorder()
			h.append(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status=%d", rr.Code)
			}
		})
	}
}

func TestDreamPolicyCreateRequestedRequiresBoundResource(t *testing.T) {
	h, _ := newAuditEvidenceHandler("ent-1", &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u", CaseTicketID: "case"}}, &recordingAuditEvidenceSink{}, stubServiceAuthenticator{allow: true})
	for _, body := range []string{
		`{"ticket_id":"opaque","enterprise_id":"ent-1","action":"dream_policy_create_requested","resource_type":"workflow","resource_id":"pol-1"}`,
		`{"ticket_id":"opaque","enterprise_id":"ent-1","action":"dream_policy_create_requested","resource_type":"dream_policy","resource_id":""}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(body))
		req.SetBasicAuth("agentatlas", "secret")
		rr := httptest.NewRecorder()
		h.append(rr, req)
		if rr.Code != 400 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
}

func TestAuditEvidenceBoundsUseUnicodeCodePoints(t *testing.T) {
	h, _ := newAuditEvidenceHandler("ent-1", &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u", CaseTicketID: "case"}}, &recordingAuditEvidenceSink{}, stubServiceAuthenticator{allow: true})
	for _, tc := range []struct {
		id   string
		want int
	}{{strings.Repeat("界", 128), 201}, {strings.Repeat("界", 129), 400}} {
		body, _ := json.Marshal(map[string]any{"ticket_id": "opaque", "enterprise_id": "ent-1", "action": "dream_policy_create_requested", "resource_type": "dream_policy", "resource_id": tc.id, "details": map[string]any{"note": strings.Repeat("界", 1024)}})
		req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", bytes.NewReader(body))
		req.SetBasicAuth("agentatlas", "secret")
		rr := httptest.NewRecorder()
		h.append(rr, req)
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
