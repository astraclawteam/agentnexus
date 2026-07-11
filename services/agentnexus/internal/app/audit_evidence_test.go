package app

import (
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

func TestAuditEvidenceAcceptsAuthorizedDreamPolicyActionAndPersists(t *testing.T) {
	sink := &recordingAuditEvidenceSink{}
	h, err := newAuditEvidenceHandler("ent-1", &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u-1"}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(`{"ticket_id":"ticket-1","enterprise_id":"ent-1","action":"dream_policy_create_authorized","trace_id":"trace-1","details":{"phase":"authorized_create_attempt"}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.append(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["audit_ref_id"] != "audit-1" || sink.input.Action != AuditActionDreamPolicyCreateAuthorized || sink.input.ActorUserID != "u-1" {
		t.Fatalf("response=%v input=%+v", response, sink.input)
	}
}

func TestAuditActionValidationKeepsLegacyAndRejectsUnknown(t *testing.T) {
	if !ValidAuditEvidenceAction(AuditActionDreamPolicyCreated) {
		t.Fatal("legacy dream_policy_created rejected")
	}
	if !ValidAuditEvidenceAction(AuditActionDreamPolicyCreateAuthorized) {
		t.Fatal("authorized action rejected")
	}
	if ValidAuditEvidenceAction("dream_policy_magic") {
		t.Fatal("unknown action accepted")
	}
}

func TestAuditEvidenceRejectsDetailsBeyondPublicBound(t *testing.T) {
	sink := &recordingAuditEvidenceSink{}
	h, _ := newAuditEvidenceHandler("ent-1", &stubTicketActors{actor: AuthorizationActor{EnterpriseID: "ent-1", UserID: "u-1"}}, sink)
	details := map[string]any{}
	for i := 0; i < 101; i++ {
		details[string(rune('a'+i))] = i
	}
	body, _ := json.Marshal(map[string]any{"ticket_id": "ticket-1", "enterprise_id": "ent-1", "action": "dream_policy_create_authorized", "details": details})
	rr := httptest.NewRecorder()
	h.append(rr, httptest.NewRequest(http.MethodPost, "/v1/audit/evidence", strings.NewReader(string(body))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
}
