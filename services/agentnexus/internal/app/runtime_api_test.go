package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuntimeAPIRejectsMissingEnvelope(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/runtime/locate", bytes.NewReader([]byte(`{"intent":"find docs"}`)))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if resp["error"] != "enterprise_id, actor_user_id, and request_id are required" {
		t.Fatalf("error = %q", resp["error"])
	}
}

func TestRuntimeAPIAuthorizedRoutes(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "test")

	locateReq := []byte(`{
		"enterprise_id": "ent_1",
		"actor_user_id": "dev_user",
		"request_id": "req_1",
		"trace_id": "trace_1",
		"intent": "find legal docs",
		"resource_types": ["connector_resource"]
	}`)
	locateRec := httptest.NewRecorder()
	router.ServeHTTP(locateRec, httptest.NewRequest(http.MethodPost, "/v1/runtime/locate", bytes.NewReader(locateReq)))
	if locateRec.Code != http.StatusOK {
		t.Fatalf("locate status = %d, body = %s", locateRec.Code, locateRec.Body.String())
	}
	var locateResp struct {
		CaseTicketID string `json:"case_ticket_id"`
		Resources    []any  `json:"resources"`
	}
	if err := json.Unmarshal(locateRec.Body.Bytes(), &locateResp); err != nil {
		t.Fatalf("locate json error = %v", err)
	}
	if locateResp.CaseTicketID == "" {
		t.Fatal("case_ticket_id is empty")
	}

	readReq := []byte(`{
		"enterprise_id": "ent_1",
		"actor_user_id": "dev_user",
		"request_id": "req_2",
		"case_ticket_id": "` + locateResp.CaseTicketID + `",
		"resource": {"type":"connector_resource","id":"resource_dev_preview","connector_instance_id":"conn_1","resource_name":"legal_contracts"},
		"fields": ["title"]
	}`)
	readRec := httptest.NewRecorder()
	router.ServeHTTP(readRec, httptest.NewRequest(http.MethodPost, "/v1/runtime/read", bytes.NewReader(readReq)))
	if readRec.Code != http.StatusOK {
		t.Fatalf("read status = %d, body = %s", readRec.Code, readRec.Body.String())
	}
	var readResp struct {
		Decision    string `json:"decision"`
		StepGrantID string `json:"step_grant_id"`
	}
	if err := json.Unmarshal(readRec.Body.Bytes(), &readResp); err != nil {
		t.Fatalf("read json error = %v", err)
	}
	if readResp.Decision != "allow" || readResp.StepGrantID == "" {
		t.Fatalf("read response = %+v", readResp)
	}

	actReq := []byte(`{
		"enterprise_id": "ent_1",
		"actor_user_id": "dev_user",
		"request_id": "req_3",
		"case_ticket_id": "` + locateResp.CaseTicketID + `",
		"resource": {"type":"connector_resource","id":"resource_dev_preview"},
		"action": "read"
	}`)
	actRec := httptest.NewRecorder()
	router.ServeHTTP(actRec, httptest.NewRequest(http.MethodPost, "/v1/runtime/act", bytes.NewReader(actReq)))
	if actRec.Code != http.StatusOK {
		t.Fatalf("act status = %d, body = %s", actRec.Code, actRec.Body.String())
	}

	ticketRec := httptest.NewRecorder()
	router.ServeHTTP(ticketRec, httptest.NewRequest(http.MethodGet, "/v1/runtime/tickets/"+locateResp.CaseTicketID, nil))
	if ticketRec.Code != http.StatusOK {
		t.Fatalf("ticket status = %d, body = %s", ticketRec.Code, ticketRec.Body.String())
	}
}
