package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/receipts"
)

func TestExternalReceiptRelayRoutes(t *testing.T) {
	relay := receipts.NewRelayWithStore(receipts.NewMemoryStore(), receipts.DelivererFunc(func(receipts.ReceiptRequest) error {
		return nil
	}))
	router := NewGatewayAPIRouter("gateway-api", "test", WithGatewayAPIReceiptRelay(relay))

	createBody := []byte(`{
		"id":"receipt_req_1",
		"enterprise_id":"ent_1",
		"case_ticket_id":"ticket_1",
		"step_grant_id":"grant_1",
		"target":{"id":"target_1","source":"external_source","channel":"claw","address":"claw:manager"}
	}`)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, httptest.NewRequest(http.MethodPost, "/api/receipts/requests", bytes.NewReader(createBody)))
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("create json error: %v", err)
	}
	if createResp.ID != "receipt_req_1" || createResp.Status != string(receipts.RequestStatusDelivered) {
		t.Fatalf("create response = %+v", createResp)
	}

	callbackBody := []byte(`{"enterprise_id":"ent_1","receipt_id":"receipt_1","result":"approved","evidence":"sha256:evidence"}`)
	callbackRec := httptest.NewRecorder()
	router.ServeHTTP(callbackRec, httptest.NewRequest(http.MethodPost, "/api/receipts/requests/receipt_req_1:callback", bytes.NewReader(callbackBody)))
	if callbackRec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, body = %s", callbackRec.Code, callbackRec.Body.String())
	}
	var callbackResp struct {
		RequestID string `json:"request_id"`
		Result    string `json:"result"`
	}
	if err := json.Unmarshal(callbackRec.Body.Bytes(), &callbackResp); err != nil {
		t.Fatalf("callback json error: %v", err)
	}
	if callbackResp.RequestID != "receipt_req_1" || callbackResp.Result != string(receipts.ReceiptApproved) {
		t.Fatalf("callback response = %+v", callbackResp)
	}
}
