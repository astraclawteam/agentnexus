package e2e_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/receipts"
)

func TestExternalReceiptRelay(t *testing.T) {
	relay := receipts.NewRelayWithStore(receipts.NewMemoryStore(), receipts.DelivererFunc(func(receipts.ReceiptRequest) error {
		return nil
	}))
	router := app.NewGatewayAPIRouter("gateway-api", "test", app.WithGatewayAPIReceiptRelay(relay))

	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, httptest.NewRequest(http.MethodPost, "/api/receipts/requests", bytes.NewReader([]byte(`{
		"id":"receipt_req_1",
		"enterprise_id":"ent_1",
		"case_ticket_id":"ticket_1",
		"step_grant_id":"grant_1",
		"target":{"id":"target_1","source":"external_source","channel":"im","address":"im:manager"}
	}`))))
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("create json error: %v", err)
	}
	if created.Status != string(receipts.RequestStatusDelivered) {
		t.Fatalf("created status = %q, want delivered", created.Status)
	}

	callbackRec := httptest.NewRecorder()
	router.ServeHTTP(callbackRec, httptest.NewRequest(http.MethodPost, "/api/receipts/requests/receipt_req_1:callback", bytes.NewReader([]byte(`{
		"enterprise_id":"ent_1",
		"receipt_id":"receipt_1",
		"result":"approved",
		"evidence":"sha256:evidence"
	}`))))
	if callbackRec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, body = %s", callbackRec.Code, callbackRec.Body.String())
	}
	var callback struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(callbackRec.Body.Bytes(), &callback); err != nil {
		t.Fatalf("callback json error: %v", err)
	}
	if callback.Result != string(receipts.ReceiptApproved) {
		t.Fatalf("callback result = %q, want approved", callback.Result)
	}
}
