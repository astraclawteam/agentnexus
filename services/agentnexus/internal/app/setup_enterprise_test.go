package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetupEnterpriseCreatesContext(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")
	req := httptest.NewRequest(http.MethodPost, "/api/setup/enterprise", bytes.NewReader([]byte(`{
		"enterprise_id": "ent_dev",
		"enterprise_name": "Local Development Enterprise",
		"admin_user_id": "admin_dev",
		"environment_label": "private-dev"
	}`)))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		EnterpriseID   string `json:"enterprise_id"`
		EnterpriseName string `json:"enterprise_name"`
		State          string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.EnterpriseID != "ent_dev" || resp.EnterpriseName != "Local Development Enterprise" {
		t.Fatalf("enterprise response = %+v", resp)
	}
	if resp.State != "configured_without_org" {
		t.Fatalf("state = %q, want configured_without_org", resp.State)
	}
}

func TestConsoleOverviewLiveEmptyEnterpriseHasNoFixtureData(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")
	createReq := httptest.NewRequest(http.MethodPost, "/api/setup/enterprise", strings.NewReader(`{
		"enterprise_id": "ent_dev",
		"enterprise_name": "Local Development Enterprise",
		"admin_user_id": "admin_dev",
		"environment_label": "private-dev"
	}`))
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/console/overview?enterprise_id=ent_dev", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "绀轰緥鍛樺伐") || strings.Contains(rec.Body.String(), "Example employee") {
		t.Fatalf("live overview returned fixture employee data: %s", rec.Body.String())
	}

	var overview ConsoleOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &overview); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if overview.Source.Kind != "api_live" {
		t.Fatalf("source kind = %q, want api_live", overview.Source.Kind)
	}
	if overview.State != "configured_without_org" {
		t.Fatalf("state = %q, want configured_without_org", overview.State)
	}
	if got := overview.Pulse.Stats[0][1]; got != "0" {
		t.Fatalf("employee count = %q, want 0", got)
	}
	if got := overview.Pulse.Stats[1][1]; got != "0" {
		t.Fatalf("department count = %q, want 0", got)
	}
}
