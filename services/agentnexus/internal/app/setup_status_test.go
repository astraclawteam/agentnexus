package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestSetupStatusUnconfigured(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()

	NewGatewayAPIRouter("gateway-api", "0.1.0-test").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		State          string `json:"state"`
		EnterpriseID   string `json:"enterprise_id"`
		EnterpriseName string `json:"enterprise_name"`
		AdminUserID    string `json:"admin_user_id"`
		SecretProvider struct {
			Mode                string   `json:"mode"`
			Writable            bool     `json:"writable"`
			AcceptedRefPrefixes []string `json:"accepted_ref_prefixes"`
		} `json:"secret_provider"`
		Services            map[string]string `json:"services"`
		NextRequiredActions []string          `json:"next_required_actions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.State != "unconfigured" {
		t.Fatalf("state = %q, want unconfigured", resp.State)
	}
	if resp.EnterpriseID != "" || resp.EnterpriseName != "" || resp.AdminUserID != "" {
		t.Fatalf("enterprise context should be empty before setup: %+v", resp)
	}
	if resp.SecretProvider.Mode != "env" {
		t.Fatalf("secret provider mode = %q, want env", resp.SecretProvider.Mode)
	}
	if resp.SecretProvider.Writable {
		t.Fatal("env secret provider should not be writable through the API")
	}
	if !slices.Contains(resp.SecretProvider.AcceptedRefPrefixes, "secret://env/") {
		t.Fatalf("accepted prefixes = %#v, want secret://env/", resp.SecretProvider.AcceptedRefPrefixes)
	}
	if resp.Services["gateway_api"] != "ready" {
		t.Fatalf("gateway_api service state = %q, want ready", resp.Services["gateway_api"])
	}
	if !slices.Contains(resp.NextRequiredActions, "create_enterprise") {
		t.Fatalf("next actions = %#v, want create_enterprise", resp.NextRequiredActions)
	}
}

func TestSetupStatusConfiguredAfterOrgImport(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")

	setupRec := httptest.NewRecorder()
	router.ServeHTTP(setupRec, httptest.NewRequest(http.MethodPost, "/api/setup/enterprise", bytes.NewReader([]byte(`{
		"enterprise_id": "ent_dev",
		"enterprise_name": "Local Development Enterprise",
		"admin_user_id": "admin_dev",
		"environment_label": "private-dev"
	}`))))
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, body = %s", setupRec.Code, setupRec.Body.String())
	}

	confirmRec := httptest.NewRecorder()
	router.ServeHTTP(confirmRec, httptest.NewRequest(http.MethodPost, "/api/org/import/confirm", bytes.NewReader([]byte(`{
		"enterprise_id": "ent_dev",
		"provider": "oa_http",
		"snapshot": {
			"departments": [{"id":"dept_rd","name":"R&D"}],
			"employees": [{"id":"user_ada","display_name":"Ada","email":"ada@example.test","department_ids":["dept_rd"]}]
		}
	}`))))
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, body = %s", confirmRec.Code, confirmRec.Body.String())
	}

	statusRec := httptest.NewRecorder()
	router.ServeHTTP(statusRec, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", statusRec.Code, statusRec.Body.String())
	}

	var resp struct {
		State               string   `json:"state"`
		NextRequiredActions []string `json:"next_required_actions"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.State != "configured" {
		t.Fatalf("state = %q, want configured", resp.State)
	}
	if slices.Contains(resp.NextRequiredActions, "import_org") {
		t.Fatalf("next actions = %#v, should not require import_org after confirmed import", resp.NextRequiredActions)
	}
}
