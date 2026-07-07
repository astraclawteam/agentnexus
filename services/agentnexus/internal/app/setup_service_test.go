package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupStatusIncludesChecklistSessionAndEnvironment(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		State       string `json:"state"`
		Session     struct {
			Mode        string `json:"mode"`
			ActorUserID string `json:"actor_user_id"`
			Secure      bool   `json:"secure"`
		} `json:"session"`
		Environment struct {
			OverallStatus string `json:"overall_status"`
			Checks        []struct {
				Key     string `json:"key"`
				Status  string `json:"status"`
				Message string `json:"message"`
				Fix     string `json:"fix,omitempty"`
			} `json:"checks"`
		} `json:"environment"`
		Checklist []struct {
			Key      string `json:"key"`
			Status   string `json:"status"`
			Required bool   `json:"required"`
			Title    string `json:"title"`
			Action   string `json:"action"`
		} `json:"checklist"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Session.Mode != "dev_admin" {
		t.Fatalf("session mode = %q, want dev_admin", resp.Session.Mode)
	}
	if resp.Session.ActorUserID == "" {
		t.Fatal("actor_user_id should be explicit in first-run status")
	}
	if resp.Session.Secure {
		t.Fatal("dev_admin session must not be labeled as secure production auth")
	}
	if resp.Environment.OverallStatus == "" {
		t.Fatal("environment overall_status should be present")
	}
	if len(resp.Environment.Checks) == 0 {
		t.Fatal("environment checks should be present")
	}
	if !checklistContains(resp.Checklist, "enterprise_tenant", "required") {
		t.Fatalf("checklist = %#v, want enterprise_tenant required", resp.Checklist)
	}
	if !checklistContains(resp.Checklist, "organization_import", "blocked") {
		t.Fatalf("checklist = %#v, want organization_import blocked before tenant setup", resp.Checklist)
	}
}

func TestSetupEnvironmentRouteReturnsDiagnostics(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")
	req := httptest.NewRequest(http.MethodGet, "/api/setup/environment", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		OverallStatus string `json:"overall_status"`
		Checks        []struct {
			Key     string `json:"key"`
			Status  string `json:"status"`
			Message string `json:"message"`
			Fix     string `json:"fix,omitempty"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OverallStatus == "" {
		t.Fatal("overall_status should be present")
	}
	for _, key := range []string{"gateway_api", "gateway_agent", "postgres", "nats", "secret_provider", "compose_profile"} {
		if !environmentContains(resp.Checks, key) {
			t.Fatalf("checks = %#v, want %s", resp.Checks, key)
		}
	}
}

func TestConsoleSetupChecklistRouteUsesSetupService(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")
	req := httptest.NewRequest(http.MethodGet, "/api/console/setup-checklist?enterprise_id=ent_dev", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		EnterpriseID string `json:"enterprise_id"`
		Items        []struct {
			Key    string `json:"key"`
			Status string `json:"status"`
			Action string `json:"action"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.EnterpriseID != "ent_dev" {
		t.Fatalf("enterprise_id = %q, want ent_dev", resp.EnterpriseID)
	}
	if len(resp.Items) == 0 {
		t.Fatal("checklist items should be present")
	}
	if !checklistContainsResponse(resp.Items, "enterprise_tenant", "required") {
		t.Fatalf("items = %#v, want enterprise_tenant required", resp.Items)
	}
}

func checklistContains(items []struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Required bool   `json:"required"`
	Title    string `json:"title"`
	Action   string `json:"action"`
}, key, status string) bool {
	for _, item := range items {
		if item.Key == key && item.Status == status {
			return true
		}
	}
	return false
}

func environmentContains(checks []struct {
	Key     string `json:"key"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}, key string) bool {
	for _, check := range checks {
		if check.Key == key && check.Status != "" && check.Message != "" {
			return true
		}
	}
	return false
}

func checklistContainsResponse(items []struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Action string `json:"action"`
}, key, status string) bool {
	for _, item := range items {
		if item.Key == key && item.Status == status {
			return true
		}
	}
	return false
}
