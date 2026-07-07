package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupSessionRouteReportsDevAdminHonestly(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")
	req := httptest.NewRequest(http.MethodGet, "/api/setup/session", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp setupSession
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Mode != "dev_admin" {
		t.Fatalf("mode = %q, want dev_admin", resp.Mode)
	}
	if resp.ActorUserID == "" {
		t.Fatal("actor_user_id should be present")
	}
	if resp.Secure {
		t.Fatal("dev admin session should not be marked secure")
	}
}

func TestSetupAdminInitAndLoginAreExplicitlyDeferredOutsideDevMode(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "0.1.0-test")

	for _, path := range []string{"/api/setup/admin/init", "/api/setup/login"} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"user_id":"admin"}`)))
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s status = %d, body = %s", path, rec.Code, rec.Body.String())
		}
		var resp struct {
			Error       string `json:"error"`
			Mode        string `json:"mode"`
			ActorUserID string `json:"actor_user_id"`
			Secure      bool   `json:"secure"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %s response: %v", path, err)
		}
		if resp.Mode != "dev_admin" || resp.ActorUserID == "" {
			t.Fatalf("%s response = %+v, want explicit dev_admin fallback", path, resp)
		}
		if resp.Secure {
			t.Fatalf("%s should not report secure auth when local admin auth is deferred", path)
		}
		if resp.Error == "" {
			t.Fatalf("%s should explain local admin auth is not implemented yet", path)
		}
	}
}

