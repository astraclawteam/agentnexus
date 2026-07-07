package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

func TestSetupSecretsValidateDoesNotLeakValues(t *testing.T) {
	t.Setenv("AGENTNEXUS_TEST_SECRET_VALUE", "super-secret-value")
	body := []byte(`{
		"refs": {
			"oa_token": "secret://env/AGENTNEXUS_TEST_SECRET_VALUE",
			"missing": "secret://env/AGENTNEXUS_TEST_SECRET_MISSING"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/secrets/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	NewGatewayAPIRouter("gateway-api", "0.1.0-test", WithGatewayAPISecretResolver(secrets.EnvProvider{})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "super-secret-value") {
		t.Fatalf("response leaked resolved secret value: %s", rec.Body.String())
	}

	var resp struct {
		Valid   bool `json:"valid"`
		Results map[string]struct {
			Resolved bool   `json:"resolved"`
			Error    string `json:"error,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Valid {
		t.Fatal("valid = true, want false because one ref is missing")
	}
	if !resp.Results["oa_token"].Resolved {
		t.Fatalf("oa_token result = %+v, want resolved", resp.Results["oa_token"])
	}
	if resp.Results["missing"].Resolved || resp.Results["missing"].Error == "" {
		t.Fatalf("missing result = %+v, want unresolved error", resp.Results["missing"])
	}
}

func TestSetupSecretsValidateRejectsRawTokenLikeValues(t *testing.T) {
	body := []byte(`{
		"refs": {
			"llmrouter_api_key": "sk-live-this-looks-like-a-real-token",
			"oa_token": "secret://env/AGENTNEXUS_TEST_SECRET_MISSING"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/secrets/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	NewGatewayAPIRouter("gateway-api", "0.1.0-test", WithGatewayAPISecretResolver(secrets.EnvProvider{})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Valid   bool `json:"valid"`
		Results map[string]struct {
			Resolved bool   `json:"resolved"`
			Code     string `json:"code"`
			Error    string `json:"error,omitempty"`
			Fix      string `json:"fix,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Valid {
		t.Fatal("valid = true, want false for raw token-like value")
	}
	if got := resp.Results["llmrouter_api_key"].Code; got != "invalid_format" {
		t.Fatalf("raw token code = %q, want invalid_format; result = %+v", got, resp.Results["llmrouter_api_key"])
	}
	if resp.Results["llmrouter_api_key"].Resolved {
		t.Fatalf("raw token should not be resolved: %+v", resp.Results["llmrouter_api_key"])
	}
	if resp.Results["llmrouter_api_key"].Fix == "" {
		t.Fatalf("raw token result should include a fix hint: %+v", resp.Results["llmrouter_api_key"])
	}
}
