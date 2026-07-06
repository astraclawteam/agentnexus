package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"gopkg.in/yaml.v3"
)

func TestConnectorPluginValidateAPI(t *testing.T) {
	manifestBytes := readConnectorFixture(t)
	router := NewGatewayAPIRouter("gateway-api", "test")
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/packages/validate", bytes.NewReader(manifestBytes))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Valid     bool     `json:"valid"`
		Name      string   `json:"name"`
		Resources []string `json:"resources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if !resp.Valid {
		t.Fatal("valid = false, want true")
	}
	if resp.Name != "legal_file_storage" {
		t.Fatalf("name = %q, want legal_file_storage", resp.Name)
	}
	if len(resp.Resources) != 1 || resp.Resources[0] != "legal_contracts" {
		t.Fatalf("resources = %#v, want [legal_contracts]", resp.Resources)
	}
}

func TestConnectorPluginSmokeAPI(t *testing.T) {
	manifest := readConnectorManifest(t)
	body, err := json.Marshal(map[string]any{
		"connector_instance_id": "connector_file_storage_1",
		"manifest":              manifest,
		"resource":              "legal_contracts",
		"operation":             "read",
		"fields":                []string{"title", "body", "owner_email"},
		"credential_ref":        "secret://agentnexus/dev/file-storage",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	router := NewGatewayAPIRouter("gateway-api", "test")
	req := httptest.NewRequest(http.MethodPost, "/api/connectors/instances/smoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK                 bool   `json:"ok"`
		Adapter            string `json:"adapter"`
		Resource           string `json:"resource"`
		Operation          string `json:"operation"`
		CredentialResolved bool   `json:"credential_resolved"`
		SchemaValid        bool   `json:"schema_valid"`
		MaskingValid       bool   `json:"masking_valid"`
		AuditEventID       string `json:"audit_event_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if !resp.OK {
		t.Fatal("ok = false, want true")
	}
	if resp.Adapter != "file_storage" {
		t.Fatalf("adapter = %q, want file_storage", resp.Adapter)
	}
	if resp.Resource != "legal_contracts" || resp.Operation != "read" {
		t.Fatalf("resource/operation = %q/%q, want legal_contracts/read", resp.Resource, resp.Operation)
	}
	if !resp.CredentialResolved {
		t.Fatal("credential_resolved = false, want true")
	}
	if !resp.SchemaValid || !resp.MaskingValid || resp.AuditEventID != "dev_smoke" {
		t.Fatalf("validation/audit = %+v", resp)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("resolved-dev-credential")) {
		t.Fatal("response leaked resolved secret value")
	}
}

func readConnectorFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "tests", "fixtures", "connectors", "file_storage_manifest.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func readConnectorManifest(t *testing.T) connector.Manifest {
	t.Helper()
	var manifest connector.Manifest
	if err := yaml.Unmarshal(readConnectorFixture(t), &manifest); err != nil {
		t.Fatalf("parse manifest fixture: %v", err)
	}
	return manifest
}
