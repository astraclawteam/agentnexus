package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
)

func TestOrgImportPreviewAPI(t *testing.T) {
	var authHeader string
	oaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/departments":
			_, _ = w.Write([]byte(`{"departments":[{"id":"dept_rd","parent_id":"","name":"R&D","manager_employee_id":"user_ada"}]}`))
		case "/employees":
			_, _ = w.Write([]byte(`{"employees":[{"id":"user_ada","display_name":"Ada","email":"ada@example.test","phone":"","manager_employee_id":"","department_ids":["dept_rd"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer oaServer.Close()

	auditLog := audit.NewHashChainLog()
	router := NewGatewayAPIRouter("gateway-api", "test", WithGatewayAPISecretResolver(connectorruntime.SecretResolverFunc(func(_ context.Context, ref string) (string, error) {
		if ref != "secret://agentnexus/dev/oa-token" {
			t.Fatalf("secret ref = %q, want secret://agentnexus/dev/oa-token", ref)
		}
		return "test-token", nil
	})), WithGatewayAPIAuditSink(auditLog))

	body := []byte(`{
		"provider": "oa_http",
		"base_url": "` + oaServer.URL + `",
		"departments_path": "/departments",
		"employees_path": "/employees",
		"token_ref": "secret://agentnexus/dev/oa-token"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/org/import/preview", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if authHeader != "Bearer test-token" {
		t.Fatalf("Authorization header = %q, want Bearer test-token", authHeader)
	}

	var resp struct {
		Provider                  string   `json:"provider"`
		SnapshotHash              string   `json:"snapshot_hash"`
		RequiresConfirmation      bool     `json:"requires_confirmation"`
		AutoImportableEmployeeIDs []string `json:"auto_importable_employee_ids"`
		Conflicts                 []any    `json:"conflicts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if resp.Provider != "oa_http" {
		t.Fatalf("provider = %q, want oa_http", resp.Provider)
	}
	if resp.SnapshotHash == "" {
		t.Fatal("snapshot_hash is empty")
	}
	if resp.RequiresConfirmation {
		t.Fatal("requires_confirmation = true, want false")
	}
	if len(resp.AutoImportableEmployeeIDs) != 1 || resp.AutoImportableEmployeeIDs[0] != "user_ada" {
		t.Fatalf("auto_importable_employee_ids = %#v, want [user_ada]", resp.AutoImportableEmployeeIDs)
	}
	if len(resp.Conflicts) != 0 {
		t.Fatalf("conflicts = %#v, want none", resp.Conflicts)
	}
	if len(auditLog.Events()) != 1 {
		t.Fatalf("audit events = %d, want 1", len(auditLog.Events()))
	}
}
