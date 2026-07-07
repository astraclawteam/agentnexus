package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

func TestOrgImportConfirmAPIWritesOrgGraph(t *testing.T) {
	iamService := iam.NewService(
		iam.NewMemoryStore(),
		iam.WithIDGenerator(sequenceIDs("identity_oa", "identity_email", "identity_llmrouter", "event_1", "version_1")),
	)
	auditLog := audit.NewHashChainLog()
	router := NewGatewayAPIRouter("gateway-api", "test", WithGatewayAPIIAMService(iamService), WithGatewayAPIAuditSink(auditLog))

	body := []byte(`{
		"enterprise_id": "ent_1",
		"enterprise_name": "Enterprise 1",
		"provider": "oa_http",
		"snapshot": {
			"departments": [{"id":"dept_rd","name":"R&D"}],
			"employees": [{"id":"user_ada","display_name":"Ada","email":"ada@example.test","department_ids":["dept_rd"]}],
			"memberships": []
		}
	}`)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/org/import/confirm", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OrgVersionID  string `json:"org_version_id"`
		VersionNumber int64  `json:"version_number"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if resp.OrgVersionID != "version_1" || resp.VersionNumber != 1 {
		t.Fatalf("response = %+v, want version_1 number 1", resp)
	}

	graphRec := httptest.NewRecorder()
	router.ServeHTTP(graphRec, httptest.NewRequest(http.MethodGet, "/api/org/graph?enterprise_id=ent_1", nil))
	if graphRec.Code != http.StatusOK {
		t.Fatalf("graph status = %d, body = %s", graphRec.Code, graphRec.Body.String())
	}
	var graphResp struct {
		Departments        []any `json:"departments"`
		Users              []any `json:"users"`
		ExternalIdentities []any `json:"external_identities"`
	}
	if err := json.Unmarshal(graphRec.Body.Bytes(), &graphResp); err != nil {
		t.Fatalf("graph json error = %v", err)
	}
	if len(graphResp.Departments) != 1 || len(graphResp.Users) != 1 || len(graphResp.ExternalIdentities) != 3 {
		t.Fatalf("graph response = %+v", graphResp)
	}
	if len(auditLog.Events()) != 1 {
		t.Fatalf("audit events = %d, want 1", len(auditLog.Events()))
	}
}

func TestOrgImportConfirmUsesPreviewSnapshotHash(t *testing.T) {
	t.Setenv("AGENTNEXUS_TEST_OA_TOKEN", "test-token")
	oaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/departments":
			_, _ = w.Write([]byte(`{"departments":[{"id":"dept_rd","name":"R&D"}]}`))
		case "/employees":
			_, _ = w.Write([]byte(`{"employees":[{"id":"user_ada","display_name":"Ada","email":"ada@example.test","department_ids":["dept_rd"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer oaServer.Close()

	iamService := iam.NewService(
		iam.NewMemoryStore(),
		iam.WithIDGenerator(sequenceIDs("identity_oa", "identity_email", "identity_llmrouter", "event_1", "version_1")),
	)
	router := NewGatewayAPIRouter("gateway-api", "test", WithGatewayAPIIAMService(iamService), WithGatewayAPISecretResolver(secrets.EnvProvider{}))
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

	previewBody := []byte(`{
		"enterprise_id": "ent_dev",
		"provider": "oa_http",
		"base_url": "` + oaServer.URL + `",
		"departments_path": "/departments",
		"employees_path": "/employees",
		"token_ref": "secret://env/AGENTNEXUS_TEST_OA_TOKEN"
	}`)
	previewRec := httptest.NewRecorder()
	router.ServeHTTP(previewRec, httptest.NewRequest(http.MethodPost, "/api/org/import/preview", bytes.NewReader(previewBody)))
	if previewRec.Code != http.StatusOK {
		t.Fatalf("preview status = %d, body = %s", previewRec.Code, previewRec.Body.String())
	}
	var previewResp struct {
		SnapshotHash string `json:"snapshot_hash"`
	}
	if err := json.Unmarshal(previewRec.Body.Bytes(), &previewResp); err != nil {
		t.Fatalf("preview json error = %v", err)
	}
	if previewResp.SnapshotHash == "" {
		t.Fatal("snapshot_hash is empty")
	}

	confirmBody := []byte(`{
		"enterprise_id": "ent_dev",
		"provider": "oa_http",
		"snapshot_hash": "` + previewResp.SnapshotHash + `",
		"human_confirmation_id": "confirm_first_org_import"
	}`)
	confirmRec := httptest.NewRecorder()
	router.ServeHTTP(confirmRec, httptest.NewRequest(http.MethodPost, "/api/org/import/confirm", bytes.NewReader(confirmBody)))
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, body = %s", confirmRec.Code, confirmRec.Body.String())
	}

	var confirmResp struct {
		EnterpriseID        string `json:"enterprise_id"`
		OrgVersionID        string `json:"org_version_id"`
		ImportedEmployees   int    `json:"imported_employees"`
		ImportedDepartments int    `json:"imported_departments"`
		ImportedMemberships int    `json:"imported_memberships"`
	}
	if err := json.Unmarshal(confirmRec.Body.Bytes(), &confirmResp); err != nil {
		t.Fatalf("confirm json error = %v", err)
	}
	if confirmResp.EnterpriseID != "ent_dev" || confirmResp.OrgVersionID != "version_1" || confirmResp.ImportedEmployees != 1 || confirmResp.ImportedDepartments != 1 || confirmResp.ImportedMemberships != 1 {
		t.Fatalf("confirm response = %+v", confirmResp)
	}
}

func TestOrgImportConfirmAPIRejectsUnconfirmedConflicts(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "test", WithGatewayAPIIAMService(iam.NewService(iam.NewMemoryStore())))
	body := []byte(`{
		"enterprise_id": "ent_1",
		"enterprise_name": "Enterprise 1",
		"provider": "oa_http",
		"snapshot": {
			"employees": [
				{"id":"user_1","display_name":"One","email":"same@example.test"},
				{"id":"user_2","display_name":"Two","email":"same@example.test"}
			]
		}
	}`)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/org/import/confirm", bytes.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error                string `json:"error"`
		RequiresConfirmation bool   `json:"requires_confirmation"`
		ConfirmationReason   string `json:"confirmation_reason"`
		Conflicts            []struct {
			Code       string `json:"code"`
			EmployeeID string `json:"employee_id"`
			RelatedID  string `json:"related_id"`
		} `json:"conflicts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if resp.Error != "org import confirmation required" || !resp.RequiresConfirmation {
		t.Fatalf("response = %+v, want structured confirmation required response", resp)
	}
	if resp.ConfirmationReason == "" {
		t.Fatalf("confirmation_reason is empty in response %+v", resp)
	}
	if len(resp.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want one duplicate email conflict", resp.Conflicts)
	}
	if resp.Conflicts[0].Code != "duplicate_email" || resp.Conflicts[0].EmployeeID != "user_2" || resp.Conflicts[0].RelatedID != "user_1" {
		t.Fatalf("conflict = %+v, want duplicate_email user_2 related user_1", resp.Conflicts[0])
	}
}

func sequenceIDs(ids ...string) func() string {
	index := 0
	return func() string {
		if index >= len(ids) {
			return "extra_id"
		}
		id := ids[index]
		index++
		return id
	}
}
