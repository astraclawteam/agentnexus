package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
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
