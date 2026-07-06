package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/instance"
)

func TestConnectorInstanceLifecycleAPI(t *testing.T) {
	auditLog := instance.NewMemoryAuditSink()
	service := instance.NewService(instance.NewMemoryStore(), instance.ServiceConfig{
		SecretResolver: instance.StaticSecretResolver{"secret://agentnexus/dev/file-storage": "resolved-secret-value"},
		AuditSink:      auditLog,
		NewID:          sequenceIDs("pkg_1", "instance_1", "audit_1"),
	})
	router := NewGatewayAPIRouter("gateway-api", "test", WithGatewayAPIConnectorInstanceService(service))

	draftBody, err := json.Marshal(map[string]any{
		"enterprise_id": "ent_1",
		"manifest":      readConnectorManifest(t),
		"base_url":      "https://files.example.test",
		"account_set":   []string{"legal"},
		"field_mapping": map[string]string{"owner_email": "owner.email"},
		"data_scope":    []string{"department:legal"},
		"credential_refs": map[string]string{
			"file_storage_reader": "secret://agentnexus/dev/file-storage",
		},
	})
	if err != nil {
		t.Fatalf("marshal draft request: %v", err)
	}
	draftRec := httptest.NewRecorder()
	router.ServeHTTP(draftRec, httptest.NewRequest(http.MethodPost, "/api/connectors/instances/draft", bytes.NewReader(draftBody)))
	if draftRec.Code != http.StatusOK {
		t.Fatalf("draft status = %d, body = %s", draftRec.Code, draftRec.Body.String())
	}
	if bytes.Contains(draftRec.Body.Bytes(), []byte("resolved-secret-value")) {
		t.Fatal("draft response leaked resolved secret value")
	}
	var draftResp struct {
		InstanceID string `json:"connector_instance_id"`
		Status     string `json:"status"`
	}
	if err := json.Unmarshal(draftRec.Body.Bytes(), &draftResp); err != nil {
		t.Fatalf("draft json error: %v", err)
	}
	if draftResp.InstanceID != "instance_1" || draftResp.Status != instance.StatusDraft {
		t.Fatalf("draft response = %+v", draftResp)
	}

	smokeBody := []byte(`{"enterprise_id":"ent_1","resource":"legal_contracts","operation":"read","fields":["title","owner_email"]}`)
	smokeRec := httptest.NewRecorder()
	router.ServeHTTP(smokeRec, httptest.NewRequest(http.MethodPost, "/api/connectors/instances/instance_1:smoke", bytes.NewReader(smokeBody)))
	if smokeRec.Code != http.StatusOK {
		t.Fatalf("smoke status = %d, body = %s", smokeRec.Code, smokeRec.Body.String())
	}
	var smokeResp struct {
		OK                 bool   `json:"ok"`
		Adapter            string `json:"adapter"`
		CredentialResolved bool   `json:"credential_resolved"`
		SchemaValid        bool   `json:"schema_valid"`
		MaskingValid       bool   `json:"masking_valid"`
		AuditEventID       string `json:"audit_event_id"`
	}
	if err := json.Unmarshal(smokeRec.Body.Bytes(), &smokeResp); err != nil {
		t.Fatalf("smoke json error: %v", err)
	}
	if !smokeResp.OK || smokeResp.Adapter != "file_storage" || !smokeResp.CredentialResolved || !smokeResp.SchemaValid || !smokeResp.MaskingValid || smokeResp.AuditEventID != "audit_1" {
		t.Fatalf("smoke response = %+v", smokeResp)
	}

	confirmBody := []byte(`{"enterprise_id":"ent_1","human_confirmation_id":"confirmation_1"}`)
	confirmRec := httptest.NewRecorder()
	router.ServeHTTP(confirmRec, httptest.NewRequest(http.MethodPost, "/api/connectors/instances/instance_1:confirm", bytes.NewReader(confirmBody)))
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, body = %s", confirmRec.Code, confirmRec.Body.String())
	}
	var confirmResp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(confirmRec.Body.Bytes(), &confirmResp); err != nil {
		t.Fatalf("confirm json error: %v", err)
	}
	if confirmResp.Status != instance.StatusPublished {
		t.Fatalf("confirm response = %+v", confirmResp)
	}
}
