package instance

import (
	"context"
	"testing"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

func TestServiceDraftSmokeConfirmLifecycle(t *testing.T) {
	ctx := context.Background()
	auditLog := NewMemoryAuditSink()
	service := NewService(NewMemoryStore(), ServiceConfig{
		SecretResolver: StaticSecretResolver{"secret://agentnexus/dev/file-storage": "resolved-secret-value"},
		AuditSink:      auditLog,
		NewID:          sequenceIDs("pkg_1", "instance_1", "audit_1"),
	})

	draft, err := service.DraftInstance(ctx, DraftInstanceInput{
		EnterpriseID: "ent_1",
		Manifest:     validInstanceManifest(),
		BaseURL:      "https://files.example.test",
		AccountSet:   []string{"legal"},
		FieldMapping: map[string]string{"owner_email": "owner.email"},
		DataScope:    []string{"department:legal"},
		CredentialRefs: map[string]string{
			"file_storage_reader": "secret://agentnexus/dev/file-storage",
		},
	})
	if err != nil {
		t.Fatalf("DraftInstance returned error: %v", err)
	}
	if draft.Package.ID != "pkg_1" || draft.Instance.ID != "instance_1" || draft.Instance.Status != StatusDraft {
		t.Fatalf("draft = %+v", draft)
	}
	if draft.Instance.CredentialRefs["file_storage_reader"] != "secret://agentnexus/dev/file-storage" {
		t.Fatalf("credential refs = %+v", draft.Instance.CredentialRefs)
	}
	if containsSecretValue(draft.Instance.CredentialRefs, "resolved-secret-value") {
		t.Fatal("instance stored resolved secret value")
	}

	smoke, err := service.SmokeInstance(ctx, SmokeInstanceInput{
		EnterpriseID: "ent_1",
		InstanceID:   draft.Instance.ID,
		Resource:     "legal_contracts",
		Operation:    "read",
		Fields:       []string{"title", "owner_email"},
	})
	if err != nil {
		t.Fatalf("SmokeInstance returned error: %v", err)
	}
	if !smoke.OK || smoke.Adapter != "file_storage" || !smoke.CredentialResolved || !smoke.SchemaValid || !smoke.MaskingValid || smoke.AuditEventID != "audit_1" {
		t.Fatalf("smoke = %+v", smoke)
	}

	confirmed, err := service.ConfirmInstance(ctx, ConfirmInstanceInput{
		EnterpriseID:        "ent_1",
		InstanceID:          draft.Instance.ID,
		HumanConfirmationID: "confirmation_1",
	})
	if err != nil {
		t.Fatalf("ConfirmInstance returned error: %v", err)
	}
	if confirmed.Status != StatusPublished {
		t.Fatalf("status = %q, want %q", confirmed.Status, StatusPublished)
	}
}

func validInstanceManifest() connector.Manifest {
	readOnly := true
	return connector.Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "legal_file_storage",
		Version:       "0.1.0",
		Resources: []connector.Resource{{
			Name:     "legal_contracts",
			Type:     connector.ResourceTypeFile,
			ReadOnly: &readOnly,
			File:     &connector.FileConfig{Bucket: "agentnexus-demo", Prefix: "legal/contracts"},
			Fields: []connector.Field{
				{Name: "title", Type: "string"},
				{Name: "owner_email", Type: "string", Mask: true},
			},
			Operations:   []connector.Operation{{Name: "read", Method: "GET", Path: "/legal/contracts"}},
			OutputSchema: map[string]any{"type": "object"},
			SmokeTests:   []connector.SmokeTest{{Name: "read smoke", Operation: "read", Fields: []string{"title"}}},
		}},
		Credentials: []connector.Credential{{Name: "file_storage_reader", CredentialRef: "secret://agentnexus/dev/file-storage"}},
	}
}

func containsSecretValue(values map[string]string, secret string) bool {
	for _, value := range values {
		if value == secret {
			return true
		}
	}
	return false
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
