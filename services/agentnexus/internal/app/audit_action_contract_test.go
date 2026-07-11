package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAuditAuthorizedActionIsPublishedInOpenAPIAndProto(t *testing.T) {
	openAPI, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi", "gateway-runtime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(openAPI)
	for _, token := range []string{"/v1/audit/evidence", "dream_policy_created", "dream_policy_create_authorized"} {
		if !strings.Contains(text, token) {
			t.Errorf("OpenAPI missing %s", token)
		}
	}
	var document map[string]any
	if err := yaml.Unmarshal(openAPI, &document); err != nil {
		t.Fatal(err)
	}
	actions := nestedMap(t, document, "components", "schemas", "AuditEvidenceAction")
	assertEnum(t, actions, []any{"workflow_draft_created", "workflow_version_published", "dream_policy_created", "dream_policy_create_authorized", "dream_job_run", "retrieval_plan_created", "evidence_located", "evidence_read", "answer_trace_created", "sensitive_artifact_parsed", "visibility_rule_changed"})
	proto, err := os.ReadFile(filepath.Join("..", "..", "api", "proto", "agentnexus", "audit", "v1", "audit.proto"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(proto), "DREAM_POLICY_CREATE_AUTHORIZED") {
		t.Fatal("audit proto missing authorized action")
	}
}
