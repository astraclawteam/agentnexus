package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAuditRequestedActionIsPublishedInOpenAPIAndProto(t *testing.T) {
	openAPI, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi", "gateway-runtime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(openAPI)
	for _, token := range []string{"/v1/audit/evidence", "dream_policy_created", "dream_policy_create_requested"} {
		if !strings.Contains(text, token) {
			t.Errorf("OpenAPI missing %s", token)
		}
	}
	var document map[string]any
	if err := yaml.Unmarshal(openAPI, &document); err != nil {
		t.Fatal(err)
	}
	actions := nestedMap(t, document, "components", "schemas", "AuditEvidenceAction")
	assertEnum(t, actions, []any{"workflow_draft_created", "workflow_version_published", "dream_policy_created", "dream_policy_create_requested", "dream_job_run", "retrieval_plan_created", "evidence_located", "evidence_read", "answer_trace_created", "sensitive_artifact_parsed", "visibility_rule_changed"})
	auditPath := nestedMap(t, document, "paths", "/v1/audit/evidence", "post")
	security := auditPath["security"].([]any)
	_, hasServiceSecurity := security[0].(map[string]any)["trustedServiceSecret"]
	_, hasBearerSecurity := security[1].(map[string]any)["browserAccessToken"]
	if len(security) != 2 || !hasServiceSecurity || !hasBearerSecurity {
		t.Fatal("audit endpoint must accept dedicated service Basic or bound browser Bearer auth")
	}
	serviceSecret := nestedMap(t, document, "components", "securitySchemes", "trustedServiceSecret")
	if serviceSecret["type"] != "http" || serviceSecret["scheme"] != "basic" || !strings.Contains(serviceSecret["description"].(string), "trusted first-party service") {
		t.Fatalf("trusted service security scheme=%v", serviceSecret)
	}
	responses := nestedMap(t, auditPath, "responses")
	for _, status := range []string{"201", "400", "401", "503"} {
		if _, ok := responses[status]; !ok {
			t.Errorf("audit response missing %s", status)
		}
	}
	requestSchema := nestedMap(t, document, "components", "schemas", "AuditEvidenceRequest")
	assertObjectProperties(t, requestSchema, []string{"business_context_ref", "action", "resource_type", "resource_id"}, []string{"request_id", "trace_id", "details"})
	if properties := nestedMap(t, requestSchema, "properties"); properties["workflow_run_id"] != nil {
		t.Fatal("audit request must not silently accept an unpersisted workflow_run_id")
	}
	if properties := nestedMap(t, requestSchema, "properties"); properties["enterprise_id"] != nil {
		t.Fatal("audit request must not carry caller-supplied tenant identity; it comes from the verified service credentials")
	}
	if branches, ok := requestSchema["oneOf"].([]any); !ok || len(branches) != 2 {
		t.Fatalf("audit resource binding oneOf=%v", requestSchema["oneOf"])
	}
	proto, err := os.ReadFile(filepath.Join("..", "..", "api", "proto", "agentnexus", "audit", "v1", "audit.proto"))
	if err != nil {
		t.Fatal(err)
	}
	protoText := string(proto)
	stable := []string{"AUDIT_ACTION_UNSPECIFIED = 0", "WORKFLOW_DRAFT_CREATED = 1", "WORKFLOW_VERSION_PUBLISHED = 2", "DREAM_POLICY_CREATED = 3", "DREAM_POLICY_CREATE_REQUESTED = 4", "DREAM_JOB_RUN = 5", "RETRIEVAL_PLAN_CREATED = 6", "EVIDENCE_LOCATED = 7", "EVIDENCE_READ = 8", "ANSWER_TRACE_CREATED = 9", "SENSITIVE_ARTIFACT_PARSED = 10", "VISIBILITY_RULE_CHANGED = 11"}
	for _, declaration := range stable {
		if !strings.Contains(protoText, declaration) {
			t.Errorf("proto missing stable enum %s", declaration)
		}
	}
}
