package app

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIGatewayRuntimeContract(t *testing.T) {
	openAPI, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi", "gateway-runtime.yaml"))
	if err != nil {
		t.Fatalf("read gateway runtime OpenAPI: %v", err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(openAPI, &document); err != nil {
		t.Fatalf("parse gateway runtime OpenAPI: %v", err)
	}
	schemas := nestedMap(t, document, "components", "schemas")
	paths := nestedMap(t, document, "paths")
	caseTicket := nestedMap(t, document, "components", "securitySchemes", "caseTicket")
	if description, _ := caseTicket["description"].(string); description != "Use the exact header format: Authorization: CaseTicket <opaque>" {
		t.Fatalf("CaseTicket security description=%q", description)
	}
	// GA Task 0E: the legacy resolution surface is RETIRED — no resolve
	// operation and no route/facts schemas may reappear.
	if _, exists := paths["/v1/approvals/resolve"]; exists {
		t.Fatal("the retired approval resolution operation must not reappear in the public contract")
	}
	for _, retired := range []string{"ApprovalRoute", "ApprovalResolveRequest"} {
		if _, exists := schemas[retired]; exists {
			t.Fatalf("retired approval resolution schema %s must not reappear", retired)
		}
	}
	transmitPath := nestedMap(t, paths, "/v1/approvals/transmissions", "post")
	if transmitPath["operationId"] != "transmitApprovalPlan" {
		t.Fatalf("transmit operationId=%v", transmitPath["operationId"])
	}
	statusPath := nestedMap(t, paths, "/v1/approvals/transmissions/{plan_ref}", "get")
	if statusPath["operationId"] != "getApprovalTransmission" {
		t.Fatalf("status operationId=%v", statusPath["operationId"])
	}
	revokePath := nestedMap(t, paths, "/v1/approvals/transmissions/{plan_ref}/revocations", "post")
	if revokePath["operationId"] != "revokeApprovalTransmission" {
		t.Fatalf("revoke operationId=%v", revokePath["operationId"])
	}
	evidencePath := nestedMap(t, paths, "/v1/approvals/evidence", "post")
	if evidencePath["operationId"] != "recordApprovalEvidence" {
		t.Fatalf("evidence operationId=%v", evidencePath["operationId"])
	}
	for path, operationID := range map[string]string{"/v1/step-grants": "createStepGrant", "/v1/tickets/verify": "verifyStepGrant"} {
		operation := nestedMap(t, paths, path, "post")
		if operation["operationId"] != operationID {
			t.Fatalf("%s operationId=%v", path, operation["operationId"])
		}
	}
	permissions := []any{"suggest", "edit", "publish_low_risk", "approve_high_risk", "workflow_edit", "workflow_advanced", "service_mode"}
	permissionSchema, ok := schemas["PrincipalPermission"].(map[string]any)
	if !ok {
		t.Fatal("PrincipalPermission schema missing")
	}
	assertEnum(t, permissionSchema, permissions)
	for _, schemaName := range []string{"BrowserSession", "PermissionDecision"} {
		items := nestedMap(t, property(t, namedSchema(t, schemas, schemaName), "permissions"), "items")
		if items["$ref"] != "#/components/schemas/PrincipalPermission" {
			t.Fatalf("%s permission items=%v", schemaName, items)
		}
	}
	riskLevelSchema, ok := schemas["RiskLevel"].(map[string]any)
	if !ok {
		t.Fatal("RiskLevel schema missing")
	}
	assertEnum(t, riskLevelSchema, []any{"low", "medium", "high"})
	tokenRequest := namedSchema(t, schemas, "BrowserTokenRequest")
	assertObjectProperties(t, tokenRequest, []string{"grant_type", "code", "code_verifier", "redirect_uri"}, nil)
	tokenSecurity := nestedMap(t, document, "components", "securitySchemes", "consoleClientSecret")
	if tokenSecurity["type"] != "http" || tokenSecurity["scheme"] != "basic" {
		t.Fatalf("console client security=%v", tokenSecurity)
	}

	for _, endpoint := range []struct{ path, method string }{
		{"/v1/browser-sessions/me", "get"},
		{"/v1/browser-sessions/logout", "post"},
		{"/v1/authorization/decisions", "post"},
		{"/v1/runtime/locate", "post"},
		{"/v1/runtime/read", "post"},
		{"/v1/runtime/act", "post"},
		{"/v1/runtime/receipts/{receipt_ref}", "get"},
		{"/v1/runtime/actions/{action_ref}/receipts", "post"},
		{"/v1/runtime/actions/{action_ref}/compensations", "post"},
		{"/v1/approvals/transmissions", "post"},
		{"/v1/approvals/transmissions/{plan_ref}", "get"},
		{"/v1/approvals/transmissions/{plan_ref}/revocations", "post"},
		{"/v1/approvals/evidence", "post"},
		{"/v1/step-grants", "post"},
		{"/v1/tickets/verify", "post"},
	} {
		operation := nestedMap(t, paths, endpoint.path, endpoint.method)
		security, ok := operation["security"].([]any)
		if !ok {
			t.Fatalf("%s %s must declare browserAccessToken security", endpoint.method, endpoint.path)
		}
		found := false
		for _, item := range security {
			if schemes, ok := item.(map[string]any); ok {
				_, found = schemes["browserAccessToken"]
			}
			if found {
				break
			}
		}
		if !found {
			t.Fatalf("%s %s accepts a browser BFF token in the runtime but omits it from OpenAPI", endpoint.method, endpoint.path)
		}
	}

	t.Run("BrowserSession", func(t *testing.T) {
		schema := namedSchema(t, schemas, "BrowserSession")
		assertObjectProperties(t, schema, []string{
			"authenticated", "tenant_ref", "principal_ref", "display_name",
			"org_version", "org_unit_ids", "permissions", "advanced_mode_allowed",
			"idle_expires_at", "absolute_expires_at",
		}, nil)
		assertPropertyType(t, schema, "authenticated", "boolean")
		assertPropertyType(t, schema, "tenant_ref", "string")
		assertPropertyType(t, schema, "principal_ref", "string")
		assertPropertyType(t, schema, "display_name", "string")
		assertPropertyType(t, schema, "org_version", "integer")
		assertStringArray(t, schema, "org_unit_ids")
		assertPropertyType(t, schema, "advanced_mode_allowed", "boolean")
		assertDateTime(t, schema, "idle_expires_at")
		assertDateTime(t, schema, "absolute_expires_at")
	})

	t.Run("PermissionDecision", func(t *testing.T) {
		schema := namedSchema(t, schemas, "PermissionDecision")
		assertObjectProperties(t, schema, []string{
			"decision", "permissions", "org_unit_ids", "mask_fields", "risk_level", "org_version",
		}, []string{"fallback_action"})
		assertEnum(t, property(t, schema, "decision"), []any{"allow", "deny"})
		assertStringArray(t, schema, "org_unit_ids")
		assertStringArray(t, schema, "mask_fields")
		assertRiskLevelRef(t, schema, "risk_level")
		assertPropertyType(t, schema, "fallback_action", "string")
		assertPropertyType(t, schema, "org_version", "integer")
	})

	t.Run("ApprovalTransmissionStatus", func(t *testing.T) {
		schema := namedSchema(t, schemas, "ApprovalTransmissionStatus")
		assertObjectProperties(t, schema, []string{
			"plan_ref", "plan_hash", "authority", "business_context_ref", "capability", "parameter_hash", "status", "expires_at", "delivery_attempts", "updated_at",
		}, []string{"last_delivery_state", "decision", "decided_at", "revoked_at"})
		assertEnum(t, property(t, schema, "status"), []any{
			"pending", "delivered", "evidence_recorded", "revoked",
		})
		properties := nestedMap(t, schema, "properties")
		// The transmission plane carries NO approver identity, queue routing
		// or risk classification: the external authority owns all of it.
		for _, banned := range []string{"reviewer_user_id", "reviewer_display_name", "queue", "mode", "org_path", "risk_level", "risk_reasons", "requester_user_id", "granted"} {
			if _, exists := properties[banned]; exists {
				t.Fatalf("ApprovalTransmissionStatus must not expose %s", banned)
			}
		}
		if property(t, schema, "decision")["$ref"] != "#/components/schemas/ApprovalDecision" {
			t.Fatal("decision must reference the shared ApprovalDecision schema")
		}
		assertDateTime(t, schema, "expires_at")
		assertDateTime(t, schema, "updated_at")
	})

	t.Run("ApprovalDecision", func(t *testing.T) {
		decisionSchema, ok := schemas["ApprovalDecision"].(map[string]any)
		if !ok {
			t.Fatal("ApprovalDecision schema missing")
		}
		assertEnum(t, decisionSchema, []any{"approved", "denied", "narrowed"})
	})

	t.Run("ApprovalEvidence", func(t *testing.T) {
		schema := namedSchema(t, schemas, "ApprovalEvidence")
		assertObjectProperties(t, schema, []string{
			"approval_ref", "plan_ref", "plan_hash", "capability", "parameter_hash", "decision", "approver_authority", "decided_at", "attestation",
		}, nil)
		if property(t, schema, "attestation")["$ref"] != "#/components/schemas/Signature" {
			t.Fatal("attestation must reference the shared Signature schema")
		}
		assertDateTime(t, schema, "decided_at")
	})

	t.Run("ApprovalTransmissionRequest", func(t *testing.T) {
		schema, ok := schemas["ApprovalTransmissionRequest"].(map[string]any)
		if !ok {
			t.Fatal("ApprovalTransmissionRequest schema missing")
		}
		composition, ok := schema["allOf"].([]any)
		if !ok || len(composition) != 2 {
			t.Fatalf("ApprovalTransmissionRequest must compose RequestEnvelope: %v", schema["allOf"])
		}
		body, ok := composition[1].(map[string]any)
		if !ok {
			t.Fatal("ApprovalTransmissionRequest body schema missing")
		}
		properties := nestedMap(t, body, "properties")
		if plan, ok := properties["plan"].(map[string]any); !ok || plan["$ref"] != "#/components/schemas/ApprovalPlanRef" {
			t.Fatalf("plan must reference the frozen ApprovalPlanRef: %v", properties["plan"])
		}
		for _, banned := range []string{"org_version", "org_unit_id", "requested_risk", "changed_fields", "reviewer_user_id"} {
			if _, exists := properties[banned]; exists {
				t.Fatalf("ApprovalTransmissionRequest must not carry %s", banned)
			}
		}
	})
	t.Run("StepGrantRequest", func(t *testing.T) {
		schema := namedSchema(t, schemas, "StepGrantRequest")
		assertObjectProperties(t, schema, []string{"request_id", "business_context_ref", "capability", "parameter_hash", "purpose", "ttl_seconds"}, []string{"trace_id"})
		if _, exists := nestedMap(t, schema, "properties")["enterprise_id"]; exists {
			t.Fatal("request must not trust enterprise_id")
		}
		if _, exists := nestedMap(t, schema, "properties")["org_version"]; exists {
			t.Fatal("request must not supply the trusted organization version")
		}
	})
}

func nestedMap(t *testing.T, root map[string]any, path ...string) map[string]any {
	t.Helper()
	current := root
	for _, key := range path {
		value, ok := current[key]
		if !ok {
			t.Fatalf("OpenAPI missing %s", key)
		}
		current, ok = value.(map[string]any)
		if !ok {
			t.Fatalf("OpenAPI %s is %T, want object", key, value)
		}
	}
	return current
}

func namedSchema(t *testing.T, schemas map[string]any, name string) map[string]any {
	t.Helper()
	value, ok := schemas[name]
	if !ok {
		t.Fatalf("contract missing schema %s", name)
	}
	schema, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema %s is %T, want object", name, value)
	}
	assertType(t, schema, "object")
	return schema
}

func assertObjectProperties(t *testing.T, schema map[string]any, required, optional []string) {
	t.Helper()
	properties := nestedMap(t, schema, "properties")
	wantProperties := append(append([]string(nil), required...), optional...)
	sort.Strings(wantProperties)
	gotProperties := make([]string, 0, len(properties))
	for name := range properties {
		gotProperties = append(gotProperties, name)
	}
	sort.Strings(gotProperties)
	if !reflect.DeepEqual(gotProperties, wantProperties) {
		t.Fatalf("properties = %v, want %v", gotProperties, wantProperties)
	}

	gotRequired, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("required is %T, want array", schema["required"])
	}
	gotRequiredNames := make([]string, 0, len(gotRequired))
	for _, value := range gotRequired {
		name, ok := value.(string)
		if !ok {
			t.Fatalf("required value is %T, want string", value)
		}
		gotRequiredNames = append(gotRequiredNames, name)
	}
	sort.Strings(gotRequiredNames)
	wantRequired := append([]string(nil), required...)
	sort.Strings(wantRequired)
	if !reflect.DeepEqual(gotRequiredNames, wantRequired) {
		t.Fatalf("required = %v, want %v", gotRequiredNames, wantRequired)
	}
}

func property(t *testing.T, schema map[string]any, name string) map[string]any {
	t.Helper()
	properties := nestedMap(t, schema, "properties")
	value, ok := properties[name]
	if !ok {
		t.Fatalf("property missing %s", name)
	}
	propertySchema, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("property %s is %T, want object", name, value)
	}
	return propertySchema
}

func assertPropertyType(t *testing.T, schema map[string]any, name, want string) {
	t.Helper()
	assertType(t, property(t, schema, name), want)
}

func assertType(t *testing.T, schema map[string]any, want string) {
	t.Helper()
	if got := schema["type"]; got != want {
		t.Fatalf("type = %v, want %s", got, want)
	}
}

func assertStringArray(t *testing.T, schema map[string]any, name string) {
	t.Helper()
	array := property(t, schema, name)
	assertType(t, array, "array")
	items, ok := array["items"].(map[string]any)
	if !ok {
		t.Fatalf("property %s items is %T, want object", name, array["items"])
	}
	assertType(t, items, "string")
}

func assertDateTime(t *testing.T, schema map[string]any, name string) {
	t.Helper()
	dateTime := property(t, schema, name)
	assertType(t, dateTime, "string")
	if got := dateTime["format"]; got != "date-time" {
		t.Fatalf("property %s format = %v, want date-time", name, got)
	}
}

func assertEnum(t *testing.T, schema map[string]any, want []any) {
	t.Helper()
	got, ok := schema["enum"].([]any)
	if !ok {
		t.Fatalf("enum is %T, want array", schema["enum"])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enum = %v, want %v", got, want)
	}
}

// assertRiskLevelRef asserts a property references the single shared
// RiskLevel schema (the enum itself is asserted once on that schema).
func assertRiskLevelRef(t *testing.T, schema map[string]any, name string) {
	t.Helper()
	if got := property(t, schema, name)["$ref"]; got != "#/components/schemas/RiskLevel" {
		t.Fatalf("property %s = %v, want $ref to the shared RiskLevel schema", name, got)
	}
}
