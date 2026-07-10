package app

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGatewayRuntimePublicContract(t *testing.T) {
	openAPI, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi", "gateway-runtime.yaml"))
	if err != nil {
		t.Fatalf("read gateway runtime OpenAPI: %v", err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(openAPI, &document); err != nil {
		t.Fatalf("parse gateway runtime OpenAPI: %v", err)
	}
	schemas := nestedMap(t, document, "components", "schemas")

	t.Run("BrowserSession", func(t *testing.T) {
		schema := namedSchema(t, schemas, "BrowserSession")
		assertObjectProperties(t, schema, []string{
			"authenticated", "enterprise_id", "enterprise_user_id", "display_name",
			"org_version", "org_unit_ids", "permissions", "advanced_mode_allowed",
			"idle_expires_at", "absolute_expires_at",
		}, nil)
		assertPropertyType(t, schema, "authenticated", "boolean")
		assertPropertyType(t, schema, "enterprise_id", "string")
		assertPropertyType(t, schema, "enterprise_user_id", "string")
		assertPropertyType(t, schema, "display_name", "string")
		assertPropertyType(t, schema, "org_version", "integer")
		assertStringArray(t, schema, "org_unit_ids")
		assertStringArray(t, schema, "permissions")
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
		assertStringArray(t, schema, "permissions")
		assertStringArray(t, schema, "org_unit_ids")
		assertStringArray(t, schema, "mask_fields")
		assertEnum(t, property(t, schema, "risk_level"), []any{"low", "medium", "high"})
		assertPropertyType(t, schema, "fallback_action", "string")
		assertPropertyType(t, schema, "org_version", "integer")
	})

	t.Run("ApprovalRoute", func(t *testing.T) {
		schema := namedSchema(t, schemas, "ApprovalRoute")
		assertObjectProperties(t, schema, []string{
			"mode", "risk_level", "risk_reasons", "requester_user_id", "org_path", "auto_publish",
		}, []string{"reviewer_user_id", "reviewer_display_name", "queue"})
		assertEnum(t, property(t, schema, "mode"), []any{
			"single_confirmation", "upward_review", "enterprise_knowledge_admin_queue",
		})
		assertEnum(t, property(t, schema, "risk_level"), []any{"low", "medium", "high"})
		assertStringArray(t, schema, "risk_reasons")
		assertPropertyType(t, schema, "requester_user_id", "string")
		assertPropertyType(t, schema, "reviewer_user_id", "string")
		assertPropertyType(t, schema, "reviewer_display_name", "string")
		assertStringArray(t, schema, "org_path")
		assertPropertyType(t, schema, "queue", "string")
		autoPublish := property(t, schema, "auto_publish")
		assertType(t, autoPublish, "boolean")
		assertEnum(t, autoPublish, []any{false})
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
