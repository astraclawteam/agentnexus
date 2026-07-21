package app

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOrgEventsPublicContract pins the organization-event subscription surface
// of the vendor-neutral runtime contract.
//
// AgentAtlas synchronizes knowledge spaces from the organization graph and has
// always declared a consumer dependency on this surface, but AgentNexus never
// published it: internal/iam owns the OrgEvent/OrgVersion domain yet has no
// route and no contract entry. Per both repositories' boundary rules a missing
// extension point is added to the PUBLIC contract first - never worked around
// in the consumer.
//
// Identity stays credential-derived: enterprise scope is carried by the
// verified service credential, so the stream declares no tenant field in a
// request body and exposes only the resumable cursor as a query parameter.
func TestOrgEventsPublicContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi", "gateway-runtime.yaml"))
	if err != nil {
		t.Fatalf("read gateway runtime OpenAPI: %v", err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse gateway runtime OpenAPI: %v", err)
	}
	paths := nestedMap(t, document, "paths")
	schemas := nestedMap(t, document, "components", "schemas")

	operation := nestedMap(t, paths, "/v1/org-events", "get")
	if operation["operationId"] != "subscribeOrgEvents" {
		t.Fatalf("org-events operationId=%v", operation["operationId"])
	}

	// The stream must be resumable: a consumer that reconnects replays strictly
	// after the last organization version it durably applied.
	parameters, ok := operation["parameters"].([]any)
	if !ok {
		t.Fatal("org-events declares no parameters")
	}
	declared := map[string]bool{}
	for _, entry := range parameters {
		parameter, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("org-events parameter is not an object: %#v", entry)
		}
		name, _ := parameter["name"].(string)
		declared[name] = true
		if name == "since_version" && parameter["required"] == true {
			t.Fatal("since_version must be optional so a first-time consumer can start from the beginning")
		}
	}
	if !declared["since_version"] {
		t.Fatalf("org-events must expose the resumable since_version cursor; declared=%v", declared)
	}
	// Tenant scope is credential-derived (Task 0B); it must never be a caller
	// -supplied parameter on this surface.
	if declared["enterprise_id"] {
		t.Fatal("enterprise_id must not be a caller-supplied parameter: tenant scope is credential-derived")
	}

	responses := nestedMap(t, operation, "responses")
	stream := nestedMap(t, responses, "200", "content")
	if _, exists := stream["text/event-stream"]; !exists {
		t.Fatalf("org-events 200 must be a text/event-stream; content=%v", keysOf(stream))
	}

	event := nestedMap(t, schemas, "OrgEvent")
	required, ok := event["required"].([]any)
	if !ok {
		t.Fatal("OrgEvent declares no required fields")
	}
	requiredSet := map[string]bool{}
	for _, field := range required {
		name, _ := field.(string)
		requiredSet[name] = true
	}
	for _, field := range []string{"event_id", "event_type", "org_version", "occurred_at"} {
		if !requiredSet[field] {
			t.Fatalf("OrgEvent must require %q; required=%v", field, required)
		}
	}
	// The organization event feed is a change notification, not an evidence
	// channel: it must not carry raw organization payloads.
	properties := nestedMap(t, event, "properties")
	for _, banned := range []string{"payload", "source_hash"} {
		if _, exists := properties[banned]; exists {
			t.Fatalf("OrgEvent must not expose %q on the public feed", banned)
		}
	}
}

func keysOf(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	return keys
}
