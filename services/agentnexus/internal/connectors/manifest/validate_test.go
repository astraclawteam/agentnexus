package manifest

import (
	"testing"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

func TestValidateManifestAcceptsPublicSDKStructs(t *testing.T) {
	m := connector.Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "knowledge_demo",
		Version:       "0.1.0",
		Resources: []connector.Resource{{
			Name: "documents",
			Type: connector.ResourceTypeHTTP,
			Fields: []connector.Field{
				{Name: "title", Type: "string"},
				{Name: "body", Type: "string", Mask: true},
			},
			Operations: []connector.Operation{{Name: "search", Method: "GET", Path: "/documents"}},
		}},
	}

	if err := Validate(m); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateManifestRejectsInvalidSchema(t *testing.T) {
	m := connector.Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "broken",
		Version:       "0.1.0",
		Resources: []connector.Resource{{
			Name: "documents",
			Type: connector.ResourceTypeHTTP,
			Fields: []connector.Field{
				{Name: "title", Type: "string"},
				{Name: "title", Type: "string"},
			},
		}},
	}

	if err := Validate(m); err == nil {
		t.Fatal("Validate returned nil, want duplicate field error")
	}
}
