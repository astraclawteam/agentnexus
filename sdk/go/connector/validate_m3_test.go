package connector

import (
	"strings"
	"testing"
)

func TestValidateManifestRejectsM3UnsafeShapes(t *testing.T) {
	tests := []struct {
		name     string
		manifest Manifest
		wantText string
	}{
		{
			name: "duplicate field",
			manifest: validM3Manifest(func(resource *Resource) {
				resource.Fields = append(resource.Fields, Field{Name: "title", Type: "string"})
			}),
			wantText: "duplicate field",
		},
		{
			name: "undeclared smoke operation",
			manifest: validM3Manifest(func(resource *Resource) {
				resource.SmokeTests = []SmokeTest{{Name: "read smoke", Operation: "missing"}}
			}),
			wantText: "undeclared smoke operation",
		},
		{
			name: "high risk missing schemas",
			manifest: validM3Manifest(func(resource *Resource) {
				resource.Risk = RiskMetadata{Level: RiskHigh}
				resource.InputSchema = nil
				resource.OutputSchema = nil
			}),
			wantText: "high-risk resource",
		},
		{
			name: "executable code upload",
			manifest: validM3Manifest(func(resource *Resource) {
				resource.Executable = &ExecutableConfig{Upload: true}
			}),
			wantText: "executable code upload is not allowed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifest(tc.manifest)
			if err == nil {
				t.Fatal("ValidateManifest returned nil")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("error = %q, want containing %q", err.Error(), tc.wantText)
			}
		})
	}
}

func TestValidateManifestAcceptsM3Metadata(t *testing.T) {
	if err := ValidateManifest(validM3Manifest(nil)); err != nil {
		t.Fatalf("ValidateManifest returned error: %v", err)
	}
}

func validM3Manifest(mutator func(*Resource)) Manifest {
	readOnly := true
	resource := Resource{
		Name:     "legal_contracts",
		Type:     ResourceTypeFile,
		ReadOnly: &readOnly,
		File:     &FileConfig{Bucket: "agentnexus-demo", Prefix: "legal/contracts"},
		Fields: []Field{
			{Name: "title", Type: "string"},
			{Name: "body", Type: "string"},
			{Name: "owner_email", Type: "string", Mask: true},
		},
		Operations: []Operation{{Name: "read", Method: "GET", Path: "/legal/contracts"}},
		Scopes:     []string{"department:legal"},
		InputSchema: map[string]any{
			"type": "object",
		},
		OutputSchema: map[string]any{
			"type": "object",
		},
		SmokeTests: []SmokeTest{{Name: "read smoke", Operation: "read", Fields: []string{"title"}}},
		Risk:       RiskMetadata{Level: RiskMedium, RequiresAudit: true},
	}
	if mutator != nil {
		mutator(&resource)
	}
	return Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "legal_file_storage",
		Version:       "0.1.0",
		Resources:     []Resource{resource},
		Credentials:   []Credential{{Name: "file_storage_reader", CredentialRef: "secret://agentnexus/dev/file-storage"}},
	}
}
