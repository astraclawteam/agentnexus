package agent

import (
	"context"
	"errors"
	"testing"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
)

func TestSignedRegistrationRequest(t *testing.T) {
	identity := Identity{
		AgentID:      "agent_1",
		EnterpriseID: "ent_1",
		DisplayName:  "Legal Connector Agent",
	}

	req, err := NewRegistrationRequest(identity, "shared-signing-key")
	if err != nil {
		t.Fatalf("NewRegistrationRequest returned error: %v", err)
	}
	if req.Signature == "" {
		t.Fatal("Signature is empty")
	}
	if !VerifyRegistrationRequest(req, "shared-signing-key") {
		t.Fatal("VerifyRegistrationRequest returned false")
	}

	req.DisplayName = "tampered"
	if VerifyRegistrationRequest(req, "shared-signing-key") {
		t.Fatal("VerifyRegistrationRequest accepted tampered request")
	}
}

func TestExecutorRejectsUnauthorizedExecution(t *testing.T) {
	executor := NewExecutor(map[string]*runtime.Runtime{})

	_, err := executor.Execute(context.Background(), ExecutionRequest{
		ConnectorInstanceID: "missing_instance",
		Resource:            "documents",
		Operation:           "search",
		Action:              runtime.ActionRead,
	})
	if !errors.Is(err, ErrUnknownConnectorInstance) {
		t.Fatalf("Execute error = %v, want ErrUnknownConnectorInstance", err)
	}
}

func TestExecutorRejectsDynamicCodePayload(t *testing.T) {
	executor := NewExecutor(map[string]*runtime.Runtime{
		"instance_1": runtime.New(runtime.RuntimeConfig{Manifest: testManifest()}),
	})

	_, err := executor.Execute(context.Background(), ExecutionRequest{
		ConnectorInstanceID: "instance_1",
		Resource:            "documents",
		Operation:           "search",
		Action:              runtime.ActionRead,
		Fields:              []string{"title"},
		DynamicCode:         "return fetch('https://example.invalid')",
	})
	if !errors.Is(err, ErrDynamicCodeRejected) {
		t.Fatalf("Execute error = %v, want ErrDynamicCodeRejected", err)
	}
}

func TestExecutorReturnsAuditContext(t *testing.T) {
	executor := NewExecutor(map[string]*runtime.Runtime{
		"instance_1": runtime.New(runtime.RuntimeConfig{Manifest: testManifest()}),
	})

	result, err := executor.Execute(context.Background(), ExecutionRequest{
		ConnectorInstanceID: "instance_1",
		Resource:            "documents",
		Operation:           "search",
		Action:              runtime.ActionRead,
		Fields:              []string{"title"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if result.Audit.ConnectorInstanceID != "instance_1" || result.Audit.Resource != "documents" {
		t.Fatalf("Audit = %+v, want connector/resource context", result.Audit)
	}
}

func testManifest() connector.Manifest {
	return connector.Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "docs",
		Version:       "0.1.0",
		Resources: []connector.Resource{{
			Name:       "documents",
			Type:       connector.ResourceTypeFile,
			Fields:     []connector.Field{{Name: "title", Type: "string"}},
			Operations: []connector.Operation{{Name: "search"}},
		}},
	}
}
