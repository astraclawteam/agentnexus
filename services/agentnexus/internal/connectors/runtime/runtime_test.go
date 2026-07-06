package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

func TestRuntimeRejectsUndeclaredField(t *testing.T) {
	rt := New(RuntimeConfig{Manifest: testManifest()})

	_, err := rt.Execute(context.Background(), Request{
		Resource:  "documents",
		Operation: "search",
		Action:    ActionRead,
		Fields:    []string{"title", "private_note"},
	})
	if !errors.Is(err, ErrUndeclaredField) {
		t.Fatalf("Execute error = %v, want ErrUndeclaredField", err)
	}
}

func TestRuntimeRejectsWriteByReadOnlyDefault(t *testing.T) {
	rt := New(RuntimeConfig{Manifest: testManifest()})

	_, err := rt.Execute(context.Background(), Request{
		Resource:  "documents",
		Operation: "update",
		Action:    ActionWrite,
		Fields:    []string{"title"},
	})
	if !errors.Is(err, ErrReadOnlyResource) {
		t.Fatalf("Execute error = %v, want ErrReadOnlyResource", err)
	}
}

func TestRuntimeResolvesCredentialWithoutExposingSecret(t *testing.T) {
	resolver := SecretResolverFunc(func(context.Context, string) (string, error) {
		return "opaque-token-for-test", nil
	})
	rt := New(RuntimeConfig{
		Manifest:       testManifest(),
		SecretResolver: resolver,
	})

	result, err := rt.Execute(context.Background(), Request{
		Resource:      "documents",
		Operation:     "search",
		Action:        ActionRead,
		Fields:        []string{"title"},
		CredentialRef: "secret://demo/http-token",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !result.Audit.CredentialResolved {
		t.Fatal("CredentialResolved = false, want true")
	}
	if strings.Contains(fmt.Sprintf("%+v", result), "opaque-token-for-test") {
		t.Fatalf("result leaked secret: %+v", result)
	}
}

func testManifest() connector.Manifest {
	return connector.Manifest{
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
			Operations: []connector.Operation{
				{Name: "search", Method: "GET", Path: "/documents"},
				{Name: "update", Method: "POST", Path: "/documents/{id}"},
			},
		}},
	}
}
