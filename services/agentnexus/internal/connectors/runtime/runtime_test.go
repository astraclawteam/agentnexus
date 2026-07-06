package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestRuntimePipelineAppliesPolicyMaskingAndEmitsEvents(t *testing.T) {
	sink := &recordingConnectorEventSink{}
	rt := New(RuntimeConfig{
		Manifest:   testManifest(),
		AuditSink:  sink,
		HealthSink: sink,
		AdapterFactory: func(connector.Resource) Adapter {
			return staticAdapter{data: map[string]any{"title": "Contract", "body": "Sensitive"}}
		},
	})

	result, err := rt.Execute(context.Background(), Request{
		ConnectorInstanceID: "connector_1",
		Resource:            "documents",
		Operation:           "search",
		Action:              ActionRead,
		Fields:              []string{"title", "body"},
		MaskFields:          []string{"body"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if result.Data["body"] != MaskedValue {
		t.Fatalf("body = %q, want masked value", result.Data["body"])
	}
	if got := result.Audit.MaskFields; len(got) != 1 || got[0] != "body" {
		t.Fatalf("audit mask fields = %#v, want [body]", got)
	}
	if len(sink.auditEvents) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(sink.auditEvents))
	}
	if sink.auditEvents[0].Decision != "allow" || sink.auditEvents[0].ConnectorInstanceID != "connector_1" {
		t.Fatalf("audit event = %+v", sink.auditEvents[0])
	}
	if len(sink.healthEvents) != 1 {
		t.Fatalf("health event count = %d, want 1", len(sink.healthEvents))
	}
	if !sink.healthEvents[0].OK || sink.healthEvents[0].Latency <= 0 {
		t.Fatalf("health event = %+v, want ok with latency", sink.healthEvents[0])
	}
}

func TestRuntimePipelineRejectsMissingHighRiskOutputSchemaAndRateLimit(t *testing.T) {
	manifest := testManifest()
	manifest.Resources[0].Risk.Level = connector.RiskHigh
	rt := New(RuntimeConfig{Manifest: manifest})
	_, err := rt.Execute(context.Background(), Request{
		Resource:  "documents",
		Operation: "search",
		Action:    ActionRead,
		Fields:    []string{"title"},
	})
	if !errors.Is(err, ErrOutputSchemaRequired) {
		t.Fatalf("Execute error = %v, want ErrOutputSchemaRequired", err)
	}

	manifest.Resources[0].OutputSchema = map[string]any{"type": "object"}
	rateLimited := New(RuntimeConfig{Manifest: manifest, RateLimiter: NewRateLimiter(1)})
	req := Request{ConnectorInstanceID: "connector_1", Resource: "documents", Operation: "search", Action: ActionRead, Fields: []string{"title"}}
	if _, err := rateLimited.Execute(context.Background(), req); err != nil {
		t.Fatalf("first Execute returned error: %v", err)
	}
	if _, err := rateLimited.Execute(context.Background(), req); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second Execute error = %v, want ErrRateLimited", err)
	}
}

func TestRuntimeRetriesAndTimesOutAdapterExecution(t *testing.T) {
	flaky := &flakyAdapter{}
	rt := New(RuntimeConfig{
		Manifest: testManifest(),
		AdapterFactory: func(connector.Resource) Adapter {
			return flaky
		},
		MaxRetries: 1,
	})
	result, err := rt.Execute(context.Background(), Request{
		Resource:  "documents",
		Operation: "search",
		Action:    ActionRead,
		Fields:    []string{"title"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if flaky.calls != 2 || result.Audit.Attempts != 2 {
		t.Fatalf("calls = %d, audit attempts = %d, want 2", flaky.calls, result.Audit.Attempts)
	}

	timeout := New(RuntimeConfig{
		Manifest: testManifest(),
		AdapterFactory: func(connector.Resource) Adapter {
			return blockingAdapter{}
		},
		Timeout: time.Millisecond,
	})
	_, err = timeout.Execute(context.Background(), Request{
		Resource:  "documents",
		Operation: "search",
		Action:    ActionRead,
		Fields:    []string{"title"},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout Execute error = %v, want context deadline exceeded", err)
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

type recordingConnectorEventSink struct {
	auditEvents  []ConnectorAuditEvent
	healthEvents []ConnectorHealthEvent
}

func (s *recordingConnectorEventSink) RecordConnectorAudit(_ context.Context, event ConnectorAuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *recordingConnectorEventSink) RecordConnectorHealth(_ context.Context, event ConnectorHealthEvent) error {
	s.healthEvents = append(s.healthEvents, event)
	return nil
}

type flakyAdapter struct {
	calls int
}

func (a *flakyAdapter) Name() string {
	return "flaky"
}

func (a *flakyAdapter) Execute(context.Context, connector.Resource, Request) (map[string]any, error) {
	a.calls++
	if a.calls == 1 {
		return nil, errors.New("temporary adapter failure")
	}
	return map[string]any{"title": "Recovered", "body": "Visible"}, nil
}

type blockingAdapter struct{}

func (blockingAdapter) Name() string {
	return "blocking"
}

func (blockingAdapter) Execute(ctx context.Context, _ connector.Resource, _ Request) (map[string]any, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type staticAdapter struct {
	data map[string]any
}

func (staticAdapter) Name() string {
	return "static"
}

func (a staticAdapter) Execute(context.Context, connector.Resource, Request) (map[string]any, error) {
	result := make(map[string]any, len(a.data))
	for key, value := range a.data {
		result[key] = value
	}
	return result, nil
}
