package main

import (
	"context"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/gatewayagent"
)

type stubDiagnostics struct{}

func (stubDiagnostics) InspectHealth(context.Context) (gatewayagent.HealthReport, error) {
	return gatewayagent.HealthReport{}, nil
}

func (stubDiagnostics) ExplainError(context.Context, string) (gatewayagent.ErrorExplanation, error) {
	return gatewayagent.ErrorExplanation{}, nil
}

// TestAssistantRefusesWithoutAModel pins the llmrouter-only boundary at the
// composition seam. There is no default provider to fall back to: the GA
// manifest pins model access as llmrouter-only with an empty direct-provider
// list, so a missing model must stop the assistant existing rather than cause
// it to reach for something else.
func TestAssistantRefusesWithoutAModel(t *testing.T) {
	assistant, err := newAssistant(stubDiagnostics{})
	if err == nil {
		t.Fatal("assistant composed without a model")
	}
	if assistant != nil {
		t.Fatal("a refused composition still returned an assistant")
	}
	if !strings.Contains(err.Error(), "model is required") {
		t.Fatalf("refusal did not name the missing model: %v", err)
	}
}

// TestAssistantRefusesWithoutDeterministicDiagnostics covers the other
// non-negotiable dependency: the assistant may only state facts a
// deterministic service produced, so it must not compose without one.
func TestAssistantRefusesWithoutDeterministicDiagnostics(t *testing.T) {
	if _, err := newAssistant(nil); err == nil {
		t.Fatal("assistant composed without a deterministic diagnostics service")
	}
}
