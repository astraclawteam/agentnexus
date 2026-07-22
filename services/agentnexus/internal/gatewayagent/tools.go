package gatewayagent

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
)

// toolNamePrefix namespaces every tool this assistant owns. A model that has
// been talked into calling something else will name a tool that does not exist,
// which is a visible failure rather than a silent one.
const toolNamePrefix = "nexus_ops_"

// ComponentHealth is one deterministic service-health fact.
type ComponentHealth struct {
	Name   string `json:"name"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// HealthReport is the deterministic health snapshot the assistant may quote.
type HealthReport struct {
	Components []ComponentHealth `json:"components"`
}

// ErrorExplanation is a deterministic decoding of a recorded failure.
type ErrorExplanation struct {
	Code     string `json:"code"`
	Meaning  string `json:"meaning"`
	NextStep string `json:"next_step,omitempty"`
}

// DiagnosticsService is the deterministic backing for every fact the assistant
// is allowed to state.
//
// This interface is the reason the assistant can be trusted to explain
// anything: it never derives a diagnostic fact from the model. The model
// chooses WHICH question to ask and phrases the answer for an operator; the
// content comes from here. An assistant with no deterministic backing has
// nothing to ground an answer in, which is why NewTools refuses to build
// without one rather than degrading to a plausible-sounding guess.
type DiagnosticsService interface {
	InspectHealth(ctx context.Context) (HealthReport, error)
	ExplainError(ctx context.Context, code string) (ErrorExplanation, error)
}

type inspectHealthArgs struct{}

type explainErrorArgs struct {
	Code string `json:"code"`
}

// inspectHealthHandler and explainErrorHandler are separate from tool
// construction so the tenant and grounding rules can be tested directly,
// without driving a model.
func inspectHealthHandler(diagnostics DiagnosticsService) func(context.Context, inspectHealthArgs) (HealthReport, error) {
	return func(ctx context.Context, _ inspectHealthArgs) (HealthReport, error) {
		// The tenant is established at the service edge from the verified
		// browser session. A handler reached without one is operating on
		// nobody's behalf, so it refuses before touching the service.
		if _, err := TenantFrom(ctx); err != nil {
			return HealthReport{}, err
		}
		return diagnostics.InspectHealth(ctx)
	}
}

func explainErrorHandler(diagnostics DiagnosticsService) func(context.Context, explainErrorArgs) (ErrorExplanation, error) {
	return func(ctx context.Context, args explainErrorArgs) (ErrorExplanation, error) {
		if _, err := TenantFrom(ctx); err != nil {
			return ErrorExplanation{}, err
		}
		return diagnostics.ExplainError(ctx, args.Code)
	}
}

// NewTools builds the tools the policy allows, and only those.
//
// A denied capability produces no tool at all. Building it and refusing at call
// time would still advertise the capability to the model, which turns a hard
// boundary into an argument the model is invited to have.
//
// Allowed is not the same as implemented. The allow-list names five
// capabilities; the three without a builder below (prepare_connector_onboarding,
// validate_draft, propose_diagnostics) simply produce nothing here, and because
// the agent instruction is generated from what this function returns, the model
// is never told they exist. TestToolsBuildExactlyTheImplementedCapabilities
// pins the resulting set so a capability can never again ship with no tool
// without a test saying so.
func NewTools(policy Policy, diagnostics DiagnosticsService) ([]tool.Tool, error) {
	if diagnostics == nil {
		return nil, errors.New("gateway agent: a deterministic diagnostics service is required; the assistant may not invent diagnostic facts")
	}

	var tools []tool.Tool

	// ADK hands a tool an agent.Context, which embeds context.Context. The
	// handlers stay plain context.Context functions so the tenant and grounding
	// rules can be tested directly, without standing up an invocation.
	if err := policy.Allow(CapabilityInspectHealth); err == nil {
		handler := inspectHealthHandler(diagnostics)
		built, err := functiontool.New(functiontool.Config{
			Name: toolNamePrefix + "inspect_health",
			// Deployment readiness, not tenant readiness. The tenant is a gate
			// on asking, not a filter on the answer, and this description is
			// handed to the model verbatim - describing it as tenant-scoped
			// would invite the model to report it as such.
			Description: "Report the deterministic readiness of this AgentNexus deployment's services. Read-only.",
		}, func(ctx agent.Context, args inspectHealthArgs) (HealthReport, error) {
			return handler(ctx, args)
		})
		if err != nil {
			return nil, fmt.Errorf("build inspect_health tool: %w", err)
		}
		tools = append(tools, built)
	}

	if err := policy.Allow(CapabilityExplainError); err == nil {
		handler := explainErrorHandler(diagnostics)
		built, err := functiontool.New(functiontool.Config{
			Name:        toolNamePrefix + "explain_error",
			Description: "Explain a recorded AgentNexus error code in operator language. Read-only; never changes state.",
		}, func(ctx agent.Context, args explainErrorArgs) (ErrorExplanation, error) {
			return handler(ctx, args)
		})
		if err != nil {
			return nil, fmt.Errorf("build explain_error tool: %w", err)
		}
		tools = append(tools, built)
	}

	if len(tools) == 0 {
		return nil, errors.New("gateway agent: policy allows no tools")
	}
	return tools, nil
}
