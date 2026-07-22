package gatewayagent

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	"google.golang.org/adk/v2/tool"
)

type stubDiagnostics struct {
	healthCalls int
	lastTenant  string
}

func (s *stubDiagnostics) InspectHealth(ctx context.Context) (HealthReport, error) {
	s.healthCalls++
	tenantRef, err := TenantFrom(ctx)
	if err != nil {
		return HealthReport{}, err
	}
	s.lastTenant = tenantRef
	return HealthReport{Components: []ComponentHealth{{Name: "gateway-api", Ready: true}}}, nil
}

func (s *stubDiagnostics) ExplainError(ctx context.Context, code string) (ErrorExplanation, error) {
	if _, err := TenantFrom(ctx); err != nil {
		return ErrorExplanation{}, err
	}
	if code == "" {
		return ErrorExplanation{}, errors.New("no code")
	}
	return ErrorExplanation{Code: code, Meaning: "the dispatch bus was unreachable", NextStep: "check the bus"}, nil
}

// policyAllowing builds a policy that permits exactly the given capabilities,
// so denial can be exercised without editing the package allow-list.
func policyAllowing(capabilities ...ToolCapability) Policy {
	policy := NewPolicy()
	allowed := make(map[ToolCapability]struct{}, len(capabilities))
	for _, capability := range capabilities {
		allowed[capability] = struct{}{}
	}
	policy.allowed = allowed
	return policy
}

// toolNames lists what NewTools actually produced.
func toolNames(tools []tool.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, built := range tools {
		names = append(names, built.Name())
	}
	sort.Strings(names)
	return names
}

// TestToolsBuildExactlyTheImplementedCapabilities pins the tool set.
//
// Its predecessor asserted only that SOME tools were built and that each was
// namespaced - which is why three allowed capabilities shipped with no tool at
// all and nothing failed. Pinning the exact set is what makes that visible:
// implementing one of the remaining capabilities, or losing one of these two,
// now has to come here and say so.
func TestToolsBuildExactlyTheImplementedCapabilities(t *testing.T) {
	tools, err := NewTools(NewPolicy(), &stubDiagnostics{})
	if err != nil {
		t.Fatalf("build tools: %v", err)
	}
	want := []string{toolNamePrefix + "explain_error", toolNamePrefix + "inspect_health"}
	got := toolNames(tools)
	if !slices.Equal(got, want) {
		t.Fatalf("built tools %v; want exactly %v", got, want)
	}
}

// TestToolsOmitDeniedCapabilities is the direction the old test never took: a
// capability the policy denies must produce no tool AT ALL. Building it and
// refusing at call time would still advertise it to the model, which turns a
// hard boundary into an argument the model is invited to have.
func TestToolsOmitDeniedCapabilities(t *testing.T) {
	tools, err := NewTools(policyAllowing(CapabilityExplainError), &stubDiagnostics{})
	if err != nil {
		t.Fatalf("build tools: %v", err)
	}
	want := []string{toolNamePrefix + "explain_error"}
	if got := toolNames(tools); !slices.Equal(got, want) {
		t.Fatalf("a policy allowing only explain_error built %v; want %v", got, want)
	}
}

// TestToolsRefuseWhenNothingAllowedIsImplemented covers the gap between the
// allow-list and the implementations directly. A policy that allows only
// capabilities with no builder must fail loudly, not hand back an assistant
// whose entire tool set is empty while its allow-list looks generous.
func TestToolsRefuseWhenNothingAllowedIsImplemented(t *testing.T) {
	policy := policyAllowing(
		CapabilityPrepareConnectorOnboarding,
		CapabilityValidateDraft,
		CapabilityProposeDiagnostics,
	)
	if _, err := NewTools(policy, &stubDiagnostics{}); err == nil {
		t.Fatal("NewTools succeeded with three allowed capabilities and no implementations")
	}
}

// TestToolsAreNamespaced keeps the prefix rule: a model that has been talked
// into calling something else names a tool that does not exist, which fails
// visibly instead of silently resolving to a neighbour's tool.
func TestToolsAreNamespaced(t *testing.T) {
	tools, err := NewTools(NewPolicy(), &stubDiagnostics{})
	if err != nil {
		t.Fatalf("build tools: %v", err)
	}
	for _, built := range tools {
		if !strings.HasPrefix(built.Name(), toolNamePrefix) {
			t.Errorf("tool %q is not namespaced under %q", built.Name(), toolNamePrefix)
		}
	}
}

// TestToolHandlersRefuseWithoutTenant: every tool runs on the ADK call path,
// where the tenant arrives only through context. A handler that ran without one
// would be operating on nobody's behalf.
func TestToolHandlersRefuseWithoutTenant(t *testing.T) {
	diagnostics := &stubDiagnostics{}
	if _, err := inspectHealthHandler(diagnostics)(context.Background(), inspectHealthArgs{}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("health handler without tenant = %v; want ErrNoTenant", err)
	}
	if diagnostics.healthCalls != 0 {
		t.Fatal("the deterministic service was reached without a tenant")
	}
}

// TestToolHandlersUseTheVerifiedTenant: the tenant a tool acts under must come
// from context, never from a model-supplied argument.
func TestToolHandlersUseTheVerifiedTenant(t *testing.T) {
	diagnostics := &stubDiagnostics{}
	ctx := WithTenant(context.Background(), "ent-real")
	if _, err := inspectHealthHandler(diagnostics)(ctx, inspectHealthArgs{}); err != nil {
		t.Fatalf("health handler: %v", err)
	}
	if diagnostics.lastTenant != "ent-real" {
		t.Fatalf("tool acted under tenant %q; want the verified ent-real", diagnostics.lastTenant)
	}
}

// TestToolsRequireDeterministicServices: the assistant may only state
// diagnostic facts a deterministic service produced. Without one there is
// nothing to ground an answer in, so construction fails rather than leaving the
// model free to invent.
func TestToolsRequireDeterministicServices(t *testing.T) {
	if _, err := NewTools(NewPolicy(), nil); err == nil {
		t.Fatal("tools built without a deterministic diagnostics service")
	}
}
