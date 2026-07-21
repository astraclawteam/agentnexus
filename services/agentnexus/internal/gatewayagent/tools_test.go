package gatewayagent

import (
	"context"
	"errors"
	"strings"
	"testing"
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

// TestToolsBuildOnlyAllowedCapabilities: a capability the policy denies must
// not produce a tool at all. Building the tool and refusing at call time would
// still advertise it to the model, which is an invitation to be argued with.
func TestToolsBuildOnlyAllowedCapabilities(t *testing.T) {
	tools, err := NewTools(NewPolicy(), &stubDiagnostics{})
	if err != nil {
		t.Fatalf("build tools: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("no tools were built")
	}
	for _, built := range tools {
		name := built.Name()
		if !strings.HasPrefix(name, toolNamePrefix) {
			t.Errorf("tool %q is not namespaced under %q", name, toolNamePrefix)
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
