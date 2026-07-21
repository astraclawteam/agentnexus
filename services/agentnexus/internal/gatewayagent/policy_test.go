package gatewayagent

import (
	"errors"
	"testing"
)

// TestPolicyAllowsExactlyTheDeclaredCapabilities pins the allow-list to the
// five capabilities GA Task 13 grants the operations assistant. Widening it is
// a deliberate act that must fail this test first.
func TestPolicyAllowsExactlyTheDeclaredCapabilities(t *testing.T) {
	want := []ToolCapability{
		CapabilityInspectHealth,
		CapabilityExplainError,
		CapabilityPrepareConnectorOnboarding,
		CapabilityValidateDraft,
		CapabilityProposeDiagnostics,
	}
	if len(AllowedCapabilities) != len(want) {
		t.Fatalf("allow-list has %d capabilities, want exactly %d: %v", len(AllowedCapabilities), len(want), AllowedCapabilities)
	}
	policy := NewPolicy()
	for _, capability := range want {
		if err := policy.Allow(capability); err != nil {
			t.Errorf("declared capability %q denied: %v", capability, err)
		}
	}
}

// TestPolicyDefaultDenies is the important direction. A capability nobody
// thought about must be refused, not permitted: an assistant that gains reach
// by default is exactly the failure this boundary exists to prevent.
func TestPolicyDefaultDenies(t *testing.T) {
	policy := NewPolicy()
	for _, unknown := range []ToolCapability{"", "read_everything", "inspect_health_v2", "INSPECT_HEALTH"} {
		if err := policy.Allow(unknown); !errors.Is(err, ErrCapabilityDenied) {
			t.Errorf("unknown capability %q returned %v; want ErrCapabilityDenied", unknown, err)
		}
	}
}

// TestPolicyDeniesForbiddenIntents names each thing the assistant must never
// do. These are listed explicitly rather than relying on default-deny so the
// refusal is documented, greppable, and survives a careless allow-list edit.
func TestPolicyDeniesForbiddenIntents(t *testing.T) {
	policy := NewPolicy()
	for _, forbidden := range []ToolCapability{
		"decide_domain_risk",
		"choose_approvers",
		"issue_grant",
		"execute_action",
		"read_business_data",
		"change_policy",
		"install_package",
		"read_secret",
	} {
		if err := policy.Allow(forbidden); !errors.Is(err, ErrCapabilityDenied) {
			t.Errorf("forbidden intent %q returned %v; want ErrCapabilityDenied", forbidden, err)
		}
	}
}

// TestForbiddenIntentsAreNotAllowable guards against the two lists drifting
// into agreement: a capability may never appear on both.
func TestForbiddenIntentsAreNotAllowable(t *testing.T) {
	allowed := map[ToolCapability]bool{}
	for _, capability := range AllowedCapabilities {
		allowed[capability] = true
	}
	for _, forbidden := range ForbiddenIntents {
		if allowed[forbidden] {
			t.Errorf("%q is on both the allow-list and the forbidden list", forbidden)
		}
	}
	if len(ForbiddenIntents) == 0 {
		t.Fatal("the forbidden list is empty; the refusals must stay documented in code")
	}
}

// TestPolicyBoundsToolUse covers the caps GA Task 13 requires. An assistant
// that can call tools without limit can be driven into a loop by hostile
// connector metadata, which is one of the named eval cases.
func TestPolicyBoundsToolUse(t *testing.T) {
	policy := NewPolicy()
	if policy.MaxToolCalls() <= 0 {
		t.Fatal("tool calls must be bounded")
	}
	if policy.MaxOutputBytes() <= 0 {
		t.Fatal("output must be bounded")
	}
	if policy.Timeout() <= 0 {
		t.Fatal("a turn must be time-bounded")
	}
}
