package policy

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEvaluatorAllowsAdminBypassWhenEnforceAdminsDefaultFalse(t *testing.T) {
	evaluator := NewEvaluator(Policy{})

	result := evaluator.Evaluate(Request{
		ActorRoles:   []string{RoleAdmin},
		ResourceType: "connector_resource",
		Action:       "delete",
	})

	if result.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want %q", result.Decision, DecisionAllow)
	}
	if result.RiskLevel != RiskLow {
		t.Fatalf("RiskLevel = %d, want %d", result.RiskLevel, RiskLow)
	}
}

func TestEvaluatorEnforcesAdminsWhenConfiguredTrue(t *testing.T) {
	evaluator := NewEvaluator(Policy{EnforceAdmins: true})

	result := evaluator.Evaluate(Request{
		ActorRoles:   []string{RoleAdmin},
		ResourceType: "connector_resource",
		Action:       "delete",
	})

	if result.Decision != DecisionDeny {
		t.Fatalf("Decision = %q, want %q", result.Decision, DecisionDeny)
	}
	if result.RiskLevel != RiskHigh {
		t.Fatalf("RiskLevel = %d, want %d", result.RiskLevel, RiskHigh)
	}
}

func TestEvaluatorAllowsAdminBypassFromYAMLEnforceAdminsFalse(t *testing.T) {
	var parsed Policy
	if err := yaml.Unmarshal([]byte(`
enforce_admins: false
rules: []
`), &parsed); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	result := NewEvaluator(parsed).Evaluate(Request{
		ActorRoles:   []string{RoleAdmin},
		ResourceType: "connector_resource",
		Action:       "delete",
	})

	if result.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want %q", result.Decision, DecisionAllow)
	}
}

func TestEvaluatorEnforcesAdminsFromYAMLEnforceAdminsTrue(t *testing.T) {
	var parsed Policy
	if err := yaml.Unmarshal([]byte(`
enforce_admins: true
rules: []
`), &parsed); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	result := NewEvaluator(parsed).Evaluate(Request{
		ActorRoles:   []string{RoleAdmin},
		ResourceType: "connector_resource",
		Action:       "delete",
	})

	if result.Decision != DecisionDeny {
		t.Fatalf("Decision = %q, want %q", result.Decision, DecisionDeny)
	}
}
