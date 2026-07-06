package policy

import "testing"

func TestEvaluatorDenyPath(t *testing.T) {
	evaluator := NewEvaluator(Policy{
		Rules: []Rule{{
			ResourceType: "knowledge_space",
			Action:       "read",
			Decision:     DecisionAllow,
			DataScope:    []string{"department:legal"},
			RiskLevel:    RiskLow,
		}},
	})

	result := evaluator.Evaluate(Request{
		ResourceType: "connector_resource",
		Action:       "write",
	})

	if result.Decision != DecisionDeny {
		t.Fatalf("Decision = %q, want %q", result.Decision, DecisionDeny)
	}
	if result.RiskLevel != RiskHigh {
		t.Fatalf("RiskLevel = %d, want %d", result.RiskLevel, RiskHigh)
	}
}

func TestEvaluatorMaskingPath(t *testing.T) {
	evaluator := NewEvaluator(Policy{
		Rules: []Rule{{
			ResourceType: "employee_profile",
			Action:       "read",
			Decision:     DecisionAllowWithMasking,
			DataScope:    []string{"department:legal"},
			MaskFields:   []string{"phone", "email"},
			RiskLevel:    RiskMedium,
		}},
	})

	result := evaluator.Evaluate(Request{
		ResourceType: "employee_profile",
		Action:       "read",
		Fields:       []string{"name", "phone"},
	})

	if result.Decision != DecisionAllowWithMasking {
		t.Fatalf("Decision = %q, want %q", result.Decision, DecisionAllowWithMasking)
	}
	if len(result.MaskFields) != 1 || result.MaskFields[0] != "phone" {
		t.Fatalf("MaskFields = %+v, want phone only", result.MaskFields)
	}
	if result.RiskLevel != RiskMedium {
		t.Fatalf("RiskLevel = %d, want %d", result.RiskLevel, RiskMedium)
	}
}
