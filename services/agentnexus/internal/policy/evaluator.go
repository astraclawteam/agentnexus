package policy

type Evaluator struct {
	policy Policy
}

func NewEvaluator(policy Policy) *Evaluator {
	return &Evaluator{policy: policy}
}

func (e *Evaluator) Evaluate(req Request) Result {
	for _, rule := range e.policy.Rules {
		if rule.ResourceType == req.ResourceType && rule.Action == req.Action {
			return Result{
				Decision:   rule.Decision,
				DataScope:  append([]string(nil), rule.DataScope...),
				MaskFields: calculateMaskFields(req.Fields, rule.MaskFields),
				RiskLevel:  riskLevel(rule.RiskLevel),
			}
		}
	}
	return Result{Decision: DecisionDeny, RiskLevel: RiskHigh}
}

func calculateMaskFields(requestedFields, maskFields []string) []string {
	maskSet := map[string]struct{}{}
	for _, field := range maskFields {
		maskSet[field] = struct{}{}
	}
	var result []string
	for _, field := range requestedFields {
		if _, ok := maskSet[field]; ok {
			result = append(result, field)
		}
	}
	return result
}

func riskLevel(value int) int {
	if value == 0 {
		return RiskMedium
	}
	return value
}
