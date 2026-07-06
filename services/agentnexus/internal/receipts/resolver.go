package receipts

func ResolveTarget(candidates []Target) (Target, bool) {
	priorities := []TargetSource{
		TargetSourceExternalSource,
		TargetSourceConnectorConfig,
		TargetSourcePolicyOrgRule,
		TargetSourceUserSelection,
	}
	for _, source := range priorities {
		for _, candidate := range candidates {
			if candidate.Source == source && candidate.Address != "" {
				return candidate, true
			}
		}
	}
	return Target{}, false
}
