package approval

import (
	"errors"
	"sort"
	"strings"
)

type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

type RiskReason string

const (
	RiskReasonPublishedBehaviorChange   RiskReason = "published_behavior_change"
	RiskReasonPermissionApprovalChange  RiskReason = "permission_approval_change"
	RiskReasonEvidenceRequirementChange RiskReason = "evidence_requirement_change"
	RiskReasonExecutionDeadlineChange   RiskReason = "execution_deadline_change"
	RiskReasonExternalSideEffect        RiskReason = "external_side_effect"
	RiskReasonEnterpriseMinimumRisk     RiskReason = "enterprise_minimum_risk"
	RiskReasonImpactedOrgScope          RiskReason = "impacted_org_scope"
	RiskReasonImpactedUserScope         RiskReason = "impacted_user_scope"
	RiskReasonRequestedRiskOverride     RiskReason = "requested_risk_override"
)

type RiskInput struct {
	ChangedFields           []string
	ImpactedOrgUnitIDs      []string
	ImpactedUserCount       int
	PublishedBehaviorChange bool
	ExternalSideEffect      bool
	RequestedRisk           RiskLevel
}

type Policy struct {
	MinimumRisk            RiskLevel
	MaxLowImpactedOrgUnits int
	MaxLowImpactedUsers    int
}

type RiskAssessment struct {
	Level   RiskLevel
	Reasons []RiskReason
}

func DefaultPolicy() Policy {
	return Policy{MinimumRisk: RiskLow, MaxLowImpactedOrgUnits: 1, MaxLowImpactedUsers: 25}
}

func ClassifyRisk(input RiskInput, policy Policy) (RiskAssessment, error) {
	if !validRisk(policy.MinimumRisk) || policy.MaxLowImpactedOrgUnits < 0 || policy.MaxLowImpactedUsers < 0 || input.ImpactedUserCount < 0 || (input.RequestedRisk != "" && !validRisk(input.RequestedRisk)) {
		return RiskAssessment{}, errors.New("invalid risk input")
	}
	if !canonicalUnique(input.ChangedFields) || !canonicalUnique(input.ImpactedOrgUnitIDs) {
		return RiskAssessment{}, errors.New("invalid risk input")
	}

	level := RiskLow
	reasons := map[RiskReason]struct{}{}
	forceHigh := func(reason RiskReason) {
		level = RiskHigh
		reasons[reason] = struct{}{}
	}
	if input.PublishedBehaviorChange {
		forceHigh(RiskReasonPublishedBehaviorChange)
	}
	for _, field := range input.ChangedFields {
		switch field {
		case "workflow_behavior", "sop_behavior":
			forceHigh(RiskReasonPublishedBehaviorChange)
		case "permissions", "approvals":
			forceHigh(RiskReasonPermissionApprovalChange)
		case "evidence_requirements":
			forceHigh(RiskReasonEvidenceRequirementChange)
		case "execution_deadline":
			forceHigh(RiskReasonExecutionDeadlineChange)
		}
	}
	if input.ExternalSideEffect {
		forceHigh(RiskReasonExternalSideEffect)
	}
	if len(input.ImpactedOrgUnitIDs) > policy.MaxLowImpactedOrgUnits {
		level = maxRisk(level, RiskMedium)
		reasons[RiskReasonImpactedOrgScope] = struct{}{}
	}
	if input.ImpactedUserCount > policy.MaxLowImpactedUsers {
		level = maxRisk(level, RiskMedium)
		reasons[RiskReasonImpactedUserScope] = struct{}{}
	}
	if riskRank(policy.MinimumRisk) > riskRank(level) {
		level = policy.MinimumRisk
		reasons[RiskReasonEnterpriseMinimumRisk] = struct{}{}
	}
	if input.RequestedRisk != "" && riskRank(input.RequestedRisk) > riskRank(level) {
		level = input.RequestedRisk
		reasons[RiskReasonRequestedRiskOverride] = struct{}{}
	}
	result := make([]RiskReason, 0, len(reasons))
	for reason := range reasons {
		result = append(result, reason)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return RiskAssessment{Level: level, Reasons: result}, nil
}

func validRisk(level RiskLevel) bool {
	return level == RiskLow || level == RiskMedium || level == RiskHigh
}

func maxRisk(left, right RiskLevel) RiskLevel {
	if riskRank(right) > riskRank(left) {
		return right
	}
	return left
}

func riskRank(level RiskLevel) int {
	switch level {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	default:
		return 0
	}
}

func canonicalUnique(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
