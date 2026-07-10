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
	RiskReasonUnverifiedChangeFacts     RiskReason = "unverified_change_facts"
	RiskReasonUnknownChangedField       RiskReason = "unknown_changed_field"
	RiskReasonUnknownAction             RiskReason = "unknown_action"
	RiskReasonActionBaseline            RiskReason = "action_baseline"
	RiskReasonExplicitReviewRequired    RiskReason = "explicit_review_required"
	RiskReasonExplicitConfirmation      RiskReason = "explicit_confirmation_required"
)

type VerifiedChangeFactsInput struct {
	ChangedFields           []string
	ImpactedOrgUnitIDs      []string
	ImpactedUserCount       int
	PublishedBehaviorChange bool
	ExternalSideEffect      bool
	Digest                  string
}

type VerifiedChangeFacts struct {
	input  VerifiedChangeFactsInput
	reason RiskReason
}

func NewVerifiedChangeFacts(input VerifiedChangeFactsInput) VerifiedChangeFacts {
	input.ChangedFields = append([]string{}, input.ChangedFields...)
	input.ImpactedOrgUnitIDs = append([]string{}, input.ImpactedOrgUnitIDs...)
	if input.ImpactedUserCount < 0 || !canonicalUnique(input.ChangedFields) || !canonicalUnique(input.ImpactedOrgUnitIDs) {
		return NewUnverifiedChangeFacts(RiskReasonUnverifiedChangeFacts)
	}
	return VerifiedChangeFacts{input: input}
}

func NewUnverifiedChangeFacts(reason RiskReason) VerifiedChangeFacts {
	if reason != RiskReasonUnknownChangedField {
		reason = RiskReasonUnverifiedChangeFacts
	}
	return VerifiedChangeFacts{input: VerifiedChangeFactsInput{ChangedFields: []string{}, ImpactedOrgUnitIDs: []string{}}, reason: reason}
}

func (f VerifiedChangeFacts) Digest() string { return f.input.Digest }
func (f VerifiedChangeFacts) ImpactedOrgUnitIDs() []string {
	return append([]string{}, f.input.ImpactedOrgUnitIDs...)
}

var knownChangedFields = map[string]struct{}{
	"title": {}, "description": {}, "content": {}, "workflow_behavior": {}, "sop_behavior": {},
	"permissions": {}, "approvals": {}, "evidence_requirements": {}, "execution_deadline": {},
}

func ClassifyVerifiedRisk(facts VerifiedChangeFacts, requested RiskLevel, resourceType, action string, policy Policy) (RiskAssessment, error) {
	baseline, known := approvalActionBaseline(resourceType, action)
	if !known {
		return RiskAssessment{Level: RiskHigh, Reasons: []RiskReason{RiskReasonUnknownAction}}, nil
	}
	if facts.reason != "" {
		return RiskAssessment{Level: RiskHigh, Reasons: []RiskReason{facts.reason}}, nil
	}
	for _, field := range facts.input.ChangedFields {
		if _, exists := knownChangedFields[field]; !exists {
			return RiskAssessment{Level: RiskHigh, Reasons: []RiskReason{RiskReasonUnknownChangedField}}, nil
		}
	}
	assessment, err := classifyRiskFacts(riskFactsInput{ChangedFields: facts.input.ChangedFields, ImpactedOrgUnitIDs: facts.input.ImpactedOrgUnitIDs, ImpactedUserCount: facts.input.ImpactedUserCount, PublishedBehaviorChange: facts.input.PublishedBehaviorChange, ExternalSideEffect: facts.input.ExternalSideEffect, RequestedRisk: requested}, policy)
	if err != nil {
		return RiskAssessment{}, err
	}
	if riskRank(baseline) > riskRank(assessment.Level) {
		assessment.Level = baseline
		assessment.Reasons = append(assessment.Reasons, RiskReasonActionBaseline)
		sort.Slice(assessment.Reasons, func(i, j int) bool { return assessment.Reasons[i] < assessment.Reasons[j] })
	}
	return assessment, nil
}

func approvalActionBaseline(resourceType, action string) (RiskLevel, bool) {
	switch resourceType + "\x00" + action {
	case "knowledge\x00knowledge.suggest", "knowledge\x00knowledge.publish_low_risk", "workflow\x00workflow.publish_low_risk":
		return RiskLow, true
	case "knowledge\x00knowledge.create", "knowledge\x00knowledge.update", "workflow\x00workflow.edit":
		return RiskMedium, true
	case "knowledge\x00knowledge.approve_high_risk", "workflow\x00workflow.edit_advanced", "workflow\x00workflow.approve_high_risk", "service\x00service.mode":
		return RiskHigh, true
	default:
		return RiskHigh, false
	}
}

type riskFactsInput struct {
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

func classifyRiskFacts(input riskFactsInput, policy Policy) (RiskAssessment, error) {
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
