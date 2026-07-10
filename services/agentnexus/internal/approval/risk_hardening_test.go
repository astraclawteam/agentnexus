package approval

import "testing"

func TestClassifyVerifiedRiskUsesClosedActionBaselineAndUnverifiedFactsForceHigh(t *testing.T) {
	verified := NewVerifiedChangeFacts(VerifiedChangeFactsInput{ChangedFields: []string{"title"}, ImpactedOrgUnitIDs: []string{"team"}, ImpactedUserCount: 1})
	assessment, err := ClassifyVerifiedRisk(verified, RiskLow, "workflow", "workflow.edit", DefaultPolicy())
	if err != nil || assessment.Level != RiskMedium {
		t.Fatalf("assessment=%+v err=%v", assessment, err)
	}
	unverified := NewUnverifiedChangeFacts(RiskReasonUnverifiedChangeFacts)
	assessment, err = ClassifyVerifiedRisk(unverified, RiskLow, "knowledge", "knowledge.publish_low_risk", DefaultPolicy())
	if err != nil || assessment.Level != RiskHigh || !containsReason(assessment.Reasons, RiskReasonUnverifiedChangeFacts) {
		t.Fatalf("assessment=%+v err=%v", assessment, err)
	}
}

func TestClassifyVerifiedRiskUnknownFieldAndActionForceHigh(t *testing.T) {
	facts := NewVerifiedChangeFacts(VerifiedChangeFactsInput{ChangedFields: []string{"future_behavior"}})
	assessment, err := ClassifyVerifiedRisk(facts, RiskLow, "knowledge", "knowledge.publish_low_risk", DefaultPolicy())
	if err != nil || assessment.Level != RiskHigh || !containsReason(assessment.Reasons, RiskReasonUnknownChangedField) {
		t.Fatalf("assessment=%+v err=%v", assessment, err)
	}
	assessment, err = ClassifyVerifiedRisk(NewVerifiedChangeFacts(VerifiedChangeFactsInput{}), RiskLow, "workflow", "knowledge.publish_low_risk", DefaultPolicy())
	if err != nil || assessment.Level != RiskHigh || !containsReason(assessment.Reasons, RiskReasonUnknownAction) {
		t.Fatalf("assessment=%+v err=%v", assessment, err)
	}
}
