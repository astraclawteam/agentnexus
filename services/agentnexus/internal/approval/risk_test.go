package approval

import (
	"reflect"
	"testing"
)

func TestClassifyRiskForcesHighForGovernedChanges(t *testing.T) {
	tests := []struct {
		name   string
		input  RiskInput
		reason RiskReason
	}{
		{name: "published behavior", input: RiskInput{PublishedBehaviorChange: true}, reason: RiskReasonPublishedBehaviorChange},
		{name: "published workflow behavior field", input: RiskInput{ChangedFields: []string{"workflow_behavior"}}, reason: RiskReasonPublishedBehaviorChange},
		{name: "published sop behavior field", input: RiskInput{ChangedFields: []string{"sop_behavior"}}, reason: RiskReasonPublishedBehaviorChange},
		{name: "permission", input: RiskInput{ChangedFields: []string{"permissions"}}, reason: RiskReasonPermissionApprovalChange},
		{name: "approval", input: RiskInput{ChangedFields: []string{"approvals"}}, reason: RiskReasonPermissionApprovalChange},
		{name: "evidence", input: RiskInput{ChangedFields: []string{"evidence_requirements"}}, reason: RiskReasonEvidenceRequirementChange},
		{name: "deadline", input: RiskInput{ChangedFields: []string{"execution_deadline"}}, reason: RiskReasonExecutionDeadlineChange},
		{name: "external side effect", input: RiskInput{ExternalSideEffect: true}, reason: RiskReasonExternalSideEffect},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ClassifyRisk(tt.input, DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if got.Level != RiskHigh || !containsReason(got.Reasons, tt.reason) {
				t.Fatalf("assessment=%+v, want high with %q", got, tt.reason)
			}
		})
	}
}

func TestClassifyRiskOnlyRaisesRequestedAndEnterpriseRisk(t *testing.T) {
	high, err := ClassifyRisk(RiskInput{ExternalSideEffect: true, RequestedRisk: RiskLow}, DefaultPolicy())
	if err != nil || high.Level != RiskHigh {
		t.Fatalf("lower override changed high: assessment=%+v err=%v", high, err)
	}
	raised, err := ClassifyRisk(RiskInput{RequestedRisk: RiskHigh}, DefaultPolicy())
	if err != nil || raised.Level != RiskHigh || !containsReason(raised.Reasons, RiskReasonRequestedRiskOverride) {
		t.Fatalf("higher override not applied: assessment=%+v err=%v", raised, err)
	}
	minimum, err := ClassifyRisk(RiskInput{}, Policy{MinimumRisk: RiskMedium, MaxLowImpactedOrgUnits: 1, MaxLowImpactedUsers: 25})
	if err != nil || minimum.Level != RiskMedium || !containsReason(minimum.Reasons, RiskReasonEnterpriseMinimumRisk) {
		t.Fatalf("minimum not applied: assessment=%+v err=%v", minimum, err)
	}
}

func TestClassifyRiskRaisesForConfiguredImpactThresholds(t *testing.T) {
	policy := DefaultPolicy()
	orgs, err := ClassifyRisk(RiskInput{ImpactedOrgUnitIDs: []string{"org-b", "org-a"}}, policy)
	if err != nil || orgs.Level != RiskMedium || !reflect.DeepEqual(orgs.Reasons, []RiskReason{RiskReasonImpactedOrgScope}) {
		t.Fatalf("org assessment=%+v err=%v", orgs, err)
	}
	users, err := ClassifyRisk(RiskInput{ImpactedUserCount: 26}, policy)
	if err != nil || users.Level != RiskMedium || !reflect.DeepEqual(users.Reasons, []RiskReason{RiskReasonImpactedUserScope}) {
		t.Fatalf("user assessment=%+v err=%v", users, err)
	}
}

func TestClassifyRiskProducesStableUniqueNonNilReasons(t *testing.T) {
	got, err := ClassifyRisk(RiskInput{ChangedFields: []string{"approvals", "permissions"}, ImpactedOrgUnitIDs: []string{"org-b", "org-a"}, ExternalSideEffect: true}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	want := []RiskReason{RiskReasonExternalSideEffect, RiskReasonImpactedOrgScope, RiskReasonPermissionApprovalChange}
	if !reflect.DeepEqual(got.Reasons, want) {
		t.Fatalf("reasons=%v want=%v", got.Reasons, want)
	}
	empty, err := ClassifyRisk(RiskInput{}, DefaultPolicy())
	if err != nil || empty.Reasons == nil || len(empty.Reasons) != 0 {
		t.Fatalf("empty reasons=%#v err=%v", empty.Reasons, err)
	}
}

func containsReason(values []RiskReason, want RiskReason) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
