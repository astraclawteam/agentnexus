package app

import (
	"context"
	"errors"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

type fakeGrantOwner struct {
	owner GrantResourceOwner
	err   error
}

func (f fakeGrantOwner) ResolveGrantResourceOwner(context.Context, string, string, string) (GrantResourceOwner, error) {
	return f.owner, f.err
}

type fakeGrantEvaluator struct {
	request  policy.ScopedRequest
	decision policy.PermissionDecision
	err      error
}

func (f *fakeGrantEvaluator) Evaluate(_ context.Context, request policy.ScopedRequest) (policy.PermissionDecision, error) {
	f.request = request
	return f.decision, f.err
}

func TestScopedGrantAuthorizerUsesCurrentDreamEvidenceDecisionAndOwnership(t *testing.T) {
	evaluator := &fakeGrantEvaluator{decision: policy.PermissionDecision{Decision: policy.DecisionAllow, Permissions: []policy.AtlasPermission{policy.PermissionApproveHighRisk}, OrgVersion: 7, OrgUnitIDs: []string{"research"}, MaskFields: []string{}, RiskLevel: policy.AtlasRiskHigh}}
	authorizer := NewScopedGrantAuthorizer(fakeGrantOwner{owner: GrantResourceOwner{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgUnitID: "research", OrgVersion: 7}}, evaluator)
	decision, err := authorizer.AuthorizeGrant(context.Background(), tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1"}, tickets.CreateStepGrantInput{OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("decision=%+v", decision)
	}
	if evaluator.request.ResourceType != policy.ResourceDreamEvidence || evaluator.request.Action != policy.ActionDreamEvidenceRead {
		t.Fatalf("request=%+v", evaluator.request)
	}
}

func TestScopedGrantAuthorizerFailsClosedOnOwnershipOrPolicyMismatch(t *testing.T) {
	baseOwner := GrantResourceOwner{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgUnitID: "research", OrgVersion: 7}
	input := tickets.CreateStepGrantInput{OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read"}
	for _, tc := range []struct {
		name     string
		owner    fakeGrantOwner
		decision policy.PermissionDecision
	}{
		{name: "owner unavailable", owner: fakeGrantOwner{err: errors.New("down")}},
		{name: "wrong owner", owner: fakeGrantOwner{owner: func() GrantResourceOwner { v := baseOwner; v.EnterpriseID = "ent_2"; return v }()}},
		{name: "policy denied", owner: fakeGrantOwner{owner: baseOwner}, decision: policy.PermissionDecision{Decision: policy.DecisionDeny, OrgVersion: 7}},
		{name: "stale policy", owner: fakeGrantOwner{owner: baseOwner}, decision: policy.PermissionDecision{Decision: policy.DecisionAllow, OrgVersion: 6, OrgUnitIDs: []string{"research"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := NewScopedGrantAuthorizer(tc.owner, &fakeGrantEvaluator{decision: tc.decision})
			decision, err := authorizer.AuthorizeGrant(context.Background(), tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1"}, input)
			if err == nil && decision.Allowed {
				t.Fatalf("allowed=%+v err=%v", decision, err)
			}
		})
	}
}

func TestScopedGrantAuthorizerRejectsMalformedAllowDecision(t *testing.T) {
	owner := fakeGrantOwner{owner: GrantResourceOwner{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgUnitID: "research", OrgVersion: 7}}
	input := tickets.CreateStepGrantInput{OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read"}
	actor := tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1"}
	base := policy.PermissionDecision{Decision: policy.DecisionAllow, Permissions: []policy.AtlasPermission{policy.PermissionApproveHighRisk}, OrgUnitIDs: []string{"research"}, MaskFields: []string{}, RiskLevel: policy.AtlasRiskHigh, OrgVersion: 7}
	for _, tc := range []struct {
		name   string
		mutate func(*policy.PermissionDecision)
	}{
		{"empty permission", func(d *policy.PermissionDecision) { d.Permissions = []policy.AtlasPermission{} }},
		{"wrong permission", func(d *policy.PermissionDecision) { d.Permissions = []policy.AtlasPermission{policy.PermissionEdit} }},
		{"extra permission", func(d *policy.PermissionDecision) { d.Permissions = append(d.Permissions, policy.PermissionEdit) }},
		{"wrong risk", func(d *policy.PermissionDecision) { d.RiskLevel = policy.AtlasRiskLow }},
		{"fallback", func(d *policy.PermissionDecision) { d.FallbackAction = policy.ActionKnowledgeSuggest }},
		{"masking", func(d *policy.PermissionDecision) { d.MaskFields = []string{"secret"} }},
		{"extra scope", func(d *policy.PermissionDecision) { d.OrgUnitIDs = []string{"research", "root"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := base
			decision.Permissions = append([]policy.AtlasPermission(nil), base.Permissions...)
			decision.OrgUnitIDs = append([]string(nil), base.OrgUnitIDs...)
			decision.MaskFields = append([]string(nil), base.MaskFields...)
			tc.mutate(&decision)
			auth := NewScopedGrantAuthorizer(owner, &fakeGrantEvaluator{decision: decision})
			got, err := auth.AuthorizeGrant(context.Background(), actor, input)
			if err == nil && got.Allowed {
				t.Fatalf("allowed malformed decision=%+v", decision)
			}
		})
	}
}
