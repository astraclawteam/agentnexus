package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

func TestScopedGrantAuthorizerAcceptsInheritedDreamPermissionWithoutInheritingEvidenceScopes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		memberships []policy.SealedMembership
	}{
		{"parent covers child", []policy.SealedMembership{{OrgUnitID: "parent", Role: string(policy.PermissionApproveHighRisk)}}},
		{"multiple covering scopes", []policy.SealedMembership{{OrgUnitID: "root", Role: string(policy.PermissionApproveHighRisk)}, {OrgUnitID: "parent", Role: string(policy.PermissionApproveHighRisk)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := policy.NewMemorySnapshotSource()
			source.StoreSnapshot("ent_1", "user_1", policy.SealedAccessSnapshot{TenantRef: "ent_1", OrgVersion: 7, OrgUnits: []policy.SealedOrgUnit{{ID: "root"}, {ID: "parent", ParentID: "root"}, {ID: "child", ParentID: "parent"}}, Memberships: tc.memberships})
			authorizer := NewScopedGrantAuthorizer(fakeGrantOwner{owner: GrantResourceOwner{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgUnitID: "child", OrgVersion: 7}}, policy.NewCapabilityEvaluator(source))
			store := tickets.NewMemoryStore()
			ids := []string{"grant_1", "audit_1"}
			i := 0
			svc := tickets.NewService(store, tickets.WithClock(func() time.Time { return time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC) }), tickets.WithIDGenerator(func() string { v := ids[i]; i++; return v }), tickets.WithTokenGenerator(func() (string, error) { return "opaque-step-grant-token", nil }), tickets.WithGrantAuthorizer(authorizer))
			grant, err := svc.AuthorizeAndCreateGrant(context.Background(), tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1", OrgVersion: 7}, tickets.CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			if grant.OrgUnitID != "child" || grant.ResourceID != "ev-1" || len(grant.Scopes) != 1 || grant.Scopes[0] != "dream:evidence:read" {
				t.Fatalf("grant inherited decision evidence instead of target binding: %+v", grant)
			}
		})
	}
}

type fakeGrantOwner struct {
	owner GrantResourceOwner
	err   error
}

func (f fakeGrantOwner) ResolveGrantResourceOwner(context.Context, string, string, string) (GrantResourceOwner, error) {
	return f.owner, f.err
}

type fakeGrantEvaluator struct {
	request  policy.CapabilityRequest
	decision policy.PermissionDecision
	err      error
}

func (f *fakeGrantEvaluator) Evaluate(_ context.Context, request policy.CapabilityRequest) (policy.PermissionDecision, error) {
	f.request = request
	return f.decision, f.err
}

func TestScopedGrantAuthorizerUsesCurrentDreamEvidenceDecisionAndOwnership(t *testing.T) {
	evaluator := &fakeGrantEvaluator{decision: policy.PermissionDecision{Decision: policy.DecisionAllow, Permissions: []policy.PrincipalPermission{policy.PermissionApproveHighRisk}, OrgVersion: 7, OrgUnitIDs: []string{"research"}, MaskFields: []string{}, RiskLevel: policy.CapabilityRiskHigh}}
	authorizer := NewScopedGrantAuthorizer(fakeGrantOwner{owner: GrantResourceOwner{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgUnitID: "research", OrgVersion: 7}}, evaluator)
	decision, err := authorizer.AuthorizeGrant(context.Background(), tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1", OrgVersion: 7}, tickets.CreateStepGrantInput{ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.OrgUnitID != "research" || decision.OrgVersion != 7 {
		t.Fatalf("decision=%+v", decision)
	}
	if evaluator.request.ResourceType != policy.ResourceDreamEvidence || evaluator.request.Capability != policy.CapabilityEvidenceRead || evaluator.request.TargetOrgUnitID != "research" || evaluator.request.SealedOrgVersion != 7 {
		t.Fatalf("request=%+v", evaluator.request)
	}
}

func TestScopedGrantAuthorizerFailsClosedOnOwnershipOrPolicyMismatch(t *testing.T) {
	baseOwner := GrantResourceOwner{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgUnitID: "research", OrgVersion: 7}
	input := tickets.CreateStepGrantInput{ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read"}
	for _, tc := range []struct {
		name     string
		owner    fakeGrantOwner
		decision policy.PermissionDecision
	}{
		{name: "owner unavailable", owner: fakeGrantOwner{err: errors.New("down")}},
		{name: "wrong owner", owner: fakeGrantOwner{owner: func() GrantResourceOwner { v := baseOwner; v.EnterpriseID = "ent_2"; return v }()}},
		{name: "owner at different sealed version", owner: fakeGrantOwner{owner: func() GrantResourceOwner { v := baseOwner; v.OrgVersion = 6; return v }()}},
		{name: "policy denied", owner: fakeGrantOwner{owner: baseOwner}, decision: policy.PermissionDecision{Decision: policy.DecisionDeny, OrgVersion: 7}},
		{name: "stale policy", owner: fakeGrantOwner{owner: baseOwner}, decision: policy.PermissionDecision{Decision: policy.DecisionAllow, OrgVersion: 6, OrgUnitIDs: []string{"research"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := NewScopedGrantAuthorizer(tc.owner, &fakeGrantEvaluator{decision: tc.decision})
			decision, err := authorizer.AuthorizeGrant(context.Background(), tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1", OrgVersion: 7}, input)
			if err == nil && decision.Allowed {
				t.Fatalf("allowed=%+v err=%v", decision, err)
			}
		})
	}
}

func TestScopedGrantAuthorizerRejectsMalformedAllowDecision(t *testing.T) {
	owner := fakeGrantOwner{owner: GrantResourceOwner{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgUnitID: "research", OrgVersion: 7}}
	input := tickets.CreateStepGrantInput{ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read"}
	actor := tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1", OrgVersion: 7}
	base := policy.PermissionDecision{Decision: policy.DecisionAllow, Permissions: []policy.PrincipalPermission{policy.PermissionApproveHighRisk}, OrgUnitIDs: []string{"research"}, MaskFields: []string{}, RiskLevel: policy.CapabilityRiskHigh, OrgVersion: 7}
	for _, tc := range []struct {
		name   string
		mutate func(*policy.PermissionDecision)
	}{
		{"empty permission", func(d *policy.PermissionDecision) { d.Permissions = []policy.PrincipalPermission{} }},
		{"wrong permission", func(d *policy.PermissionDecision) {
			d.Permissions = []policy.PrincipalPermission{policy.PermissionEdit}
		}},
		{"extra permission", func(d *policy.PermissionDecision) { d.Permissions = append(d.Permissions, policy.PermissionEdit) }},
		{"wrong risk", func(d *policy.PermissionDecision) { d.RiskLevel = policy.CapabilityRiskLow }},
		{"fallback", func(d *policy.PermissionDecision) { d.FallbackCapability = policy.CapabilityKnowledgeSuggest }},
		{"masking", func(d *policy.PermissionDecision) { d.MaskFields = []string{"secret"} }},
		{"empty scopes", func(d *policy.PermissionDecision) { d.OrgUnitIDs = []string{} }},
		{"duplicate scopes", func(d *policy.PermissionDecision) { d.OrgUnitIDs = []string{"research", "research"} }},
		{"noncanonical scope", func(d *policy.PermissionDecision) { d.OrgUnitIDs = []string{" research"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision := base
			decision.Permissions = append([]policy.PrincipalPermission(nil), base.Permissions...)
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
