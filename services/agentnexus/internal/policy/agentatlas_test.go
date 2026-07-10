package policy

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestAgentAtlasVocabulary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		resourceType ResourceType
		action       AtlasAction
		permission   AtlasPermission
		risk         AtlasRiskLevel
	}{
		{name: "suggest", resourceType: ResourceKnowledge, action: ActionKnowledgeSuggest, permission: PermissionSuggest, risk: AtlasRiskLow},
		{name: "create", resourceType: ResourceKnowledge, action: ActionKnowledgeCreate, permission: PermissionEdit, risk: AtlasRiskMedium},
		{name: "update", resourceType: ResourceKnowledge, action: ActionKnowledgeUpdate, permission: PermissionEdit, risk: AtlasRiskMedium},
		{name: "publish low risk", resourceType: ResourceKnowledge, action: ActionKnowledgePublishLowRisk, permission: PermissionPublishLowRisk, risk: AtlasRiskLow},
		{name: "approve high risk", resourceType: ResourceKnowledge, action: ActionKnowledgeApproveHighRisk, permission: PermissionApproveHighRisk, risk: AtlasRiskHigh},
		{name: "workflow edit", resourceType: ResourceWorkflow, action: ActionWorkflowEdit, permission: PermissionWorkflowEdit, risk: AtlasRiskMedium},
		{name: "workflow advanced", resourceType: ResourceWorkflow, action: ActionWorkflowEditAdvanced, permission: PermissionWorkflowAdvanced, risk: AtlasRiskHigh},
		{name: "service mode", resourceType: ResourceService, action: ActionServiceMode, permission: PermissionServiceMode, risk: AtlasRiskHigh},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			permission, risk, ok := RequiredPermission(test.resourceType, test.action)
			if !ok {
				t.Fatal("known action/resource pair was rejected")
			}
			if permission != test.permission {
				t.Fatalf("permission = %q, want %q", permission, test.permission)
			}
			if risk != test.risk {
				t.Fatalf("risk = %q, want %q", risk, test.risk)
			}
		})
	}
}

func TestAgentAtlasActionRequiresMatchingResourceType(t *testing.T) {
	t.Parallel()

	for action, requirement := range actionRequirements {
		for _, resourceType := range []ResourceType{ResourceKnowledge, ResourceWorkflow, ResourceService} {
			if resourceType == requirement.resourceType {
				continue
			}
			if _, _, ok := RequiredPermission(resourceType, action); ok {
				t.Fatalf("action %q was accepted for mismatched resource %q", action, resourceType)
			}
		}
	}
	if _, _, ok := RequiredPermission(ResourceType("unknown"), ActionWorkflowEdit); ok {
		t.Fatal("unknown resource type was accepted")
	}
	if _, _, ok := RequiredPermission("", ActionWorkflowEdit); ok {
		t.Fatal("empty resource type was accepted")
	}
	if _, _, ok := RequiredPermission(ResourceKnowledge, AtlasAction("unknown")); ok {
		t.Fatal("unknown action was accepted")
	}
	if _, _, ok := RequiredPermission(ResourceKnowledge, ""); ok {
		t.Fatal("empty action was accepted")
	}
}

type stubAtlasPolicySource struct {
	snapshot AtlasAccessSnapshot
	err      error
}

func (s stubAtlasPolicySource) LoadAccessSnapshot(context.Context, string, string) (AtlasAccessSnapshot, error) {
	return s.snapshot, s.err
}

func TestAgentAtlasScopedEvaluation(t *testing.T) {
	t.Parallel()

	base := AtlasAccessSnapshot{
		EnterpriseID: "enterprise-1",
		OrgVersion:   42,
		OrgUnits: []AtlasOrgUnit{
			{ID: "dept-child", ParentID: "dept-parent"},
			{ID: "dept-other"},
			{ID: "dept-parent"},
		},
		Memberships: []AtlasMembership{
			{OrgUnitID: "dept-parent", Role: string(PermissionEdit)},
			{OrgUnitID: "dept-parent", Role: string(PermissionSuggest)},
			{OrgUnitID: "dept-child", Role: string(PermissionWorkflowAdvanced)},
			{OrgUnitID: "dept-child", Role: string(PermissionServiceMode)},
		},
	}

	tests := []struct {
		name            string
		mutateSnapshot  func(*AtlasAccessSnapshot)
		mutateRequest   func(*ScopedRequest)
		wantDecision    Decision
		wantPermissions []AtlasPermission
		wantScopes      []string
		wantFallback    AtlasAction
	}{
		{name: "same org allow", wantDecision: DecisionAllow, wantPermissions: []AtlasPermission{PermissionEdit}, wantScopes: []string{"dept-parent"}},
		{name: "parent covers child", mutateRequest: func(r *ScopedRequest) { r.OrgUnitID = "dept-child" }, wantDecision: DecisionAllow, wantPermissions: []AtlasPermission{PermissionEdit}, wantScopes: []string{"dept-parent"}},
		{name: "child does not cover parent", mutateSnapshot: func(s *AtlasAccessSnapshot) {
			s.Memberships = []AtlasMembership{{OrgUnitID: "dept-child", Role: string(PermissionEdit)}}
		}, wantDecision: DecisionDeny},
		{name: "stale version", mutateRequest: func(r *ScopedRequest) { r.OrgVersion = 41 }, wantDecision: DecisionDeny},
		{name: "future version", mutateRequest: func(r *ScopedRequest) { r.OrgVersion = 43 }, wantDecision: DecisionDeny},
		{name: "missing version", mutateRequest: func(r *ScopedRequest) { r.OrgVersion = 0 }, wantDecision: DecisionDeny},
		{name: "empty org", mutateRequest: func(r *ScopedRequest) { r.OrgUnitID = "" }, wantDecision: DecisionDeny},
		{name: "empty resource id", mutateRequest: func(r *ScopedRequest) { r.ResourceID = "" }, wantDecision: DecisionDeny},
		{name: "unknown org resource", mutateRequest: func(r *ScopedRequest) { r.OrgUnitID = "dept-missing" }, wantDecision: DecisionDeny},
		{name: "unknown action", mutateRequest: func(r *ScopedRequest) { r.Action = "unknown" }, wantDecision: DecisionDeny},
		{name: "mismatched action resource", mutateRequest: func(r *ScopedRequest) { r.ResourceType = ResourceWorkflow }, wantDecision: DecisionDeny},
		{name: "malformed graph missing parent", mutateSnapshot: func(s *AtlasAccessSnapshot) { s.OrgUnits[0].ParentID = "missing" }, mutateRequest: func(r *ScopedRequest) { r.OrgUnitID = "dept-child" }, wantDecision: DecisionDeny},
		{name: "malformed graph cycle", mutateSnapshot: func(s *AtlasAccessSnapshot) { s.OrgUnits[2].ParentID = "dept-child" }, mutateRequest: func(r *ScopedRequest) { r.OrgUnitID = "dept-child" }, wantDecision: DecisionDeny},
		{name: "update deny falls back to scoped suggest", mutateSnapshot: func(s *AtlasAccessSnapshot) {
			s.Memberships = []AtlasMembership{{OrgUnitID: "dept-child", Role: string(PermissionSuggest)}, {OrgUnitID: "dept-parent", Role: string(PermissionSuggest)}}
		}, mutateRequest: func(r *ScopedRequest) { r.OrgUnitID = "dept-child" }, wantDecision: DecisionDeny, wantPermissions: []AtlasPermission{PermissionSuggest}, wantScopes: []string{"dept-child", "dept-parent"}, wantFallback: ActionKnowledgeSuggest},
		{name: "update deny without suggest has no fallback", mutateSnapshot: func(s *AtlasAccessSnapshot) { s.Memberships = nil }, wantDecision: DecisionDeny},
		{name: "other deny never falls back", mutateSnapshot: func(s *AtlasAccessSnapshot) {
			s.Memberships = []AtlasMembership{{OrgUnitID: "dept-parent", Role: string(PermissionSuggest)}}
		}, mutateRequest: func(r *ScopedRequest) { r.Action = ActionKnowledgeCreate }, wantDecision: DecisionDeny},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneAtlasSnapshot(base)
			if test.mutateSnapshot != nil {
				test.mutateSnapshot(&snapshot)
			}
			req := ScopedRequest{EnterpriseID: "enterprise-1", ActorUserID: "user-1", OrgUnitID: "dept-parent", OrgVersion: 42, ResourceType: ResourceKnowledge, ResourceID: "knowledge-1", Action: ActionKnowledgeUpdate}
			if test.mutateRequest != nil {
				test.mutateRequest(&req)
			}
			decision, err := NewAgentAtlasEvaluator(stubAtlasPolicySource{snapshot: snapshot}).Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if decision.Decision != test.wantDecision {
				t.Fatalf("decision = %q, want %q", decision.Decision, test.wantDecision)
			}
			if !reflect.DeepEqual(decision.Permissions, nonNilPermissions(test.wantPermissions)) {
				t.Fatalf("permissions = %#v, want %#v", decision.Permissions, nonNilPermissions(test.wantPermissions))
			}
			if !reflect.DeepEqual(decision.OrgUnitIDs, nonNilStrings(test.wantScopes)) {
				t.Fatalf("org scopes = %#v, want %#v", decision.OrgUnitIDs, nonNilStrings(test.wantScopes))
			}
			if decision.MaskFields == nil {
				t.Fatal("mask_fields is nil")
			}
			if decision.FallbackAction != test.wantFallback {
				t.Fatalf("fallback = %q, want %q", decision.FallbackAction, test.wantFallback)
			}
			if decision.OrgVersion != 42 {
				t.Fatalf("org version = %d, want 42", decision.OrgVersion)
			}
		})
	}
}

func TestAgentAtlasMemberOnlyGetsSuggest(t *testing.T) {
	t.Parallel()
	snapshot := AtlasAccessSnapshot{EnterpriseID: "enterprise-1", OrgVersion: 7, OrgUnits: []AtlasOrgUnit{{ID: "dept"}}, Memberships: []AtlasMembership{{OrgUnitID: "dept", Role: "member"}, {OrgUnitID: "dept", Role: "manager"}, {OrgUnitID: "dept", Role: "admin"}}}
	evaluator := NewAgentAtlasEvaluator(stubAtlasPolicySource{snapshot: snapshot})

	for _, action := range []AtlasAction{ActionKnowledgeSuggest, ActionKnowledgeUpdate, ActionKnowledgePublishLowRisk, ActionKnowledgeApproveHighRisk, ActionWorkflowEdit, ActionWorkflowEditAdvanced, ActionServiceMode} {
		resourceType := actionRequirements[action].resourceType
		decision, err := evaluator.Evaluate(context.Background(), ScopedRequest{EnterpriseID: "enterprise-1", ActorUserID: "user", OrgUnitID: "dept", OrgVersion: 7, ResourceType: resourceType, ResourceID: "resource", Action: action})
		if err != nil {
			t.Fatal(err)
		}
		want := DecisionDeny
		if action == ActionKnowledgeSuggest {
			want = DecisionAllow
		}
		if decision.Decision != want {
			t.Fatalf("action %q decision = %q, want %q", action, decision.Decision, want)
		}
	}
}

func TestAgentAtlasOnlyExplicitAdvancedAndServiceGrants(t *testing.T) {
	t.Parallel()
	snapshot := AtlasAccessSnapshot{EnterpriseID: "enterprise-1", OrgVersion: 8, OrgUnits: []AtlasOrgUnit{{ID: "dept"}}, Memberships: []AtlasMembership{{OrgUnitID: "dept", Role: string(PermissionWorkflowAdvanced)}, {OrgUnitID: "dept", Role: string(PermissionServiceMode)}}}
	evaluator := NewAgentAtlasEvaluator(stubAtlasPolicySource{snapshot: snapshot})

	for _, tc := range []struct {
		action       AtlasAction
		resourceType ResourceType
		permission   AtlasPermission
	}{{ActionWorkflowEditAdvanced, ResourceWorkflow, PermissionWorkflowAdvanced}, {ActionServiceMode, ResourceService, PermissionServiceMode}} {
		decision, err := evaluator.Evaluate(context.Background(), ScopedRequest{EnterpriseID: "enterprise-1", ActorUserID: "user", OrgUnitID: "dept", OrgVersion: 8, ResourceType: tc.resourceType, ResourceID: "resource", Action: tc.action})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != DecisionAllow || !reflect.DeepEqual(decision.Permissions, []AtlasPermission{tc.permission}) {
			t.Fatalf("action %q decision = %#v", tc.action, decision)
		}
	}
}

func TestAgentAtlasEveryCanonicalPermissionCanBeExplicitlyGranted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		permission   AtlasPermission
		action       AtlasAction
		resourceType ResourceType
	}{
		{PermissionSuggest, ActionKnowledgeSuggest, ResourceKnowledge},
		{PermissionEdit, ActionKnowledgeUpdate, ResourceKnowledge},
		{PermissionPublishLowRisk, ActionKnowledgePublishLowRisk, ResourceKnowledge},
		{PermissionApproveHighRisk, ActionKnowledgeApproveHighRisk, ResourceKnowledge},
		{PermissionWorkflowEdit, ActionWorkflowEdit, ResourceWorkflow},
		{PermissionWorkflowAdvanced, ActionWorkflowEditAdvanced, ResourceWorkflow},
		{PermissionServiceMode, ActionServiceMode, ResourceService},
	}
	for _, test := range tests {
		t.Run(string(test.permission), func(t *testing.T) {
			snapshot := AtlasAccessSnapshot{EnterpriseID: "enterprise-1", OrgVersion: 10, OrgUnits: []AtlasOrgUnit{{ID: "dept"}}, Memberships: []AtlasMembership{{OrgUnitID: "dept", Role: string(test.permission)}}}
			decision, err := NewAgentAtlasEvaluator(stubAtlasPolicySource{snapshot: snapshot}).Evaluate(context.Background(), ScopedRequest{EnterpriseID: "enterprise-1", ActorUserID: "user", OrgUnitID: "dept", OrgVersion: 10, ResourceType: test.resourceType, ResourceID: "resource", Action: test.action})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != DecisionAllow || !reflect.DeepEqual(decision.Permissions, []AtlasPermission{test.permission}) {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestAgentAtlasFailsClosedWhenPolicyUnavailableOrCrossEnterprise(t *testing.T) {
	t.Parallel()
	req := ScopedRequest{EnterpriseID: "enterprise-1", ActorUserID: "user", OrgUnitID: "dept", OrgVersion: 3, ResourceType: ResourceKnowledge, ResourceID: "resource", Action: ActionKnowledgeSuggest}

	if _, err := NewAgentAtlasEvaluator(stubAtlasPolicySource{err: errors.New("database down")}).Evaluate(context.Background(), req); !errors.Is(err, ErrAtlasPolicyUnavailable) {
		t.Fatalf("unavailable source error = %v", err)
	}
	foreign := AtlasAccessSnapshot{EnterpriseID: "enterprise-2", OrgVersion: 3, OrgUnits: []AtlasOrgUnit{{ID: "dept"}}, Memberships: []AtlasMembership{{OrgUnitID: "dept", Role: "suggest"}}}
	if _, err := NewAgentAtlasEvaluator(stubAtlasPolicySource{snapshot: foreign}).Evaluate(context.Background(), req); !errors.Is(err, ErrAtlasPolicyUnavailable) {
		t.Fatalf("cross-enterprise snapshot error = %v", err)
	}
}

func TestMemoryAtlasPolicySourceIsConcurrentAndReturnsCopies(t *testing.T) {
	t.Parallel()
	source := NewMemoryAtlasPolicySource()
	snapshot := AtlasAccessSnapshot{EnterpriseID: "enterprise-1", OrgVersion: 9, OrgUnits: []AtlasOrgUnit{{ID: "dept"}}, Memberships: []AtlasMembership{{OrgUnitID: "dept", Role: "suggest"}}}
	source.StoreSnapshot("enterprise-1", "user-1", snapshot)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			got, err := source.LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
			if err != nil {
				t.Errorf("LoadAccessSnapshot() error = %v", err)
				return
			}
			got.OrgUnits[0].ID = "mutated"
			got.Memberships[0].Role = "edit"
		}()
		go func() {
			defer wg.Done()
			source.StoreSnapshot("enterprise-1", "user-1", snapshot)
		}()
	}
	wg.Wait()

	got, err := source.LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.OrgUnits[0].ID != "dept" || got.Memberships[0].Role != "suggest" {
		t.Fatalf("stored snapshot was aliased: %#v", got)
	}
	if _, err := source.LoadAccessSnapshot(context.Background(), "enterprise-2", "user-1"); !errors.Is(err, ErrAtlasPolicyUnavailable) {
		t.Fatalf("missing enterprise lookup error = %v", err)
	}
}

func cloneAtlasSnapshot(snapshot AtlasAccessSnapshot) AtlasAccessSnapshot {
	snapshot.OrgUnits = append([]AtlasOrgUnit(nil), snapshot.OrgUnits...)
	snapshot.Memberships = append([]AtlasMembership(nil), snapshot.Memberships...)
	return snapshot
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilPermissions(values []AtlasPermission) []AtlasPermission {
	if values == nil {
		return []AtlasPermission{}
	}
	return values
}
