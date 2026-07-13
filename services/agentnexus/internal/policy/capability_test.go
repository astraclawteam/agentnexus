package policy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

// Parity note (GA Task 0B): every still-meaningful case of the retired
// internal/policy/agentatlas_test.go moved here against the neutral
// capability vocabulary before agentatlas.go/agentatlas_test.go were
// deleted. The wire values (permissions, risk levels, decision payload) are
// unchanged; identity and organization facts now arrive credential-derived
// through CapabilityRequest instead of caller-scoped request fields.

func TestMembershipRolePermissionIsTheCanonicalClosedMapping(t *testing.T) {
	tests := []struct {
		role       string
		permission PrincipalPermission
		known      bool
	}{
		{role: "member", permission: PermissionSuggest, known: true},
		{role: "manager", known: true},
		{role: "admin", known: true},
		{role: string(PermissionSuggest), permission: PermissionSuggest, known: true},
		{role: string(PermissionEdit), permission: PermissionEdit, known: true},
		{role: string(PermissionPublishLowRisk), permission: PermissionPublishLowRisk, known: true},
		{role: string(PermissionApproveHighRisk), permission: PermissionApproveHighRisk, known: true},
		{role: string(PermissionWorkflowEdit), permission: PermissionWorkflowEdit, known: true},
		{role: string(PermissionWorkflowAdvanced), permission: PermissionWorkflowAdvanced, known: true},
		{role: string(PermissionServiceMode), permission: PermissionServiceMode, known: true},
		{role: "unknown"},
		{role: " member"},
	}
	for _, test := range tests {
		permission, known := MembershipRolePermission(test.role)
		if permission != test.permission || known != test.known {
			t.Errorf("role=%q permission=%q known=%v, want %q/%v", test.role, permission, known, test.permission, test.known)
		}
	}
}

func TestCapabilityVocabulary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		resourceType ResourceType
		capability   Capability
		permission   PrincipalPermission
		risk         CapabilityRisk
	}{
		{name: "suggest", resourceType: ResourceKnowledge, capability: CapabilityKnowledgeSuggest, permission: PermissionSuggest, risk: CapabilityRiskLow},
		{name: "create", resourceType: ResourceKnowledge, capability: CapabilityKnowledgeCreate, permission: PermissionEdit, risk: CapabilityRiskMedium},
		{name: "update", resourceType: ResourceKnowledge, capability: CapabilityKnowledgeUpdate, permission: PermissionEdit, risk: CapabilityRiskMedium},
		{name: "publish low risk", resourceType: ResourceKnowledge, capability: CapabilityKnowledgePublishLowRisk, permission: PermissionPublishLowRisk, risk: CapabilityRiskLow},
		{name: "approve high risk", resourceType: ResourceKnowledge, capability: CapabilityKnowledgeApproveHighRisk, permission: PermissionApproveHighRisk, risk: CapabilityRiskHigh},
		{name: "workflow edit", resourceType: ResourceWorkflow, capability: CapabilityWorkflowEdit, permission: PermissionWorkflowEdit, risk: CapabilityRiskMedium},
		{name: "workflow advanced", resourceType: ResourceWorkflow, capability: CapabilityWorkflowEditAdvanced, permission: PermissionWorkflowAdvanced, risk: CapabilityRiskHigh},
		{name: "workflow publish", resourceType: ResourceWorkflow, capability: CapabilityWorkflowPublishLowRisk, permission: PermissionPublishLowRisk, risk: CapabilityRiskLow},
		{name: "workflow approve", resourceType: ResourceWorkflow, capability: CapabilityWorkflowApproveHighRisk, permission: PermissionApproveHighRisk, risk: CapabilityRiskHigh},
		{name: "service mode", resourceType: ResourceService, capability: CapabilityServiceMode, permission: PermissionServiceMode, risk: CapabilityRiskHigh},
		{name: "evidence read", resourceType: ResourceDreamEvidence, capability: CapabilityEvidenceRead, permission: PermissionApproveHighRisk, risk: CapabilityRiskHigh},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			permission, risk, ok := RequiredCapabilityPermission(test.resourceType, test.capability)
			if !ok {
				t.Fatal("known capability/resource pair was rejected")
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

func TestCapabilityRequiresMatchingResourceType(t *testing.T) {
	t.Parallel()

	for capability, requirement := range capabilityRequirements {
		// Sentinel: no connector.* capability may ever be added to the grantable
		// requirements map. Connector capabilities are denied at ingress and must
		// never become directly grantable; adding e.g. connector.export here
		// later fails the build.
		if IsConnectorCapability(capability) {
			t.Fatalf("connector capability %q must never be a grantable requirement", capability)
		}
		for _, resourceType := range []ResourceType{ResourceKnowledge, ResourceWorkflow, ResourceService, ResourceDreamEvidence} {
			if resourceType == requirement.resourceType {
				continue
			}
			if _, _, ok := RequiredCapabilityPermission(resourceType, capability); ok {
				t.Fatalf("capability %q was accepted for mismatched resource %q", capability, resourceType)
			}
		}
	}
	if _, _, ok := RequiredCapabilityPermission(ResourceType("unknown"), CapabilityWorkflowEdit); ok {
		t.Fatal("unknown resource type was accepted")
	}
	if _, _, ok := RequiredCapabilityPermission("", CapabilityWorkflowEdit); ok {
		t.Fatal("empty resource type was accepted")
	}
	if _, _, ok := RequiredCapabilityPermission(ResourceKnowledge, Capability("unknown")); ok {
		t.Fatal("unknown capability was accepted")
	}
	if _, _, ok := RequiredCapabilityPermission(ResourceKnowledge, ""); ok {
		t.Fatal("empty capability was accepted")
	}
}

func TestConnectorCapabilityNamespaceIsNeverGrantable(t *testing.T) {
	t.Parallel()
	if !IsConnectorCapability("connector.erp.read") || IsConnectorCapability(CapabilityKnowledgeSuggest) {
		t.Fatal("connector namespace classification broken")
	}
	snapshot := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 3, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: string(PermissionApproveHighRisk)}}}
	decision, err := NewCapabilityEvaluator(stubSnapshotSource{snapshot: snapshot}).Evaluate(context.Background(), CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user", SealedOrgVersion: 3, ResourceType: ResourceService, ResourceID: "erp-1", Capability: "connector.erp.read"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny || decision.RiskLevel != CapabilityRiskHigh {
		t.Fatalf("connector capability decision = %#v, want high-risk deny", decision)
	}
}

type stubSnapshotSource struct {
	snapshot SealedAccessSnapshot
	err      error
}

func (s stubSnapshotSource) LoadAccessSnapshot(context.Context, string, string) (SealedAccessSnapshot, error) {
	return s.snapshot, s.err
}

type recordingIntegrityObserver struct {
	calls      int
	tenantRef  string
	orgVersion int64
}

func (o *recordingIntegrityObserver) SealedSnapshotIntegrityFailure(_ context.Context, tenantRef, _ string, orgVersion int64) {
	o.calls++
	o.tenantRef = tenantRef
	o.orgVersion = orgVersion
}

// TestCapabilityCorruptSealedSnapshotIsVisibleNotSilent proves an integrity
// failure in the sealed (server-authored) snapshot is surfaced distinctly — a
// high-risk deny plus an observer signal — never a silent baseline-risk deny
// indistinguishable from an ordinary permission denial (no-silent-degradation
// governance rule).
func TestCapabilityCorruptSealedSnapshotIsVisibleNotSilent(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		snapshot SealedAccessSnapshot
	}{
		{name: "cycle", snapshot: SealedAccessSnapshot{TenantRef: "ent-1", OrgVersion: 5, OrgUnits: []SealedOrgUnit{{ID: "a", ParentID: "b"}, {ID: "b", ParentID: "a"}}, Memberships: []SealedMembership{{OrgUnitID: "a", Role: "suggest"}}}},
		{name: "dangling membership", snapshot: SealedAccessSnapshot{TenantRef: "ent-1", OrgVersion: 5, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "missing", Role: "suggest"}}}},
		{name: "duplicate unit", snapshot: SealedAccessSnapshot{TenantRef: "ent-1", OrgVersion: 5, OrgUnits: []SealedOrgUnit{{ID: "dept"}, {ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "suggest"}}}},
		{name: "unknown role", snapshot: SealedAccessSnapshot{TenantRef: "ent-1", OrgVersion: 5, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "Suggest"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observer := &recordingIntegrityObserver{}
			decision, err := NewCapabilityEvaluator(stubSnapshotSource{snapshot: tc.snapshot}, WithSnapshotIntegrityObserver(observer)).Evaluate(context.Background(), CapabilityRequest{TenantRef: "ent-1", PrincipalRef: "user-1", SealedOrgVersion: 5, ResourceType: ResourceKnowledge, ResourceID: "article-1", Capability: CapabilityKnowledgeSuggest})
			if err != nil {
				t.Fatalf("integrity failure must not surface as an error (it is a scoped deny): %v", err)
			}
			if decision.Decision != DecisionDeny || decision.RiskLevel != CapabilityRiskHigh {
				t.Fatalf("corrupt snapshot must deny at high risk, got %#v", decision)
			}
			if observer.calls != 1 || observer.tenantRef != "ent-1" || observer.orgVersion != 5 {
				t.Fatalf("corrupt snapshot must signal the integrity observer exactly once: %+v", observer)
			}
		})
	}

	// Contrast: a structurally VALID snapshot where the principal simply lacks
	// the permission is an ordinary deny at the capability's baseline risk and
	// does NOT trip the integrity observer.
	observer := &recordingIntegrityObserver{}
	valid := SealedAccessSnapshot{TenantRef: "ent-1", OrgVersion: 5, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "suggest"}}}
	decision, err := NewCapabilityEvaluator(stubSnapshotSource{snapshot: valid}, WithSnapshotIntegrityObserver(observer)).Evaluate(context.Background(), CapabilityRequest{TenantRef: "ent-1", PrincipalRef: "user-1", SealedOrgVersion: 5, ResourceType: ResourceKnowledge, ResourceID: "article-1", Capability: CapabilityKnowledgeCreate})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny || decision.RiskLevel != CapabilityRiskMedium || observer.calls != 0 {
		t.Fatalf("an ordinary permission deny must stay at baseline risk and not signal integrity: decision=%#v calls=%d", decision, observer.calls)
	}
}

func TestCapabilityScopedEvaluation(t *testing.T) {
	t.Parallel()

	base := SealedAccessSnapshot{
		TenantRef:  "enterprise-1",
		OrgVersion: 42,
		OrgUnits: []SealedOrgUnit{
			{ID: "dept-child", ParentID: "dept-parent"},
			{ID: "dept-other"},
			{ID: "dept-parent"},
		},
		Memberships: []SealedMembership{
			{OrgUnitID: "dept-parent", Role: string(PermissionEdit)},
			{OrgUnitID: "dept-parent", Role: string(PermissionSuggest)},
			{OrgUnitID: "dept-child", Role: string(PermissionWorkflowAdvanced)},
			{OrgUnitID: "dept-child", Role: string(PermissionServiceMode)},
		},
	}

	tests := []struct {
		name            string
		mutateSnapshot  func(*SealedAccessSnapshot)
		mutateRequest   func(*CapabilityRequest)
		wantDecision    Decision
		wantPermissions []PrincipalPermission
		wantScopes      []string
		wantFallback    Capability
	}{
		{name: "same org allow", wantDecision: DecisionAllow, wantPermissions: []PrincipalPermission{PermissionEdit}, wantScopes: []string{"dept-parent"}},
		{name: "parent covers child", mutateRequest: func(r *CapabilityRequest) { r.TargetOrgUnitID = "dept-child" }, wantDecision: DecisionAllow, wantPermissions: []PrincipalPermission{PermissionEdit}, wantScopes: []string{"dept-parent"}},
		{name: "child does not cover parent", mutateSnapshot: func(s *SealedAccessSnapshot) {
			s.Memberships = []SealedMembership{{OrgUnitID: "dept-child", Role: string(PermissionEdit)}}
		}, wantDecision: DecisionDeny},
		{name: "stale sealed version", mutateRequest: func(r *CapabilityRequest) { r.SealedOrgVersion = 41 }, wantDecision: DecisionDeny},
		{name: "future sealed version", mutateRequest: func(r *CapabilityRequest) { r.SealedOrgVersion = 43 }, wantDecision: DecisionDeny},
		{name: "missing sealed version", mutateRequest: func(r *CapabilityRequest) { r.SealedOrgVersion = 0 }, wantDecision: DecisionDeny},
		{name: "non-canonical target", mutateRequest: func(r *CapabilityRequest) { r.TargetOrgUnitID = " dept-parent" }, wantDecision: DecisionDeny},
		{name: "empty resource id", mutateRequest: func(r *CapabilityRequest) { r.ResourceID = "" }, wantDecision: DecisionDeny},
		{name: "unknown target org unit", mutateRequest: func(r *CapabilityRequest) { r.TargetOrgUnitID = "dept-missing" }, wantDecision: DecisionDeny},
		{name: "unknown capability", mutateRequest: func(r *CapabilityRequest) { r.Capability = "unknown" }, wantDecision: DecisionDeny},
		{name: "mismatched capability resource", mutateRequest: func(r *CapabilityRequest) { r.ResourceType = ResourceWorkflow }, wantDecision: DecisionDeny},
		{name: "malformed graph missing parent", mutateSnapshot: func(s *SealedAccessSnapshot) { s.OrgUnits[0].ParentID = "missing" }, mutateRequest: func(r *CapabilityRequest) { r.TargetOrgUnitID = "dept-child" }, wantDecision: DecisionDeny},
		{name: "malformed graph cycle", mutateSnapshot: func(s *SealedAccessSnapshot) { s.OrgUnits[2].ParentID = "dept-child" }, mutateRequest: func(r *CapabilityRequest) { r.TargetOrgUnitID = "dept-child" }, wantDecision: DecisionDeny},
		{name: "update deny falls back to scoped suggest", mutateSnapshot: func(s *SealedAccessSnapshot) {
			s.Memberships = []SealedMembership{{OrgUnitID: "dept-child", Role: string(PermissionSuggest)}, {OrgUnitID: "dept-parent", Role: string(PermissionSuggest)}}
		}, mutateRequest: func(r *CapabilityRequest) { r.TargetOrgUnitID = "dept-child" }, wantDecision: DecisionDeny, wantPermissions: []PrincipalPermission{PermissionSuggest}, wantScopes: []string{"dept-child", "dept-parent"}, wantFallback: CapabilityKnowledgeSuggest},
		{name: "update deny without suggest has no fallback", mutateSnapshot: func(s *SealedAccessSnapshot) { s.Memberships = nil }, wantDecision: DecisionDeny},
		{name: "other deny never falls back", mutateSnapshot: func(s *SealedAccessSnapshot) {
			s.Memberships = []SealedMembership{{OrgUnitID: "dept-parent", Role: string(PermissionSuggest)}}
		}, mutateRequest: func(r *CapabilityRequest) { r.Capability = CapabilityKnowledgeCreate }, wantDecision: DecisionDeny},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneSealedSnapshot(base)
			if test.mutateSnapshot != nil {
				test.mutateSnapshot(&snapshot)
			}
			req := CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user-1", TargetOrgUnitID: "dept-parent", SealedOrgVersion: 42, ResourceType: ResourceKnowledge, ResourceID: "knowledge-1", Capability: CapabilityKnowledgeUpdate}
			if test.mutateRequest != nil {
				test.mutateRequest(&req)
			}
			decision, err := NewCapabilityEvaluator(stubSnapshotSource{snapshot: snapshot}).Evaluate(context.Background(), req)
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
			if decision.FallbackCapability != test.wantFallback {
				t.Fatalf("fallback = %q, want %q", decision.FallbackCapability, test.wantFallback)
			}
			if decision.OrgVersion != 42 {
				t.Fatalf("org version = %d, want 42", decision.OrgVersion)
			}
		})
	}
}

// TestCapabilityUntargetedQueryListsPermittedScopes covers the frozen public
// decision surface: the caller supplies no organization scope at all and the
// decision lists the sealed membership scopes where the permission holds.
func TestCapabilityUntargetedQueryListsPermittedScopes(t *testing.T) {
	t.Parallel()
	snapshot := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 42, OrgUnits: []SealedOrgUnit{{ID: "dept-child", ParentID: "dept-parent"}, {ID: "dept-parent"}}, Memberships: []SealedMembership{{OrgUnitID: "dept-parent", Role: string(PermissionEdit)}, {OrgUnitID: "dept-child", Role: string(PermissionEdit)}}}
	decision, err := NewCapabilityEvaluator(stubSnapshotSource{snapshot: snapshot}).Evaluate(context.Background(), CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user-1", SealedOrgVersion: 42, ResourceType: ResourceKnowledge, ResourceID: "knowledge-1", Capability: CapabilityKnowledgeUpdate})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionAllow || !reflect.DeepEqual(decision.OrgUnitIDs, []string{"dept-child", "dept-parent"}) {
		t.Fatalf("decision = %#v", decision)
	}
	empty := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 42, OrgUnits: []SealedOrgUnit{{ID: "dept-parent"}}, Memberships: nil}
	decision, err = NewCapabilityEvaluator(stubSnapshotSource{snapshot: empty}).Evaluate(context.Background(), CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user-1", SealedOrgVersion: 42, ResourceType: ResourceKnowledge, ResourceID: "knowledge-1", Capability: CapabilityKnowledgeUpdate})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != DecisionDeny || len(decision.OrgUnitIDs) != 0 {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestCapabilityMemberOnlyGetsSuggest(t *testing.T) {
	t.Parallel()
	snapshot := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 7, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "member"}, {OrgUnitID: "dept", Role: "manager"}, {OrgUnitID: "dept", Role: "admin"}}}
	evaluator := NewCapabilityEvaluator(stubSnapshotSource{snapshot: snapshot})

	for _, capability := range []Capability{CapabilityKnowledgeSuggest, CapabilityKnowledgeUpdate, CapabilityKnowledgePublishLowRisk, CapabilityKnowledgeApproveHighRisk, CapabilityWorkflowEdit, CapabilityWorkflowEditAdvanced, CapabilityServiceMode} {
		resourceType := capabilityRequirements[capability].resourceType
		decision, err := evaluator.Evaluate(context.Background(), CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user", TargetOrgUnitID: "dept", SealedOrgVersion: 7, ResourceType: resourceType, ResourceID: "resource", Capability: capability})
		if err != nil {
			t.Fatal(err)
		}
		want := DecisionDeny
		if capability == CapabilityKnowledgeSuggest {
			want = DecisionAllow
		}
		if decision.Decision != want {
			t.Fatalf("capability %q decision = %q, want %q", capability, decision.Decision, want)
		}
	}
}

func TestCapabilityOnlyExplicitAdvancedAndServiceGrants(t *testing.T) {
	t.Parallel()
	snapshot := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 8, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: string(PermissionWorkflowAdvanced)}, {OrgUnitID: "dept", Role: string(PermissionServiceMode)}}}
	evaluator := NewCapabilityEvaluator(stubSnapshotSource{snapshot: snapshot})

	for _, tc := range []struct {
		capability   Capability
		resourceType ResourceType
		permission   PrincipalPermission
	}{{CapabilityWorkflowEditAdvanced, ResourceWorkflow, PermissionWorkflowAdvanced}, {CapabilityServiceMode, ResourceService, PermissionServiceMode}} {
		decision, err := evaluator.Evaluate(context.Background(), CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user", TargetOrgUnitID: "dept", SealedOrgVersion: 8, ResourceType: tc.resourceType, ResourceID: "resource", Capability: tc.capability})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != DecisionAllow || !reflect.DeepEqual(decision.Permissions, []PrincipalPermission{tc.permission}) {
			t.Fatalf("capability %q decision = %#v", tc.capability, decision)
		}
	}
}

func TestCapabilityEveryCanonicalPermissionCanBeExplicitlyGranted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		permission   PrincipalPermission
		capability   Capability
		resourceType ResourceType
	}{
		{PermissionSuggest, CapabilityKnowledgeSuggest, ResourceKnowledge},
		{PermissionEdit, CapabilityKnowledgeUpdate, ResourceKnowledge},
		{PermissionPublishLowRisk, CapabilityKnowledgePublishLowRisk, ResourceKnowledge},
		{PermissionApproveHighRisk, CapabilityKnowledgeApproveHighRisk, ResourceKnowledge},
		{PermissionWorkflowEdit, CapabilityWorkflowEdit, ResourceWorkflow},
		{PermissionWorkflowAdvanced, CapabilityWorkflowEditAdvanced, ResourceWorkflow},
		{PermissionServiceMode, CapabilityServiceMode, ResourceService},
	}
	for _, test := range tests {
		t.Run(string(test.permission), func(t *testing.T) {
			snapshot := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 10, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: string(test.permission)}}}
			decision, err := NewCapabilityEvaluator(stubSnapshotSource{snapshot: snapshot}).Evaluate(context.Background(), CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user", TargetOrgUnitID: "dept", SealedOrgVersion: 10, ResourceType: test.resourceType, ResourceID: "resource", Capability: test.capability})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != DecisionAllow || !reflect.DeepEqual(decision.Permissions, []PrincipalPermission{test.permission}) {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestCapabilityFailsClosedWhenPolicyUnavailableOrCrossTenant(t *testing.T) {
	t.Parallel()
	req := CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user", TargetOrgUnitID: "dept", SealedOrgVersion: 3, ResourceType: ResourceKnowledge, ResourceID: "resource", Capability: CapabilityKnowledgeSuggest}

	if _, err := NewCapabilityEvaluator(stubSnapshotSource{err: errors.New("database down")}).Evaluate(context.Background(), req); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("unavailable source error = %v", err)
	}
	foreign := SealedAccessSnapshot{TenantRef: "enterprise-2", OrgVersion: 3, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "suggest"}}}
	if _, err := NewCapabilityEvaluator(stubSnapshotSource{snapshot: foreign}).Evaluate(context.Background(), req); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("cross-tenant snapshot error = %v", err)
	}
}

func TestMemorySnapshotSourceIsConcurrentAndReturnsCopies(t *testing.T) {
	t.Parallel()
	source := NewMemorySnapshotSource()
	snapshot := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 9, OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "suggest"}}}
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
	if _, err := source.LoadAccessSnapshot(context.Background(), "enterprise-2", "user-1"); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("missing enterprise lookup error = %v", err)
	}
}

func TestMemorySnapshotSourceCopiesPublishedInput(t *testing.T) {
	t.Parallel()
	source := NewMemorySnapshotSource()
	units := []SealedOrgUnit{{ID: "dept"}}
	memberships := []SealedMembership{{OrgUnitID: "dept", Role: "suggest"}}
	source.StoreSnapshot("enterprise-1", "user-1", SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 4, OrgUnits: units, Memberships: memberships})
	units[0].ID = "mutated"
	memberships[0].Role = "edit"

	got, err := source.LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.OrgUnits[0].ID != "dept" || got.Memberships[0].Role != "suggest" {
		t.Fatalf("published input was aliased: %#v", got)
	}
}

func sealedRelationRequest(target string) CapabilityRequest {
	return CapabilityRequest{TenantRef: "enterprise-1", PrincipalRef: "user-1", SealedOrgVersion: 1, ResourceType: ResourceKnowledge, ResourceID: "knowledge-1", Capability: CapabilityKnowledgeUpdate, TargetOrgUnitID: target}
}

func TestSealedSnapshotAnalysisIsLinear(t *testing.T) {
	t.Parallel()
	const units = 200
	snapshot := SealedAccessSnapshot{TenantRef: "enterprise-1", OrgVersion: 1}
	for i := 0; i < units; i++ {
		id := fmt.Sprintf("unit-%03d", i)
		parent := ""
		if i > 0 {
			parent = "unit-000"
		}
		snapshot.OrgUnits = append(snapshot.OrgUnits, SealedOrgUnit{ID: id, ParentID: parent})
		snapshot.Memberships = append(snapshot.Memberships, SealedMembership{OrgUnitID: id, Role: string(PermissionEdit)})
	}
	work := map[sealedGraphWork]int{}
	analysis, valid, err := sealCapabilityRelations(context.Background(), snapshot, sealedRelationRequest("unit-199"), PermissionEdit, func(item sealedGraphWork) { work[item]++ })
	if err != nil || !valid {
		t.Fatalf("analysis valid=%t err=%v", valid, err)
	}
	if len(analysis.requiredScopes) != 2 || !analysis.covered {
		t.Fatalf("required scopes = %#v covered=%t", analysis.requiredScopes, analysis.covered)
	}
	if work[sealedGraphWorkUnit] != units || work[sealedGraphWorkParent] < units || work[sealedGraphWorkParent] > 2*units || work[sealedGraphWorkMembership] != units || work[sealedGraphWorkAncestor] != 2 {
		t.Fatalf("non-linear work = %#v", work)
	}
}

func TestSealedSnapshotAnalysisLimits(t *testing.T) {
	t.Parallel()
	makeUnits := func(count int) []SealedOrgUnit {
		units := make([]SealedOrgUnit, count)
		for i := range units {
			units[i] = SealedOrgUnit{ID: fmt.Sprintf("unit-%d", i)}
		}
		return units
	}
	tests := []struct {
		name     string
		snapshot SealedAccessSnapshot
		target   string
	}{
		{name: "too many units", snapshot: SealedAccessSnapshot{OrgUnits: makeUnits(MaxSealedOrgUnits + 1)}, target: "unit-0"},
		{name: "too many memberships", snapshot: SealedAccessSnapshot{OrgUnits: []SealedOrgUnit{{ID: "unit"}}, Memberships: make([]SealedMembership, MaxSealedMemberships+1)}, target: "unit"},
	}
	deep := SealedAccessSnapshot{}
	for i := 0; i <= MaxSealedOrgDepth; i++ {
		parent := ""
		if i > 0 {
			parent = fmt.Sprintf("unit-%d", i-1)
		}
		deep.OrgUnits = append(deep.OrgUnits, SealedOrgUnit{ID: fmt.Sprintf("unit-%d", i), ParentID: parent})
	}
	tests = append(tests, struct {
		name     string
		snapshot SealedAccessSnapshot
		target   string
	}{name: "too deep", snapshot: deep, target: fmt.Sprintf("unit-%d", MaxSealedOrgDepth)})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, valid, err := sealCapabilityRelations(context.Background(), test.snapshot, sealedRelationRequest(test.target), PermissionSuggest, nil)
			if err != nil {
				t.Fatalf("unexpected error = %v", err)
			}
			if valid {
				t.Fatal("oversized snapshot was accepted")
			}
		})
	}
}

func TestSealedSnapshotAnalysisObservesCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	snapshot := SealedAccessSnapshot{}
	for i := 0; i < 1000; i++ {
		snapshot.OrgUnits = append(snapshot.OrgUnits, SealedOrgUnit{ID: fmt.Sprintf("unit-%d", i)})
	}
	visited := 0
	_, _, err := sealCapabilityRelations(ctx, snapshot, sealedRelationRequest("unit-999"), PermissionSuggest, func(work sealedGraphWork) {
		if work == sealedGraphWorkUnit {
			visited++
			if visited == 5 {
				cancel()
			}
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if visited > 6 {
		t.Fatalf("cancellation observed too late after %d visits", visited)
	}
}

func TestSealedSnapshotAnalysisRejectsDuplicateMembership(t *testing.T) {
	t.Parallel()
	snapshot := SealedAccessSnapshot{OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "suggest"}, {OrgUnitID: "dept", Role: "suggest"}}}
	analysis, valid, err := sealCapabilityRelations(context.Background(), snapshot, sealedRelationRequest("dept"), PermissionSuggest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if valid || len(analysis.requiredScopes) != 0 || len(analysis.suggestScopes) != 0 {
		t.Fatalf("duplicate membership leaked scopes: valid=%t analysis=%#v", valid, analysis)
	}
}

func TestSealedSnapshotAnalysisRejectsMalformedOrNonCanonicalData(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		snapshot SealedAccessSnapshot
	}{
		{name: "duplicate unit", snapshot: SealedAccessSnapshot{OrgUnits: []SealedOrgUnit{{ID: "dept"}, {ID: "dept"}}}},
		{name: "dangling parent", snapshot: SealedAccessSnapshot{OrgUnits: []SealedOrgUnit{{ID: "dept", ParentID: "missing"}}}},
		{name: "dangling membership", snapshot: SealedAccessSnapshot{OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "missing", Role: "suggest"}}}},
		{name: "cycle", snapshot: SealedAccessSnapshot{OrgUnits: []SealedOrgUnit{{ID: "a", ParentID: "b"}, {ID: "b", ParentID: "a"}}}},
		{name: "role case mismatch", snapshot: SealedAccessSnapshot{OrgUnits: []SealedOrgUnit{{ID: "dept"}}, Memberships: []SealedMembership{{OrgUnitID: "dept", Role: "Edit"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			analysis, valid, err := sealCapabilityRelations(context.Background(), test.snapshot, sealedRelationRequest("dept"), PermissionEdit, nil)
			if err != nil {
				t.Fatal(err)
			}
			if valid || len(analysis.requiredScopes) != 0 || len(analysis.suggestScopes) != 0 {
				t.Fatalf("invalid snapshot leaked grants: valid=%t analysis=%#v", valid, analysis)
			}
		})
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilPermissions(values []PrincipalPermission) []PrincipalPermission {
	if values == nil {
		return []PrincipalPermission{}
	}
	return values
}
