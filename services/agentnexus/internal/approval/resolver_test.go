package approval

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type permissionKey struct {
	userID     string
	permission Permission
}

type fakePermissionChecker struct {
	allowed map[permissionKey]bool
	err     error
	calls   []PermissionRequest
}

func (f *fakePermissionChecker) Allows(_ context.Context, req PermissionRequest) (bool, error) {
	f.calls = append(f.calls, req)
	if f.err != nil {
		return false, f.err
	}
	return f.allowed[permissionKey{userID: req.UserID, permission: req.Permission}], nil
}

func TestResolveAuthorizedLowUsesSingleConfirmationWithoutPublishing(t *testing.T) {
	checker := &fakePermissionChecker{allowed: map[permissionKey]bool{{"requester", PermissionPublishLowRisk}: true}}
	route, err := NewResolver(checker, DefaultPolicy()).Resolve(context.Background(), baseRequest(), validSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != ModeSingleConfirmation || route.AutoPublish || route.ReviewerUserID != "" || route.Queue != "" || !reflect.DeepEqual(route.OrgPath, []string{"team"}) {
		t.Fatalf("route=%+v", route)
	}
}

func TestResolveUnauthorizedLowWalksUpUsingPublishPermission(t *testing.T) {
	checker := &fakePermissionChecker{allowed: map[permissionKey]bool{{"dept-head", PermissionPublishLowRisk}: true, {"root-head", PermissionPublishLowRisk}: true}}
	route, err := NewResolver(checker, DefaultPolicy()).Resolve(context.Background(), baseRequest(), validSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != ModeUpwardReview || route.ReviewerUserID != "dept-head" || route.ReviewerDisplayName != "Department Head" || !reflect.DeepEqual(route.OrgPath, []string{"team", "dept"}) || route.AutoPublish {
		t.Fatalf("route=%+v", route)
	}
}

func TestResolveMediumAndHighUseApprovePermissionAndExcludeRequester(t *testing.T) {
	tests := []struct {
		name  string
		input RiskInput
	}{
		{name: "medium", input: RiskInput{ImpactedUserCount: 26}},
		{name: "high", input: RiskInput{ExternalSideEffect: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseRequest()
			req.RequesterUserID = "team-manager"
			req.Risk = tt.input
			checker := &fakePermissionChecker{allowed: map[permissionKey]bool{{"team-manager", PermissionApproveHighRisk}: true, {"dept-head", PermissionApproveHighRisk}: true}}
			route, err := NewResolver(checker, DefaultPolicy()).Resolve(context.Background(), req, validSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			if route.Mode != ModeUpwardReview || route.ReviewerUserID != "dept-head" || route.ReviewerUserID == req.RequesterUserID || route.AutoPublish {
				t.Fatalf("route=%+v", route)
			}
		})
	}
}

func TestResolveSkipsUnauthorizedManagerAndChoosesStableNearestCandidate(t *testing.T) {
	units, memberships, users := validSnapshotRows()
	memberships = append(memberships,
		SnapshotMembership{UserID: "team-manager-b", OrgUnitID: "team", Role: RoleManager},
		SnapshotMembership{UserID: "team-manager-a", OrgUnitID: "team", Role: RoleManager},
	)
	users = append(users,
		SnapshotUser{ID: "team-manager-b", DisplayName: "B"},
		SnapshotUser{ID: "team-manager-a", DisplayName: "A"},
	)
	snapshot, err := NewOrgSnapshot("enterprise-1", 7, units, memberships, users)
	if err != nil {
		t.Fatal(err)
	}
	req := baseRequest()
	req.Risk.ExternalSideEffect = true
	checker := &fakePermissionChecker{allowed: map[permissionKey]bool{{"team-manager-b", PermissionApproveHighRisk}: true, {"team-manager-a", PermissionApproveHighRisk}: true}}
	route, err := NewResolver(checker, DefaultPolicy()).Resolve(context.Background(), req, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if route.ReviewerUserID != "team-manager-a" || !reflect.DeepEqual(route.OrgPath, []string{"team"}) {
		t.Fatalf("route=%+v", route)
	}
}

func TestResolveNoReviewerUsesKnowledgeAdminQueue(t *testing.T) {
	req := baseRequest()
	req.Risk.ExternalSideEffect = true
	route, err := NewResolver(&fakePermissionChecker{allowed: map[permissionKey]bool{}}, DefaultPolicy()).Resolve(context.Background(), req, validSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != ModeEnterpriseKnowledgeAdminQueue || route.Queue != EnterpriseKnowledgeAdminQueue || route.ReviewerUserID != "" || route.ReviewerDisplayName != "" || route.AutoPublish || !reflect.DeepEqual(route.OrgPath, []string{"team", "dept", "root"}) {
		t.Fatalf("route=%+v", route)
	}
}

func TestResolveFailsClosedForInvalidSnapshotBindings(t *testing.T) {
	tests := []struct {
		name     string
		request  func() Request
		snapshot func() OrgSnapshot
	}{
		{name: "cross enterprise", request: baseRequest, snapshot: func() OrgSnapshot {
			units, memberships, users := validSnapshotRows()
			return mustSnapshot(t, "other", 7, units, memberships, users)
		}},
		{name: "stale", request: func() Request { r := baseRequest(); r.OrgVersion++; return r }, snapshot: validSnapshot},
		{name: "missing target", request: func() Request { r := baseRequest(); r.OrgUnitID = "missing"; return r }, snapshot: validSnapshot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewResolver(&fakePermissionChecker{allowed: map[permissionKey]bool{}}, DefaultPolicy()).Resolve(context.Background(), tt.request(), tt.snapshot())
			if !errors.Is(err, ErrApprovalUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestNewOrgSnapshotRejectsCycleDanglingAndDuplicates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*[]SnapshotUnit, *[]SnapshotMembership)
	}{
		{name: "cycle", mutate: func(units *[]SnapshotUnit, _ *[]SnapshotMembership) { (*units)[2].ParentID = "team" }},
		{name: "dangling", mutate: func(units *[]SnapshotUnit, _ *[]SnapshotMembership) { (*units)[1].ParentID = "missing" }},
		{name: "duplicate unit", mutate: func(units *[]SnapshotUnit, _ *[]SnapshotMembership) { *units = append(*units, (*units)[0]) }},
		{name: "duplicate membership", mutate: func(_ *[]SnapshotUnit, memberships *[]SnapshotMembership) {
			*memberships = append(*memberships, (*memberships)[0])
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			units, memberships, users := validSnapshotRows()
			tt.mutate(&units, &memberships)
			if _, err := NewOrgSnapshot("enterprise-1", 7, units, memberships, users); !errors.Is(err, ErrApprovalUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestResolveFailsClosedForLimitsCancellationAndPermissionUnavailable(t *testing.T) {
	if _, err := NewOrgSnapshot("enterprise-1", 7, make([]SnapshotUnit, MaxSnapshotOrgUnits+1), nil, nil); !errors.Is(err, ErrApprovalUnavailable) {
		t.Fatalf("limit err=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewResolver(&fakePermissionChecker{allowed: map[permissionKey]bool{}}, DefaultPolicy()).Resolve(cancelled, baseRequest(), validSnapshot()); !errors.Is(err, ErrApprovalUnavailable) {
		t.Fatalf("cancel err=%v", err)
	}
	req := baseRequest()
	req.Risk.ExternalSideEffect = true
	if _, err := NewResolver(&fakePermissionChecker{err: errors.New("down")}, DefaultPolicy()).Resolve(context.Background(), req, validSnapshot()); !errors.Is(err, ErrApprovalUnavailable) {
		t.Fatalf("checker err=%v", err)
	}
}

func baseRequest() Request {
	return Request{EnterpriseID: "enterprise-1", RequesterUserID: "requester", OrgVersion: 7, OrgUnitID: "team", ResourceType: "workflow", ResourceID: "workflow-1", Action: "workflow.update"}
}

func validSnapshot() OrgSnapshot {
	units, memberships, users := validSnapshotRows()
	return mustSnapshot(nil, "enterprise-1", 7, units, memberships, users)
}

func validSnapshotRows() ([]SnapshotUnit, []SnapshotMembership, []SnapshotUser) {
	return []SnapshotUnit{
			{ID: "root"},
			{ID: "dept", ParentID: "root"},
			{ID: "team", ParentID: "dept"},
		}, []SnapshotMembership{
			{UserID: "team-manager", OrgUnitID: "team", Role: RoleManager},
			{UserID: "dept-head", OrgUnitID: "dept", Role: RoleManager},
			{UserID: "root-head", OrgUnitID: "root", Role: RoleManager},
		}, []SnapshotUser{
			{ID: "requester", DisplayName: "Requester"},
			{ID: "team-manager", DisplayName: "Team Manager"},
			{ID: "dept-head", DisplayName: "Department Head"},
			{ID: "root-head", DisplayName: "Root Head"},
		}
}

func mustSnapshot(t *testing.T, enterpriseID string, version int64, units []SnapshotUnit, memberships []SnapshotMembership, users []SnapshotUser) OrgSnapshot {
	snapshot, err := NewOrgSnapshot(enterpriseID, version, units, memberships, users)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return snapshot
}
