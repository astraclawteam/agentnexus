package approval

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestResolveAuthorizedLowUsesSingleConfirmationWithoutPublishing(t *testing.T) {
	route, err := NewIndexedResolver(DefaultPolicy()).Resolve(context.Background(), baseRequest(), snapshotWithPermissions(t, SnapshotMembership{UserID: "requester", OrgUnitID: "team", Role: string(PermissionPublishLowRisk)}))
	if err != nil {
		t.Fatal(err)
	}
	if route.Mode != ModeSingleConfirmation || route.AutoPublish || route.ReviewerUserID != "" || route.Queue != "" || !reflect.DeepEqual(route.OrgPath, []string{"team"}) {
		t.Fatalf("route=%+v", route)
	}
}

func TestResolveUnauthorizedLowWalksUpUsingPublishPermission(t *testing.T) {
	route, err := NewIndexedResolver(DefaultPolicy()).Resolve(context.Background(), baseRequest(), snapshotWithPermissions(t, SnapshotMembership{UserID: "dept-head", OrgUnitID: "dept", Role: string(PermissionPublishLowRisk)}, SnapshotMembership{UserID: "root-head", OrgUnitID: "root", Role: string(PermissionPublishLowRisk)}))
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
		input riskFactsInput
	}{
		{name: "medium", input: riskFactsInput{ImpactedUserCount: 26}},
		{name: "high", input: riskFactsInput{ExternalSideEffect: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseRequest()
			req.RequesterUserID = "team-manager"
			req.Facts = verifiedFacts(tt.input)
			route, err := NewIndexedResolver(DefaultPolicy()).Resolve(context.Background(), req, snapshotWithPermissions(t, SnapshotMembership{UserID: "dept-head", OrgUnitID: "dept", Role: string(PermissionApproveHighRisk)}))
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
	req.Facts = NewVerifiedChangeFacts(VerifiedChangeFactsInput{ExternalSideEffect: true})
	memberships = append(memberships, SnapshotMembership{UserID: "team-manager-b", OrgUnitID: "team", Role: string(PermissionApproveHighRisk)}, SnapshotMembership{UserID: "team-manager-a", OrgUnitID: "team", Role: string(PermissionApproveHighRisk)})
	snapshot, err = NewOrgSnapshot("enterprise-1", 7, units, memberships, users)
	if err != nil {
		t.Fatal(err)
	}
	route, err := NewIndexedResolver(DefaultPolicy()).Resolve(context.Background(), req, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if route.ReviewerUserID != "team-manager-a" || !reflect.DeepEqual(route.OrgPath, []string{"team"}) {
		t.Fatalf("route=%+v", route)
	}
}

func TestResolveNoReviewerUsesKnowledgeAdminQueue(t *testing.T) {
	req := baseRequest()
	req.Facts = NewVerifiedChangeFacts(VerifiedChangeFactsInput{ExternalSideEffect: true})
	route, err := NewIndexedResolver(DefaultPolicy()).Resolve(context.Background(), req, validSnapshot())
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
			_, err := NewIndexedResolver(DefaultPolicy()).Resolve(context.Background(), tt.request(), tt.snapshot())
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
	if _, err := NewIndexedResolver(DefaultPolicy()).Resolve(cancelled, baseRequest(), validSnapshot()); !errors.Is(err, ErrApprovalUnavailable) {
		t.Fatalf("cancel err=%v", err)
	}
}

func TestResolveBuildsPermissionIndexOnceForManyManagers(t *testing.T) {
	units := []SnapshotUnit{{ID: "root"}, {ID: "team", ParentID: "root"}}
	memberships := make([]SnapshotMembership, 0, 2000)
	users := make([]SnapshotUser, 0, 1001)
	users = append(users, SnapshotUser{ID: "requester", DisplayName: "Requester"})
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("manager-%04d", i)
		users = append(users, SnapshotUser{ID: id, DisplayName: id})
		memberships = append(memberships, SnapshotMembership{UserID: id, OrgUnitID: "team", Role: RoleManager}, SnapshotMembership{UserID: id, OrgUnitID: "root", Role: string(PermissionApproveHighRisk)})
	}
	snapshot := mustSnapshot(t, "enterprise-1", 7, units, memberships, users)
	req := baseRequest()
	req.Facts = NewVerifiedChangeFacts(VerifiedChangeFactsInput{ExternalSideEffect: true})
	counts := map[string]int{}
	resolver := NewIndexedResolver(DefaultPolicy())
	resolver.observe = func(work string) { counts[work]++ }
	if _, err := resolver.Resolve(context.Background(), req, snapshot); err != nil {
		t.Fatal(err)
	}
	if counts["membership"] != len(memberships) || counts["candidate"] > 1 {
		t.Fatalf("counts=%v memberships=%d", counts, len(memberships))
	}
}

func baseRequest() Request {
	return Request{EnterpriseID: "enterprise-1", RequesterUserID: "requester", OrgVersion: 7, OrgUnitID: "team", ResourceType: "knowledge", ResourceID: "article-1", Action: "knowledge.publish_low_risk", Facts: NewVerifiedChangeFacts(VerifiedChangeFactsInput{}), PolicyVersion: 1}
}

func verifiedFacts(input riskFactsInput) VerifiedChangeFacts {
	return NewVerifiedChangeFacts(VerifiedChangeFactsInput{ChangedFields: input.ChangedFields, ImpactedOrgUnitIDs: input.ImpactedOrgUnitIDs, ImpactedUserCount: input.ImpactedUserCount, PublishedBehaviorChange: input.PublishedBehaviorChange, ExternalSideEffect: input.ExternalSideEffect})
}

func snapshotWithPermissions(t *testing.T, extra ...SnapshotMembership) OrgSnapshot {
	units, memberships, users := validSnapshotRows()
	memberships = append(memberships, extra...)
	return mustSnapshot(t, "enterprise-1", 7, units, memberships, users)
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
