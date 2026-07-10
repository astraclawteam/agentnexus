package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
)

func TestMemoryApprovalStoreCreatesQueueOnlyForReviewRoutesAndAlwaysAudits(t *testing.T) {
	store := newMemoryApprovalTestStore(nil)
	req := storeRequest()
	direct := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: req.RequesterUserID, RequesterPermission: approval.PermissionPublishLowRisk, RequesterPermissionOrgUnitID: req.OrgUnitID, OrgPath: []string{req.OrgUnitID}, PolicyVersion: req.PolicyVersion}
	if err := store.Record(context.Background(), req, direct); err != nil {
		t.Fatal(err)
	}
	review := approval.Route{Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", ReviewerPermission: approval.PermissionApproveHighRisk, ReviewerPermissionOrgUnitID: "root", OrgPath: []string{"team", "root"}, PolicyVersion: req.PolicyVersion}
	req.IdempotencyHash = strings.Repeat("f", 64)
	if err := store.Record(context.Background(), req, review); err != nil {
		t.Fatal(err)
	}
	queues, events := store.Snapshot()
	if len(queues) != 1 || len(events) != 2 || queues[0].OrgVersion != req.OrgVersion || queues[0].InputHash == "" || queues[0].OutputHash == "" {
		t.Fatalf("queues=%+v events=%+v", queues, events)
	}
	if err := audit.VerifyHashChain(events); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryApprovalStoreRollsBackQueueAndAuditFailures(t *testing.T) {
	for _, stage := range []ApprovalRecordStage{ApprovalStageQueue, ApprovalStageAudit} {
		t.Run(string(stage), func(t *testing.T) {
			store := newMemoryApprovalTestStore(func(got ApprovalRecordStage) error {
				if got == stage {
					return errors.New("injected")
				}
				return nil
			})
			req := storeRequest()
			route := approval.Route{Mode: approval.ModeEnterpriseKnowledgeAdminQueue, RiskLevel: approval.RiskMedium, RiskReasons: []approval.RiskReason{approval.RiskReasonImpactedUserScope}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team", "root"}, Queue: approval.EnterpriseKnowledgeAdminQueue, PolicyVersion: req.PolicyVersion, AdminRootReached: true}
			if err := store.Record(context.Background(), req, route); err == nil {
				t.Fatal("expected failure")
			}
			queues, events := store.Snapshot()
			if len(queues) != 0 || len(events) != 0 {
				t.Fatalf("partial commit queues=%v events=%v", queues, events)
			}
		})
	}
}

func TestMemoryApprovalStoreSerializesConcurrentAuditChain(t *testing.T) {
	store := newMemoryApprovalTestStore(nil)
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: req.RequesterUserID, RequesterPermission: approval.PermissionPublishLowRisk, RequesterPermissionOrgUnitID: "team", OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := req
			request.IdempotencyHash = fmt.Sprintf("%064x", i+1)
			errs <- store.Record(context.Background(), request, route)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, events := store.Snapshot()
	if len(events) != 20 {
		t.Fatalf("events=%d", len(events))
	}
	if err := audit.VerifyHashChain(events); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryApprovalStoreIdempotentReplayConflictAndStaleRevalidation(t *testing.T) {
	store := newMemoryApprovalTestStore(nil)
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", ReviewerPermission: approval.PermissionApproveHighRisk, ReviewerPermissionOrgUnitID: "team", OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
	first, err := store.RecordResolution(context.Background(), req, route)
	if err != nil {
		t.Fatal(err)
	}
	store.SetCurrentVersions(req.EnterpriseID, req.OrgVersion+1, req.PolicyVersion+1)
	replayed, err := store.RecordResolution(context.Background(), req, route)
	if err != nil || !reflect.DeepEqual(first, replayed) {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	queues, events := store.Snapshot()
	if len(queues) != 1 || len(events) != 1 {
		t.Fatalf("queues=%d events=%d", len(queues), len(events))
	}
	conflict := req
	conflict.ResourceID = "other"
	conflict.ReplayHash = strings.Repeat("f", 64)
	if _, err := store.RecordResolution(context.Background(), conflict, route); !errors.Is(err, ErrApprovalIdempotencyConflict) {
		t.Fatalf("conflict err=%v", err)
	}
	stale := req
	stale.IdempotencyHash = strings.Repeat("e", 64)
	if _, err := store.RecordResolution(context.Background(), stale, route); !errors.Is(err, ErrApprovalStale) {
		t.Fatalf("stale err=%v", err)
	}
}

func TestMemoryApprovalStoreConcurrentSameKeyCommitsOnce(t *testing.T) {
	store := newMemoryApprovalTestStore(nil)
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", ReviewerPermission: approval.PermissionApproveHighRisk, ReviewerPermissionOrgUnitID: "team", OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.RecordResolution(context.Background(), req, route)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	queues, events := store.Snapshot()
	if len(queues) != 1 || len(events) != 1 {
		t.Fatalf("queues=%d events=%d", len(queues), len(events))
	}
}

func newMemoryApprovalTestStore(fail func(ApprovalRecordStage) error) *MemoryApprovalStore {
	store := NewMemoryApprovalStore(bytes.NewReader(make([]byte, 16384)), fail)
	store.SetCurrentVersions("enterprise-1", 7, 1)
	return store
}

func TestRecordedRouteRejectsMalformedDatabaseEvidence(t *testing.T) {
	req := storeRequest()
	valid := approval.Route{Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", ReviewerPermission: approval.PermissionApproveHighRisk, ReviewerPermissionOrgUnitID: "team", OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
	tests := []approval.Route{
		func() approval.Route { v := valid; v.RiskReasons = []approval.RiskReason{}; return v }(),
		func() approval.Route {
			v := valid
			v.RiskReasons = []approval.RiskReason{approval.RiskReasonExternalSideEffect, approval.RiskReasonExternalSideEffect}
			return v
		}(),
		func() approval.Route {
			v := valid
			v.RiskReasons = []approval.RiskReason{approval.RiskReasonUnknownAction, approval.RiskReasonExternalSideEffect}
			return v
		}(),
		func() approval.Route { v := valid; v.OrgPath = []string{"other"}; return v }(),
		func() approval.Route { v := valid; v.OrgPath = []string{"team", "team"}; return v }(),
		func() approval.Route { v := valid; v.ReviewerDisplayName = ""; return v }(),
		func() approval.Route { v := valid; v.ReviewerPermission = approval.PermissionPublishLowRisk; return v }(),
		func() approval.Route { v := valid; v.ReviewerPermissionOrgUnitID = " other"; return v }(),
		{Mode: approval.ModeEnterpriseKnowledgeAdminQueue, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team"}, Queue: approval.EnterpriseKnowledgeAdminQueue, PolicyVersion: req.PolicyVersion},
	}
	for _, route := range tests {
		if validRecordedRoute(req, route) {
			t.Fatalf("accepted malformed route=%+v", route)
		}
	}
}

func TestApprovalQueueStatusTransitionsAreOneWayAfterVersionsAdvance(t *testing.T) {
	for _, next := range []string{"approved", "rejected", "cancelled"} {
		if !validApprovalQueueStatusTransition("pending", next) {
			t.Fatalf("pending -> %s rejected", next)
		}
		other := "approved"
		if next == other {
			other = "rejected"
		}
		if validApprovalQueueStatusTransition(next, "pending") || validApprovalQueueStatusTransition(next, other) {
			t.Fatalf("terminal %s changed", next)
		}
	}
	if !validApprovalQueueStatusTransition("pending", "pending") {
		t.Fatal("pending no-op rejected")
	}
}

func TestRecordedDirectRouteAllowsInheritedRequesterPermissionEvidence(t *testing.T) {
	req := storeRequest()
	route := approval.Route{
		Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow,
		RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: req.RequesterUserID,
		RequesterPermission: approval.PermissionPublishLowRisk, RequesterPermissionOrgUnitID: "root",
		OrgPath: []string{req.OrgUnitID}, PolicyVersion: req.PolicyVersion,
	}
	if !validRecordedRoute(req, route) {
		t.Fatalf("inherited requester permission rejected: %+v", route)
	}
}

func TestRecordedReviewRouteAllowsInheritedReviewerPermissionEvidence(t *testing.T) {
	req := storeRequest()
	route := approval.Route{
		Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh,
		RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID,
		ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", ReviewerPermission: approval.PermissionApproveHighRisk,
		ReviewerPermissionOrgUnitID: "root", OrgPath: []string{req.OrgUnitID, "dept"}, PolicyVersion: req.PolicyVersion,
	}
	if !validRecordedRoute(req, route) {
		t.Fatalf("inherited reviewer permission rejected: %+v", route)
	}
}

func storeRequest() approval.Request {
	return approval.Request{EnterpriseID: "enterprise-1", RequesterUserID: "requester", OrgVersion: 7, OrgUnitID: "team", ResourceType: "knowledge", ResourceID: "article-1", Action: "knowledge.publish_low_risk", Facts: approval.NewVerifiedChangeFacts(approval.VerifiedChangeFactsInput{ChangedFields: []string{"title"}, Digest: strings.Repeat("c", 64)}), PolicyVersion: 1, IdempotencyHash: strings.Repeat("d", 64), ReplayHash: strings.Repeat("a", 64)}
}
