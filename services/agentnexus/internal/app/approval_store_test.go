package app

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
)

func TestMemoryApprovalStoreCreatesQueueOnlyForReviewRoutesAndAlwaysAudits(t *testing.T) {
	store := NewMemoryApprovalStore(bytes.NewReader(make([]byte, 4096)), nil)
	req := storeRequest()
	direct := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{}, RequesterUserID: req.RequesterUserID, OrgPath: []string{req.OrgUnitID}}
	if err := store.Record(context.Background(), req, direct); err != nil {
		t.Fatal(err)
	}
	review := approval.Route{Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", OrgPath: []string{"team", "root"}}
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
			store := NewMemoryApprovalStore(bytes.NewReader(make([]byte, 4096)), func(got ApprovalRecordStage) error {
				if got == stage {
					return errors.New("injected")
				}
				return nil
			})
			req := storeRequest()
			route := approval.Route{Mode: approval.ModeEnterpriseKnowledgeAdminQueue, RiskLevel: approval.RiskMedium, RiskReasons: []approval.RiskReason{approval.RiskReasonImpactedUserScope}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team", "root"}, Queue: approval.EnterpriseKnowledgeAdminQueue}
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
	store := NewMemoryApprovalStore(bytes.NewReader(make([]byte, 16384)), nil)
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team"}}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.Record(context.Background(), req, route)
		}()
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

func storeRequest() approval.Request {
	return approval.Request{EnterpriseID: "enterprise-1", RequesterUserID: "requester", OrgVersion: 7, OrgUnitID: "team", ResourceType: "workflow", ResourceID: "workflow-1", Action: "workflow.update", Risk: approval.RiskInput{ChangedFields: []string{"title"}}}
}
