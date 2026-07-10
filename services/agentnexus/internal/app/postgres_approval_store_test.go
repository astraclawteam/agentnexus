package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/jackc/pgx/v5"
)

type fakeApprovalWriteTx struct {
	order         []string
	insertErr     error
	auditErr      error
	commitErr     error
	rolledBack    bool
	existing      *db.ApprovalResolutionIdempotency
	orgVersion    int64
	policyVersion int64
}

func (t *fakeApprovalWriteTx) AcquireEnterpriseOrgPublicationLock(context.Context, string) (any, error) {
	t.order = append(t.order, "org-lock")
	return nil, nil
}

func (t *fakeApprovalWriteTx) AcquireEnterpriseAuditLock(context.Context, string) (any, error) {
	t.order = append(t.order, "lock")
	return nil, nil
}
func (t *fakeApprovalWriteTx) GetLatestEnterpriseAuditHash(context.Context, string) (string, error) {
	t.order = append(t.order, "hash")
	return "", nil
}
func (t *fakeApprovalWriteTx) GetLatestApprovalOrgVersion(context.Context, string) (int64, error) {
	t.order = append(t.order, "org-version")
	if t.orgVersion == 0 {
		return 7, nil
	}
	return t.orgVersion, nil
}
func (t *fakeApprovalWriteTx) GetCurrentApprovalPolicyVersion(context.Context, string) (int64, error) {
	t.order = append(t.order, "policy-version")
	if t.policyVersion == 0 {
		return 1, nil
	}
	return t.policyVersion, nil
}
func (t *fakeApprovalWriteTx) GetApprovalResolution(context.Context, db.GetApprovalResolutionParams) (db.ApprovalResolutionIdempotency, error) {
	t.order = append(t.order, "existing")
	if t.existing == nil {
		return db.ApprovalResolutionIdempotency{}, pgx.ErrNoRows
	}
	return *t.existing, nil
}
func (t *fakeApprovalWriteTx) InsertApprovalResolution(context.Context, db.InsertApprovalResolutionParams) (int64, error) {
	t.order = append(t.order, "resolution")
	return 1, nil
}
func (t *fakeApprovalWriteTx) InsertApprovalQueueItem(context.Context, db.InsertApprovalQueueItemParams) error {
	t.order = append(t.order, "queue")
	return t.insertErr
}
func (t *fakeApprovalWriteTx) AppendAuditEvent(context.Context, db.AppendAuditEventParams) error {
	t.order = append(t.order, "audit")
	return t.auditErr
}
func (t *fakeApprovalWriteTx) Commit(context.Context) error {
	t.order = append(t.order, "commit")
	return t.commitErr
}
func (t *fakeApprovalWriteTx) Rollback(context.Context) error {
	t.rolledBack = true
	return nil
}

type fakeApprovalWritePool struct {
	tx      *fakeApprovalWriteTx
	options pgx.TxOptions
}

func (p *fakeApprovalWritePool) BeginApprovalWriteTx(_ context.Context, options pgx.TxOptions) (approvalWriteTx, error) {
	p.options = options
	return p.tx, nil
}

func TestPostgresApprovalStoreUsesOneTransactionAndAuditLock(t *testing.T) {
	tx := &fakeApprovalWriteTx{}
	store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tx}, bytes.NewReader(make([]byte, 4096)))
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", OrgPath: []string{"team", "root"}, PolicyVersion: req.PolicyVersion}
	if err := store.Record(context.Background(), req, route); err != nil {
		t.Fatal(err)
	}
	want := []string{"org-lock", "existing", "org-version", "policy-version", "lock", "hash", "resolution", "queue", "audit", "commit"}
	if len(tx.order) != len(want) {
		t.Fatalf("order=%v", tx.order)
	}
	for i := range want {
		if tx.order[i] != want[i] {
			t.Fatalf("order=%v want=%v", tx.order, want)
		}
	}
}

func TestPostgresApprovalStoreRollsBackQueueOrAuditFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		tx   *fakeApprovalWriteTx
	}{
		{name: "queue", tx: &fakeApprovalWriteTx{insertErr: errors.New("queue failed")}},
		{name: "audit", tx: &fakeApprovalWriteTx{auditErr: errors.New("audit failed")}},
		{name: "commit", tx: &fakeApprovalWriteTx{commitErr: errors.New("commit failed")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tc.tx}, bytes.NewReader(make([]byte, 4096)))
			req := storeRequest()
			route := approval.Route{Mode: approval.ModeEnterpriseKnowledgeAdminQueue, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team", "root"}, Queue: approval.EnterpriseKnowledgeAdminQueue, PolicyVersion: req.PolicyVersion}
			if err := store.Record(context.Background(), req, route); err == nil {
				t.Fatal("expected error")
			}
			if !tc.tx.rolledBack {
				t.Fatal("transaction not rolled back")
			}
			for _, step := range tc.tx.order {
				if step == "commit" && tc.name != "commit" {
					t.Fatalf("committed after failure: %v", tc.tx.order)
				}
			}
		})
	}
}

func TestPostgresApprovalStoreRandomFailureRollsBackBeforeResolutionInsert(t *testing.T) {
	tx := &fakeApprovalWriteTx{}
	store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tx}, bytes.NewReader([]byte{1}))
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
	if _, err := store.RecordResolution(context.Background(), req, route); err == nil || !tx.rolledBack || containsStep(tx.order, "resolution") {
		t.Fatalf("err=%v rollback=%v order=%v", err, tx.rolledBack, tx.order)
	}
}

func TestPostgresApprovalStoreDirectLowSkipsQueueButAudits(t *testing.T) {
	tx := &fakeApprovalWriteTx{}
	store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tx}, bytes.NewReader(make([]byte, 4096)))
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
	if err := store.Record(context.Background(), req, route); err != nil {
		t.Fatal(err)
	}
	for _, step := range tx.order {
		if step == "queue" {
			t.Fatalf("direct low queued: %v", tx.order)
		}
	}
}

func TestPostgresApprovalStoreReplaysBeforeStaleCheckAndDetectsConflict(t *testing.T) {
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
	requestHash := req.ReplayHash
	reasons, _ := json.Marshal(route.RiskReasons)
	path, _ := json.Marshal(route.OrgPath)
	existing := db.ApprovalResolutionIdempotency{EnterpriseID: req.EnterpriseID, IdempotencyKeyHash: req.IdempotencyHash, RequestHash: requestHash, RequesterUserID: req.RequesterUserID, OrgVersion: req.OrgVersion, OrgUnitID: req.OrgUnitID, PolicyVersion: req.PolicyVersion, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: req.Action, RouteMode: string(route.Mode), RiskLevel: string(route.RiskLevel), RiskReasons: reasons, OrgPath: path, AuditEventID: "audit-1"}
	tx := &fakeApprovalWriteTx{existing: &existing, orgVersion: 99, policyVersion: 99}
	store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tx}, bytes.NewReader(make([]byte, 4096)))
	replayed, err := store.RecordResolution(context.Background(), req, route)
	if err != nil || replayed.Mode != route.Mode || containsStep(tx.order, "org-version") || containsStep(tx.order, "audit") {
		t.Fatalf("route=%+v err=%v order=%v", replayed, err, tx.order)
	}
	existing.RequestHash = strings.Repeat("f", 64)
	tx = &fakeApprovalWriteTx{existing: &existing}
	store = newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tx}, bytes.NewReader(make([]byte, 4096)))
	if _, err := store.RecordResolution(context.Background(), req, route); !errors.Is(err, ErrApprovalIdempotencyConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestPostgresApprovalStoreRejectsStaleOrgOrPolicyBeforeAuditLock(t *testing.T) {
	for _, tx := range []*fakeApprovalWriteTx{{orgVersion: 8}, {orgVersion: 7, policyVersion: 2}} {
		store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tx}, bytes.NewReader(make([]byte, 4096)))
		req := storeRequest()
		route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{approval.RiskReasonExplicitConfirmation}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team"}, PolicyVersion: req.PolicyVersion}
		if _, err := store.RecordResolution(context.Background(), req, route); !errors.Is(err, ErrApprovalStale) || containsStep(tx.order, "lock") {
			t.Fatalf("err=%v order=%v", err, tx.order)
		}
	}
}

func containsStep(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
