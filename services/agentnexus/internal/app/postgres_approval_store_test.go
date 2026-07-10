package app

import (
	"bytes"
	"context"
	"errors"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/jackc/pgx/v5"
)

type fakeApprovalWriteTx struct {
	order      []string
	insertErr  error
	auditErr   error
	commitErr  error
	rolledBack bool
}

func (t *fakeApprovalWriteTx) AcquireEnterpriseAuditLock(context.Context, string) (any, error) {
	t.order = append(t.order, "lock")
	return nil, nil
}
func (t *fakeApprovalWriteTx) GetLatestEnterpriseAuditHash(context.Context, string) (string, error) {
	t.order = append(t.order, "hash")
	return "", nil
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
	route := approval.Route{Mode: approval.ModeUpwardReview, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, ReviewerUserID: "reviewer", ReviewerDisplayName: "Reviewer", OrgPath: []string{"team", "root"}}
	if err := store.Record(context.Background(), req, route); err != nil {
		t.Fatal(err)
	}
	want := []string{"lock", "hash", "queue", "audit", "commit"}
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tc.tx}, bytes.NewReader(make([]byte, 4096)))
			req := storeRequest()
			route := approval.Route{Mode: approval.ModeEnterpriseKnowledgeAdminQueue, RiskLevel: approval.RiskHigh, RiskReasons: []approval.RiskReason{approval.RiskReasonExternalSideEffect}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team", "root"}, Queue: approval.EnterpriseKnowledgeAdminQueue}
			if err := store.Record(context.Background(), req, route); err == nil {
				t.Fatal("expected error")
			}
			if !tc.tx.rolledBack {
				t.Fatal("transaction not rolled back")
			}
			for _, step := range tc.tx.order {
				if step == "commit" {
					t.Fatalf("committed after failure: %v", tc.tx.order)
				}
			}
		})
	}
}

func TestPostgresApprovalStoreDirectLowSkipsQueueButAudits(t *testing.T) {
	tx := &fakeApprovalWriteTx{}
	store := newPostgresApprovalStoreWithPool(&fakeApprovalWritePool{tx: tx}, bytes.NewReader(make([]byte, 4096)))
	req := storeRequest()
	route := approval.Route{Mode: approval.ModeSingleConfirmation, RiskLevel: approval.RiskLow, RiskReasons: []approval.RiskReason{}, RequesterUserID: req.RequesterUserID, OrgPath: []string{"team"}}
	if err := store.Record(context.Background(), req, route); err != nil {
		t.Fatal(err)
	}
	for _, step := range tx.order {
		if step == "queue" {
			t.Fatalf("direct low queued: %v", tx.order)
		}
	}
}
