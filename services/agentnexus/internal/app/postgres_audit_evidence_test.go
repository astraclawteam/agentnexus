package app

import (
	"bytes"
	"context"
	"errors"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
)

type fakeAuditEvidenceDB struct{ tx *fakeAuditEvidenceTx }

func (f *fakeAuditEvidenceDB) BeginAuditEvidenceTx(context.Context, pgx.TxOptions) (auditEvidenceTx, error) {
	f.tx.order = append(f.tx.order, "begin")
	return f.tx, nil
}

type fakeAuditEvidenceTx struct {
	order     []string
	params    db.AppendAuditEventParams
	appendErr error
}

func (f *fakeAuditEvidenceTx) AcquireEnterpriseAuditLock(context.Context, string) (any, error) {
	f.order = append(f.order, "lock")
	return nil, nil
}
func (f *fakeAuditEvidenceTx) GetLatestEnterpriseAuditHash(context.Context, string) (string, error) {
	f.order = append(f.order, "previous")
	return "sha256:prev", nil
}
func (f *fakeAuditEvidenceTx) AppendAuditEvent(_ context.Context, p db.AppendAuditEventParams) (db.AuditEvent, error) {
	f.order = append(f.order, "append")
	f.params = p
	return db.AuditEvent{}, f.appendErr
}
func (f *fakeAuditEvidenceTx) Commit(context.Context) error {
	f.order = append(f.order, "commit")
	return nil
}
func (f *fakeAuditEvidenceTx) Rollback(context.Context) error {
	f.order = append(f.order, "rollback")
	return nil
}

func TestPostgresAuditEvidencePersistsRequestedLineageInSerializedTransaction(t *testing.T) {
	tx := &fakeAuditEvidenceTx{}
	sink := newPostgresAuditEvidenceSinkWithDB(&fakeAuditEvidenceDB{tx: tx}, bytes.NewReader(make([]byte, 18)))
	id, err := sink.AppendAuditEvidence(context.Background(), AuditEvidenceInput{EnterpriseID: "ent-1", ActorUserID: "u-1", CaseTicketID: "case-internal", Action: AuditActionDreamPolicyCreateRequested, ResourceType: "dream_policy", ResourceID: "pol-1", TraceID: "trace-1", Details: map[string]any{"phase": "create_requested"}})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || tx.params.CaseTicketID.String != "case-internal" || tx.params.ResourceType.String != "dream_policy" || tx.params.ResourceID.String != "pol-1" || tx.params.Action != "dream_policy_create_requested" || tx.params.Decision != "requested" || !tx.params.InputHash.Valid || tx.params.PrevHash.String != "sha256:prev" {
		t.Fatalf("id=%q params=%+v", id, tx.params)
	}
	want := []string{"begin", "lock", "previous", "append", "commit", "rollback"}
	if len(tx.order) != len(want) {
		t.Fatalf("order=%v", tx.order)
	}
	for i := range want {
		if tx.order[i] != want[i] {
			t.Fatalf("order=%v", tx.order)
		}
	}
}

func TestPostgresAuditEvidenceRollsBackOnAppendFailure(t *testing.T) {
	tx := &fakeAuditEvidenceTx{appendErr: errors.New("down")}
	sink := newPostgresAuditEvidenceSinkWithDB(&fakeAuditEvidenceDB{tx: tx}, bytes.NewReader(make([]byte, 18)))
	_, err := sink.AppendAuditEvidence(context.Background(), AuditEvidenceInput{EnterpriseID: "ent", ActorUserID: "u", CaseTicketID: "case", Action: AuditActionDreamPolicyCreateRequested, ResourceType: "dream_policy", ResourceID: "pol"})
	if err == nil {
		t.Fatal("append failure accepted")
	}
	for _, step := range tx.order {
		if step == "commit" {
			t.Fatalf("committed after failure: %v", tx.order)
		}
	}
	if tx.order[len(tx.order)-1] != "rollback" {
		t.Fatalf("no rollback: %v", tx.order)
	}
}
