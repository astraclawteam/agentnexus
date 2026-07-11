package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
)

type fakeAuditEvidenceDB struct {
	tx       *fakeAuditEvidenceTx
	txs      []*fakeAuditEvidenceTx
	beginErr error
	latest   string
}

func (f *fakeAuditEvidenceDB) BeginAuditEvidenceTx(context.Context, pgx.TxOptions) (auditEvidenceTx, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	tx := f.tx
	if tx == nil {
		tx = &fakeAuditEvidenceTx{}
		f.txs = append(f.txs, tx)
	}
	tx.database = f
	tx.order = append(tx.order, "begin")
	return tx, nil
}

type fakeAuditEvidenceTx struct {
	database            *fakeAuditEvidenceDB
	order               []string
	params              db.AppendAuditEventParams
	lockErr             error
	latestErr           error
	appendErr           error
	commitErr           error
	rollbackErr         error
	cancelOnLock        context.CancelFunc
	rollbackContextErr  error
	rollbackHasDeadline bool
	committed           bool
}

func (f *fakeAuditEvidenceTx) AcquireEnterpriseAuditLock(context.Context, string) (any, error) {
	f.order = append(f.order, "lock")
	if f.cancelOnLock != nil {
		f.cancelOnLock()
	}
	return nil, f.lockErr
}

func (f *fakeAuditEvidenceTx) GetLatestEnterpriseAuditHash(context.Context, string) (string, error) {
	f.order = append(f.order, "previous")
	if f.latestErr != nil {
		return "", f.latestErr
	}
	return f.database.latest, nil
}

func (f *fakeAuditEvidenceTx) AppendAuditEvent(_ context.Context, params db.AppendAuditEventParams) (db.AuditEvent, error) {
	f.order = append(f.order, "append")
	f.params = params
	return db.AuditEvent{}, f.appendErr
}

func (f *fakeAuditEvidenceTx) Commit(context.Context) error {
	f.order = append(f.order, "commit")
	if f.commitErr == nil {
		f.committed = true
		f.database.latest = f.params.EventHash
	}
	return f.commitErr
}

func (f *fakeAuditEvidenceTx) Rollback(ctx context.Context) error {
	f.order = append(f.order, "rollback")
	f.rollbackContextErr = ctx.Err()
	_, f.rollbackHasDeadline = ctx.Deadline()
	if f.committed && f.rollbackErr == nil {
		return pgx.ErrTxClosed
	}
	return f.rollbackErr
}

func validAuditEvidenceInput(resourceID string) AuditEvidenceInput {
	return AuditEvidenceInput{EnterpriseID: "ent-1", ActorUserID: "u-1", CaseTicketID: "case-internal", Action: AuditActionDreamPolicyCreateRequested, ResourceType: "dream_policy", ResourceID: resourceID, TraceID: "trace-1", Details: map[string]any{"phase": "create_requested"}}
}

func assertAuditEvidenceOrder(t *testing.T, tx *fakeAuditEvidenceTx, want string) {
	t.Helper()
	if got := strings.Join(tx.order, ","); got != want {
		t.Fatalf("order=%s want=%s", got, want)
	}
}

func TestPostgresAuditEvidencePersistsRequestedLineageInSerializedTransaction(t *testing.T) {
	tx := &fakeAuditEvidenceTx{}
	database := &fakeAuditEvidenceDB{tx: tx, latest: "sha256:prev"}
	sink := newPostgresAuditEvidenceSinkWithDB(database, bytes.NewReader(make([]byte, 18)))
	id, err := sink.AppendAuditEvidence(context.Background(), validAuditEvidenceInput("pol-1"))
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || tx.params.CaseTicketID.String != "case-internal" || tx.params.ResourceType.String != "dream_policy" || tx.params.ResourceID.String != "pol-1" || tx.params.Action != "dream_policy_create_requested" || tx.params.Decision != "requested" || tx.params.PrevHash.String != "sha256:prev" {
		t.Fatalf("id=%q params=%+v", id, tx.params)
	}
	const wantInputHash = "sha256:bcfc24af76cbd804add2a4f9216879a3662113625d6cf4f902246bbf61cde229"
	if tx.params.InputHash.String != wantInputHash {
		t.Fatalf("input hash=%q want=%q", tx.params.InputHash.String, wantInputHash)
	}
	assertAuditEvidenceOrder(t, tx, "begin,lock,previous,append,commit,rollback")
}

func TestPostgresAuditEvidenceLinksTwoSerializedEvents(t *testing.T) {
	database := &fakeAuditEvidenceDB{}
	sink := newPostgresAuditEvidenceSinkWithDB(database, bytes.NewReader(make([]byte, 36)))
	if _, err := sink.AppendAuditEvidence(context.Background(), validAuditEvidenceInput("pol-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.AppendAuditEvidence(context.Background(), validAuditEvidenceInput("pol-2")); err != nil {
		t.Fatal(err)
	}
	if len(database.txs) != 2 {
		t.Fatalf("transactions=%d", len(database.txs))
	}
	first, second := database.txs[0], database.txs[1]
	if second.params.PrevHash.String != first.params.EventHash {
		t.Fatalf("second prev=%q first event=%q", second.params.PrevHash.String, first.params.EventHash)
	}
	assertAuditEvidenceOrder(t, first, "begin,lock,previous,append,commit,rollback")
	assertAuditEvidenceOrder(t, second, "begin,lock,previous,append,commit,rollback")
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestPostgresAuditEvidenceRollsBackEveryTransactionFailure(t *testing.T) {
	failure := errors.New("operation failed")
	for _, test := range []struct {
		name      string
		configure func(*fakeAuditEvidenceDB, *fakeAuditEvidenceTx) io.Reader
		wantOrder string
	}{
		{name: "lock", configure: func(_ *fakeAuditEvidenceDB, tx *fakeAuditEvidenceTx) io.Reader {
			tx.lockErr = failure
			return bytes.NewReader(make([]byte, 18))
		}, wantOrder: "begin,lock,rollback"},
		{name: "latest", configure: func(_ *fakeAuditEvidenceDB, tx *fakeAuditEvidenceTx) io.Reader {
			tx.latestErr = failure
			return bytes.NewReader(make([]byte, 18))
		}, wantOrder: "begin,lock,previous,rollback"},
		{name: "random", configure: func(_ *fakeAuditEvidenceDB, _ *fakeAuditEvidenceTx) io.Reader { return failingReader{err: failure} }, wantOrder: "begin,lock,previous,rollback"},
		{name: "append", configure: func(_ *fakeAuditEvidenceDB, tx *fakeAuditEvidenceTx) io.Reader {
			tx.appendErr = failure
			return bytes.NewReader(make([]byte, 18))
		}, wantOrder: "begin,lock,previous,append,rollback"},
		{name: "commit", configure: func(_ *fakeAuditEvidenceDB, tx *fakeAuditEvidenceTx) io.Reader {
			tx.commitErr = failure
			return bytes.NewReader(make([]byte, 18))
		}, wantOrder: "begin,lock,previous,append,commit,rollback"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &fakeAuditEvidenceTx{}
			database := &fakeAuditEvidenceDB{tx: tx}
			random := test.configure(database, tx)
			_, err := newPostgresAuditEvidenceSinkWithDB(database, random).AppendAuditEvidence(context.Background(), validAuditEvidenceInput("pol"))
			if !errors.Is(err, failure) {
				t.Fatalf("error=%v", err)
			}
			assertAuditEvidenceOrder(t, tx, test.wantOrder)
		})
	}
}

func TestPostgresAuditEvidenceBeginFailureDoesNotRollback(t *testing.T) {
	failure := errors.New("begin failed")
	database := &fakeAuditEvidenceDB{beginErr: failure}
	_, err := newPostgresAuditEvidenceSinkWithDB(database, bytes.NewReader(make([]byte, 18))).AppendAuditEvidence(context.Background(), validAuditEvidenceInput("pol"))
	if !errors.Is(err, failure) || len(database.txs) != 0 {
		t.Fatalf("error=%v transactions=%d", err, len(database.txs))
	}
}

func TestPostgresAuditEvidenceRollbackSurvivesCancellationAndJoinsErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	operationErr := errors.New("lock failed")
	cleanupErr := errors.New("rollback failed")
	tx := &fakeAuditEvidenceTx{lockErr: operationErr, rollbackErr: cleanupErr, cancelOnLock: cancel}
	database := &fakeAuditEvidenceDB{tx: tx}
	_, err := newPostgresAuditEvidenceSinkWithDB(database, bytes.NewReader(make([]byte, 18))).AppendAuditEvidence(ctx, validAuditEvidenceInput("pol"))
	if !errors.Is(err, operationErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("joined error=%v", err)
	}
	if tx.rollbackContextErr != nil || !tx.rollbackHasDeadline {
		t.Fatalf("rollback context error=%v deadline=%t", tx.rollbackContextErr, tx.rollbackHasDeadline)
	}
	assertAuditEvidenceOrder(t, tx, "begin,lock,rollback")
}
