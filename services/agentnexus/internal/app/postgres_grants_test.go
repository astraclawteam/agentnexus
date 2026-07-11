package app

import (
	"context"
	"errors"
	"testing"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type fakeGrantWriteTx struct {
	owner                 db.SensitiveResourceOwnership
	ticket                db.CaseTicket
	latest                int64
	previous              string
	steps                 []string
	fail                  string
	committed, rolledBack bool
}

func (f *fakeGrantWriteTx) mark(step string) error {
	f.steps = append(f.steps, step)
	if f.fail == step {
		return errors.New("failed")
	}
	return nil
}
func (f *fakeGrantWriteTx) AcquireEnterpriseOrgPublicationLock(context.Context, string) (any, error) {
	return nil, f.mark("org_lock")
}
func (f *fakeGrantWriteTx) GetActiveCaseTicketForGrant(context.Context, db.GetActiveCaseTicketForGrantParams) (db.CaseTicket, error) {
	return f.ticket, f.mark("ticket")
}
func (f *fakeGrantWriteTx) GetGrantResourceOwnerForUpdate(context.Context, db.GetGrantResourceOwnerForUpdateParams) (db.SensitiveResourceOwnership, error) {
	return f.owner, f.mark("owner")
}
func (f *fakeGrantWriteTx) GetLatestGrantOrgVersion(context.Context, string) (int64, error) {
	return f.latest, f.mark("version")
}
func (f *fakeGrantWriteTx) AcquireEnterpriseAuditLock(context.Context, string) (any, error) {
	return nil, f.mark("audit_lock")
}
func (f *fakeGrantWriteTx) GetLatestEnterpriseAuditHash(context.Context, string) (string, error) {
	return f.previous, f.mark("audit_hash")
}
func (f *fakeGrantWriteTx) CreateStepGrant(context.Context, db.CreateStepGrantParams) (db.StepGrant, error) {
	return db.StepGrant{}, f.mark("grant")
}
func (f *fakeGrantWriteTx) InsertStepGrantIssuance(context.Context, db.InsertStepGrantIssuanceParams) (db.StepGrantIssuance, error) {
	return db.StepGrantIssuance{}, f.mark("issuance")
}
func (f *fakeGrantWriteTx) AppendAuditEvent(context.Context, db.AppendAuditEventParams) error {
	return f.mark("audit")
}
func (f *fakeGrantWriteTx) Commit(context.Context) error   { f.committed = true; return f.mark("commit") }
func (f *fakeGrantWriteTx) Rollback(context.Context) error { f.rolledBack = true; return nil }

type fakeGrantPool struct{ tx *fakeGrantWriteTx }

func (f fakeGrantPool) BeginGrantWriteTx(context.Context, pgx.TxOptions) (grantWriteTx, error) {
	return f.tx, nil
}

func TestPostgresGrantStorePersistsGrantAndAuditAtomicallyAfterRevalidation(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	tx := &fakeGrantWriteTx{latest: 7, ticket: db.CaseTicket{ExpiresAt: pgtype.Timestamptz{Time: now.Add(30 * time.Second), Valid: true}}, owner: db.SensitiveResourceOwnership{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgVersion: 7, OrgUnitID: "research"}}
	store := newPostgresGrantStoreWithPool(fakeGrantPool{tx})
	grant := tickets.StepGrant{ID: "grant_1", TokenHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EnterpriseID: "ent_1", ActorUserID: "user_1", CaseTicketID: "ticket_1", OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scopes: []string{"dream:evidence:read"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	stored, err := store.CreateStepGrantAndAudit(context.Background(), grant, "audit_1")
	if err != nil {
		t.Fatal(err)
	}
	if !stored.ExpiresAt.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("expiry=%s", stored.ExpiresAt)
	}
	want := []string{"org_lock", "ticket", "owner", "version", "audit_lock", "audit_hash", "grant", "issuance", "audit", "commit"}
	if len(tx.steps) != len(want) {
		t.Fatalf("steps=%v", tx.steps)
	}
	for i := range want {
		if tx.steps[i] != want[i] {
			t.Fatalf("steps=%v", tx.steps)
		}
	}
	if !tx.committed {
		t.Fatal("not committed")
	}
}

func TestPostgresGrantStoreRollsBackAuditFailureAndRejectsStaleOwnership(t *testing.T) {
	base := &fakeGrantWriteTx{latest: 7, ticket: db.CaseTicket{ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}, owner: db.SensitiveResourceOwnership{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgVersion: 7, OrgUnitID: "research"}}
	grant := tickets.StepGrant{ID: "grant_1", TokenHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EnterpriseID: "ent_1", ActorUserID: "user_1", CaseTicketID: "ticket_1", OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scopes: []string{"dream:evidence:read"}, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	for _, tc := range []struct {
		name   string
		mutate func(*fakeGrantWriteTx)
	}{{"audit", func(tx *fakeGrantWriteTx) { tx.fail = "audit" }}, {"stale", func(tx *fakeGrantWriteTx) { tx.latest = 8 }}} {
		t.Run(tc.name, func(t *testing.T) {
			copy := *base
			copy.steps = nil
			tc.mutate(&copy)
			store := newPostgresGrantStoreWithPool(fakeGrantPool{&copy})
			if _, err := store.CreateStepGrantAndAudit(context.Background(), grant, "audit_1"); err == nil {
				t.Fatal("expected error")
			}
			if copy.committed || !copy.rolledBack {
				t.Fatalf("commit=%v rollback=%v", copy.committed, copy.rolledBack)
			}
		})
	}
}
