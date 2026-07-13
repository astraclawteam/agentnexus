package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type fakeGrantReader struct {
	row db.GetStepGrantByTokenHashRow
	err error
}

func (f fakeGrantReader) GetGrantResourceOwner(context.Context, db.GetGrantResourceOwnerParams) (db.SensitiveResourceOwnership, error) {
	return db.SensitiveResourceOwnership{}, errors.New("unused")
}

func (f fakeGrantReader) GetStepGrantByTokenHash(context.Context, db.GetStepGrantByTokenHashParams) (db.GetStepGrantByTokenHashRow, error) {
	return f.row, f.err
}

func TestStepGrantTrustVerifierResolvesIdentityAndTranslatesErrors(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	validHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	validRow := db.GetStepGrantByTokenHashRow{ID: "grant_1", EnterpriseID: "ent_1", ActorUserID: "user_1", CaseTicketID: "ticket_1", TokenHash: validHash, ExpiresAt: pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true}}

	t.Run("resolves bound identity", func(t *testing.T) {
		store := &PostgresGrantStore{reader: fakeGrantReader{row: validRow}}
		identity, err := store.LookupStepGrantIdentity(context.Background(), "ent_1", validHash)
		if err != nil {
			t.Fatalf("LookupStepGrantIdentity: %v", err)
		}
		if identity.TenantRef != "ent_1" || identity.PrincipalRef != "user_1" || identity.TicketRef != "ticket_1" || identity.GrantRef != "grant_1" || !identity.ExpiresAt.Equal(now.Add(time.Minute)) {
			t.Fatalf("identity=%+v", identity)
		}
	})

	for _, tc := range []struct {
		name  string
		store *PostgresGrantStore
		hash  string
		want  error
	}{
		{name: "no reader", store: &PostgresGrantStore{}, hash: validHash, want: trust.ErrSourceUnavailable},
		{name: "short hash", store: &PostgresGrantStore{reader: fakeGrantReader{row: validRow}}, hash: "short", want: trust.ErrSourceUnavailable},
		{name: "no rows rejects", store: &PostgresGrantStore{reader: fakeGrantReader{err: pgx.ErrNoRows}}, hash: validHash, want: trust.ErrCredentialRejected},
		{name: "database fault unavailable", store: &PostgresGrantStore{reader: fakeGrantReader{err: errors.New("db down")}}, hash: validHash, want: trust.ErrSourceUnavailable},
		{name: "cross enterprise row rejected", store: &PostgresGrantStore{reader: fakeGrantReader{row: func() db.GetStepGrantByTokenHashRow { r := validRow; r.EnterpriseID = "ent_2"; return r }()}}, hash: validHash, want: trust.ErrCredentialRejected},
		{name: "grant without expiry rejected", store: &PostgresGrantStore{reader: fakeGrantReader{row: func() db.GetStepGrantByTokenHashRow { r := validRow; r.ExpiresAt = pgtype.Timestamptz{}; return r }()}}, hash: validHash, want: trust.ErrCredentialRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.store.LookupStepGrantIdentity(context.Background(), "ent_1", tc.hash)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}

	t.Run("adapter hashes token before lookup", func(t *testing.T) {
		hashed := tickets.HashStepGrantToken("opaque-grant-token")
		row := validRow
		row.TokenHash = hashed
		verifier := NewPostgresStepGrantVerifier("ent_1", &PostgresGrantStore{reader: fakeGrantReader{row: row}})
		identity, err := verifier.VerifyStepGrant(context.Background(), "opaque-grant-token")
		if err != nil || identity.GrantRef != "grant_1" {
			t.Fatalf("identity=%+v err=%v", identity, err)
		}
	})
}

type fakeGrantWriteTx struct {
	owner                 db.SensitiveResourceOwnership
	ticket                db.CaseTicket
	latest                int64
	previous              string
	steps                 []string
	fail                  string
	committed, rolledBack bool
	issuance              db.InsertStepGrantIssuanceParams
	audit                 db.AppendAuditEventParams
	grantRow              db.GetStepGrantByTokenHashRow
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
func (f *fakeGrantWriteTx) GetGrantResourceOwnerForGrant(context.Context, db.GetGrantResourceOwnerForGrantParams) (db.SensitiveResourceOwnership, error) {
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
func (f *fakeGrantWriteTx) InsertStepGrantIssuance(_ context.Context, p db.InsertStepGrantIssuanceParams) (db.StepGrantIssuance, error) {
	f.issuance = p
	return db.StepGrantIssuance{}, f.mark("issuance")
}
func (f *fakeGrantWriteTx) GetStepGrantByTokenHash(context.Context, db.GetStepGrantByTokenHashParams) (db.GetStepGrantByTokenHashRow, error) {
	return f.grantRow, f.mark("verify_read")
}
func (f *fakeGrantWriteTx) AppendAuditEvent(_ context.Context, p db.AppendAuditEventParams) error {
	f.audit = p
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
	if tx.issuance.ExpectedAuditInputHash != tx.audit.InputHash.String || tx.issuance.ExpectedAuditOutputHash != tx.audit.OutputHash.String || !tx.audit.InputHash.Valid || !tx.audit.OutputHash.Valid {
		t.Fatalf("issuance/audit hashes not durably bound: issuance=%+v audit=%+v", tx.issuance, tx.audit)
	}
	if !tx.audit.EvidencePointer.Valid || tx.audit.EvidencePointer.String != "grant_1" {
		t.Fatalf("audit pointer=%+v", tx.audit.EvidencePointer)
	}
}

func TestPostgresGrantStoreRollsBackAuditFailureAndRejectsStaleOwnership(t *testing.T) {
	base := &fakeGrantWriteTx{latest: 7, ticket: db.CaseTicket{ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}, owner: db.SensitiveResourceOwnership{EnterpriseID: "ent_1", ResourceType: "dream_evidence", ResourceID: "ev-1", OrgVersion: 7, OrgUnitID: "research"}}
	grant := tickets.StepGrant{ID: "grant_1", TokenHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EnterpriseID: "ent_1", ActorUserID: "user_1", CaseTicketID: "ticket_1", OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scopes: []string{"dream:evidence:read"}, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	for _, tc := range []struct {
		name   string
		mutate func(*fakeGrantWriteTx)
	}{{"issuance", func(tx *fakeGrantWriteTx) { tx.fail = "issuance" }}, {"audit", func(tx *fakeGrantWriteTx) { tx.fail = "audit" }}, {"stale", func(tx *fakeGrantWriteTx) { tx.latest = 8 }}} {
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

func TestPostgresGrantStoreVerifiesAndAuditsInOneTransaction(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	row := db.GetStepGrantByTokenHashRow{ID: "grant_1", EnterpriseID: "ent_1", CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scopes: []byte(`["dream:evidence:read"]`), ExpiresAt: pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true}, CreatedAt: pgtype.Timestamptz{Time: now.Add(-time.Minute), Valid: true}, TokenHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ActorUserID: "user_1", OrgVersion: 7, OrgUnitID: "research"}
	actor := tickets.Actor{EnterpriseID: "ent_1", UserID: "user_1", OrgVersion: 7}
	input := tickets.VerifyStepGrantInput{ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scope: "dream:evidence:read"}
	for _, tc := range []struct {
		name       string
		fail       string
		wantCommit bool
	}{
		{name: "success", wantCommit: true},
		{name: "audit failure", fail: "audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fakeGrantWriteTx{grantRow: row, fail: tc.fail}
			store := newPostgresGrantStoreWithPool(fakeGrantPool{tx})
			_, err := store.VerifyStepGrantAndAudit(context.Background(), actor, input, row.TokenHash, "verify_audit", now)
			if tc.wantCommit && err != nil {
				t.Fatal(err)
			}
			if !tc.wantCommit && err == nil {
				t.Fatal("audit failure returned successful verification")
			}
			if tx.committed != tc.wantCommit || (!tc.wantCommit && !tx.rolledBack) {
				t.Fatalf("commit=%v rollback=%v steps=%v", tx.committed, tx.rolledBack, tx.steps)
			}
			if tc.wantCommit {
				want := []string{"verify_read", "audit_lock", "audit_hash", "audit", "commit"}
				if !reflect.DeepEqual(tx.steps, want) {
					t.Fatalf("steps=%v want=%v", tx.steps, want)
				}
				if tx.audit.Action != "step_grant.verify" || tx.audit.EnterpriseID != "ent_1" || tx.audit.CaseTicketID.String != "ticket_1" || tx.audit.StepGrantID.String != "grant_1" || tx.audit.ResourceID.String != "ev-1" || !tx.audit.InputHash.Valid || !tx.audit.OutputHash.Valid {
					t.Fatalf("audit not fully bound: %+v", tx.audit)
				}
			}
		})
	}
}
