package iam

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type fakeIAMSnapshotDB struct {
	db.DBTX
	tx       *fakeIAMSnapshotTx
	options  []pgx.TxOptions
	beginErr error
}

func (f *fakeIAMSnapshotDB) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	f.options = append(f.options, options)
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	f.tx.calls = append(f.tx.calls, "begin")
	return f.tx, nil
}

type fakeIAMSnapshotTx struct {
	pgx.Tx
	calls               []string
	args                [][]any
	failAt              string
	committed           bool
	rolledBack          bool
	cancelAt            string
	cancel              context.CancelFunc
	rollbackContextErr  error
	rollbackHasDeadline bool
	rollbackErr         error
}

func (f *fakeIAMSnapshotTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	call := "version"
	switch {
	case strings.Contains(sql, "INSERT INTO org_events"):
		call = "event"
	case strings.Contains(sql, "UPDATE org_versions"):
		call = "seal"
	}
	f.calls = append(f.calls, call)
	f.args = append(f.args, args)
	err := error(nil)
	if f.cancelAt == call && f.cancel != nil {
		f.cancel()
	}
	if f.failAt == call {
		err = errors.New(call + " failed")
	}
	return fakePublicationRow{kind: call, args: args, err: err}
}

func (f *fakeIAMSnapshotTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	call := ""
	switch {
	case strings.Contains(sql, "org_policy_snapshot_memberships"):
		call = "memberships"
	case strings.Contains(sql, "org_policy_snapshot_units"):
		call = "units"
	default:
		panic("unexpected SQL: " + sql)
	}
	f.calls = append(f.calls, call)
	f.args = append(f.args, args)
	if f.failAt == call {
		return pgconn.CommandTag{}, errors.New(call + " capture failed")
	}
	if f.cancelAt == call && f.cancel != nil {
		f.cancel()
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (f *fakeIAMSnapshotTx) Commit(context.Context) error {
	f.calls = append(f.calls, "commit")
	if f.failAt == "commit" {
		return errors.New("commit failed")
	}
	f.committed = true
	return nil
}

func (f *fakeIAMSnapshotTx) Rollback(ctx context.Context) error {
	f.rollbackContextErr = ctx.Err()
	_, f.rollbackHasDeadline = ctx.Deadline()
	if f.committed || f.rolledBack {
		return pgx.ErrTxClosed
	}
	f.calls = append(f.calls, "rollback")
	f.rolledBack = true
	return f.rollbackErr
}

type fakePublicationRow struct {
	kind string
	args []any
	err  error
}

func (r fakePublicationRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if r.kind == "event" {
		*(dest[0].(*string)) = r.args[0].(string)
		*(dest[1].(*string)) = r.args[1].(string)
		*(dest[2].(*string)) = r.args[2].(string)
		*(dest[3].(*pgtype.Text)) = r.args[3].(pgtype.Text)
		*(dest[4].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: time.Unix(90, 0).UTC(), Valid: true}
		return nil
	}
	if r.kind == "seal" {
		*(dest[0].(*string)) = "version-id"
		*(dest[1].(*string)) = r.args[0].(string)
		*(dest[2].(*int64)) = r.args[1].(int64)
		*(dest[3].(*pgtype.Text)) = pgtype.Text{String: "event-id", Valid: true}
		*(dest[4].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: time.Unix(100, 0).UTC(), Valid: true}
		*(dest[5].(*bool)) = true
		return nil
	}
	*(dest[0].(*string)) = r.args[0].(string)
	*(dest[1].(*string)) = r.args[1].(string)
	*(dest[2].(*int64)) = r.args[2].(int64)
	*(dest[3].(*pgtype.Text)) = r.args[3].(pgtype.Text)
	*(dest[4].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: time.Unix(100, 0).UTC(), Valid: true}
	*(dest[5].(*bool)) = false
	return nil
}

func TestPostgresCreateOrgVersionPublishesImmutableSnapshotInOneTransaction(t *testing.T) {
	t.Parallel()
	tx := &fakeIAMSnapshotTx{}
	database := &fakeIAMSnapshotDB{tx: tx}
	store := newPostgresStoreWithDB(database)

	version, err := store.CreateOrgVersion(context.Background(), OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
	if err != nil {
		t.Fatal(err)
	}
	if version.ID != "version-id" || version.EnterpriseID != "enterprise-1" || version.VersionNumber != 23 || version.SourceEventID != "event-id" {
		t.Fatalf("version = %#v", version)
	}
	if len(database.options) != 1 {
		t.Fatalf("BeginTx calls = %d", len(database.options))
	}
	if database.options[0].IsoLevel != pgx.RepeatableRead || database.options[0].AccessMode != pgx.ReadWrite {
		t.Fatalf("publication transaction options = %#v", database.options[0])
	}
	if !reflect.DeepEqual(tx.calls, []string{"begin", "version", "units", "memberships", "seal", "commit"}) {
		t.Fatalf("calls = %#v", tx.calls)
	}
	for _, args := range tx.args[1:] {
		if !reflect.DeepEqual(args, []any{"enterprise-1", int64(23)}) {
			t.Fatalf("snapshot args = %#v", args)
		}
	}
}

func TestPostgresCreateOrgVersionRollsBackEveryFailure(t *testing.T) {
	t.Parallel()
	for _, failAt := range []string{"version", "units", "memberships", "seal", "commit"} {
		t.Run(failAt, func(t *testing.T) {
			tx := &fakeIAMSnapshotTx{failAt: failAt}
			store := newPostgresStoreWithDB(&fakeIAMSnapshotDB{tx: tx})
			_, err := store.CreateOrgVersion(context.Background(), OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
			if err == nil {
				t.Fatal("failure was accepted")
			}
			if tx.committed || !tx.rolledBack || tx.calls[len(tx.calls)-1] != "rollback" {
				t.Fatalf("calls=%#v committed=%t rolledBack=%t", tx.calls, tx.committed, tx.rolledBack)
			}
			for _, forbidden := range tx.calls {
				if failAt != "commit" && forbidden == "commit" {
					t.Fatalf("commit after %s failure: %#v", failAt, tx.calls)
				}
			}
		})
	}
}

func TestPostgresPublishOrgVersionIncludesEventAndSealAtomically(t *testing.T) {
	t.Parallel()
	tx := &fakeIAMSnapshotTx{}
	store := newPostgresStoreWithDB(&fakeIAMSnapshotDB{tx: tx})
	version, err := store.PublishOrgVersion(context.Background(), OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import", SourceHash: "source"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
	if err != nil {
		t.Fatal(err)
	}
	if version.ID != "version-id" || !reflect.DeepEqual(tx.calls, []string{"begin", "event", "version", "units", "memberships", "seal", "commit"}) {
		t.Fatalf("version=%#v calls=%#v", version, tx.calls)
	}
}

func TestPostgresPublishOrgVersionRejectsInvalidLinkageBeforeBegin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		event   OrgEvent
		version OrgVersion
	}{
		{name: "enterprise mismatch", event: OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version-id", EnterpriseID: "enterprise-2", VersionNumber: 23, SourceEventID: "event-id"}},
		{name: "source event mismatch", event: OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "other-event"}},
		{name: "blank event id", event: OrgEvent{EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23}},
		{name: "noncanonical version id", event: OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, version: OrgVersion{ID: " version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := &fakeIAMSnapshotDB{tx: &fakeIAMSnapshotTx{}}
			store := newPostgresStoreWithDB(database)
			if _, err := store.PublishOrgVersion(context.Background(), test.event, test.version); err == nil {
				t.Fatal("invalid publication was accepted")
			}
			if len(database.options) != 0 {
				t.Fatalf("invalid publication began %d transactions", len(database.options))
			}
		})
	}
}

func TestPostgresPublishOrgVersionRollsBackEventAndUsesBoundedCleanupAfterCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	tx := &fakeIAMSnapshotTx{failAt: "memberships", cancelAt: "memberships", cancel: cancel}
	store := newPostgresStoreWithDB(&fakeIAMSnapshotDB{tx: tx})
	_, err := store.PublishOrgVersion(ctx, OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
	if err == nil || !strings.Contains(err.Error(), "memberships capture failed") {
		t.Fatalf("error = %v", err)
	}
	if !tx.rolledBack || tx.rollbackContextErr != nil || !tx.rollbackHasDeadline {
		t.Fatalf("cleanup rollback=%t contextErr=%v deadline=%t calls=%#v", tx.rolledBack, tx.rollbackContextErr, tx.rollbackHasDeadline, tx.calls)
	}
}

func TestPostgresPublishOrgVersionEventFailureLeavesNothingCommitted(t *testing.T) {
	t.Parallel()
	tx := &fakeIAMSnapshotTx{failAt: "event"}
	store := newPostgresStoreWithDB(&fakeIAMSnapshotDB{tx: tx})
	_, err := store.PublishOrgVersion(context.Background(), OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
	if err == nil || tx.committed || !tx.rolledBack || !reflect.DeepEqual(tx.calls, []string{"begin", "event", "rollback"}) {
		t.Fatalf("error=%v committed=%t rolledBack=%t calls=%#v", err, tx.committed, tx.rolledBack, tx.calls)
	}
}

func TestPostgresPublishOrgVersionJoinsCleanupFailureWithoutHidingOriginal(t *testing.T) {
	t.Parallel()
	cleanupErr := errors.New("rollback transport failed")
	tx := &fakeIAMSnapshotTx{failAt: "memberships", rollbackErr: cleanupErr}
	store := newPostgresStoreWithDB(&fakeIAMSnapshotDB{tx: tx})
	_, err := store.PublishOrgVersion(context.Background(), OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
	if !errors.Is(err, cleanupErr) || !strings.Contains(err.Error(), "memberships capture failed") {
		t.Fatalf("joined error = %v", err)
	}
}
