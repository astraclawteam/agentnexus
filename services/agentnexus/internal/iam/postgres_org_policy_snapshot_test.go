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
	calls      []string
	args       [][]any
	failAt     string
	committed  bool
	rolledBack bool
}

func (f *fakeIAMSnapshotTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.calls = append(f.calls, "version")
	f.args = append(f.args, args)
	err := error(nil)
	if f.failAt == "version" {
		err = errors.New("version insert failed")
	}
	return fakeOrgVersionRow{args: args, err: err}
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

func (f *fakeIAMSnapshotTx) Rollback(context.Context) error {
	if f.committed || f.rolledBack {
		return pgx.ErrTxClosed
	}
	f.calls = append(f.calls, "rollback")
	f.rolledBack = true
	return nil
}

type fakeOrgVersionRow struct {
	args []any
	err  error
}

func (r fakeOrgVersionRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.args[0].(string)
	*(dest[1].(*string)) = r.args[1].(string)
	*(dest[2].(*int64)) = r.args[2].(int64)
	*(dest[3].(*pgtype.Text)) = r.args[3].(pgtype.Text)
	*(dest[4].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: time.Unix(100, 0).UTC(), Valid: true}
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
	if !reflect.DeepEqual(tx.calls, []string{"begin", "version", "units", "memberships", "commit"}) {
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
	for _, failAt := range []string{"version", "units", "memberships", "commit"} {
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
