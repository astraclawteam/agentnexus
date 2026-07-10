package iam

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type fakeIAMSnapshotDB struct {
	db.DBTX
	tx         *fakeIAMSnapshotTx
	conn       *fakeIAMPublicationConn
	options    []pgx.TxOptions
	beginErr   error
	acquireErr error
	calls      []string
}

func (f *fakeIAMSnapshotDB) AcquireOrgPublicationConn(context.Context) (orgPublicationConn, error) {
	f.calls = append(f.calls, "acquire")
	if f.acquireErr != nil {
		return nil, f.acquireErr
	}
	if f.conn == nil {
		f.conn = &fakeIAMPublicationConn{database: f, tx: f.tx, unlockOK: true}
	}
	return f.conn, nil
}

func (f *fakeIAMSnapshotDB) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	f.options = append(f.options, options)
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	f.tx.calls = append(f.tx.calls, "begin")
	return f.tx, nil
}

type fakeIAMPublicationConn struct {
	db.DBTX
	database          *fakeIAMSnapshotDB
	tx                *fakeIAMSnapshotTx
	lockErr           error
	unlockErr         error
	unlockOK          bool
	destroyErr        error
	released          bool
	destroyed         bool
	unlockContextErr  error
	unlockHasDeadline bool
	advisoryArgs      []string
}

func (c *fakeIAMPublicationConn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if len(args) == 1 {
		c.advisoryArgs = append(c.advisoryArgs, args[0].(string))
	}
	switch {
	case strings.Contains(sql, "pg_advisory_lock"):
		c.database.calls = append(c.database.calls, "session-lock")
		return fakeAdvisoryRow{err: c.lockErr, locked: true}
	case strings.Contains(sql, "pg_advisory_unlock"):
		c.database.calls = append(c.database.calls, "session-unlock")
		c.unlockContextErr = ctx.Err()
		_, c.unlockHasDeadline = ctx.Deadline()
		return fakeAdvisoryRow{err: c.unlockErr, locked: c.unlockOK}
	default:
		panic("unexpected connection SQL: " + sql)
	}
}

func (c *fakeIAMPublicationConn) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	c.database.calls = append(c.database.calls, "begin")
	c.database.options = append(c.database.options, options)
	if c.database.beginErr != nil {
		return nil, c.database.beginErr
	}
	c.tx.calls = append(c.tx.calls, "begin")
	return c.tx, nil
}

func (c *fakeIAMPublicationConn) Release() {
	c.database.calls = append(c.database.calls, "release")
	c.released = true
}

func (c *fakeIAMPublicationConn) Destroy(context.Context) error {
	c.database.calls = append(c.database.calls, "destroy")
	c.destroyed = true
	return c.destroyErr
}

type fakeAdvisoryRow struct {
	err    error
	locked bool
}

func (r fakeAdvisoryRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) == 1 {
		if value, ok := dest[0].(*bool); ok {
			*value = r.locked
		}
	}
	return nil
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
	beforeVersion       func(int64) error
	afterCommit         func()
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
	if call == "version" && f.beforeVersion != nil {
		err = f.beforeVersion(args[2].(int64))
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
	if f.afterCommit != nil {
		f.afterCommit()
	}
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

func TestPostgresPublicationLocksDedicatedConnectionBeforeBeginOnBothPaths(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		publish func(*PostgresStore) error
	}{
		{name: "direct", publish: func(store *PostgresStore) error {
			_, err := store.CreateOrgVersion(context.Background(), OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
			return err
		}},
		{name: "atomic service", publish: func(store *PostgresStore) error {
			_, err := store.PublishOrgVersion(context.Background(), OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &fakeIAMSnapshotTx{}
			database := &fakeIAMSnapshotDB{tx: tx}
			if err := test.publish(newPostgresStoreWithDB(database)); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(database.calls, []string{"acquire", "session-lock", "begin", "session-unlock", "release"}) {
				t.Fatalf("connection lifecycle = %#v", database.calls)
			}
			if len(database.options) != 1 || database.options[0].IsoLevel != pgx.RepeatableRead || database.options[0].AccessMode != pgx.ReadWrite {
				t.Fatalf("transaction options = %#v", database.options)
			}
			if database.conn.released == database.conn.destroyed || database.conn.unlockContextErr != nil || !database.conn.unlockHasDeadline {
				t.Fatalf("released=%t destroyed=%t unlockContextErr=%v deadline=%t", database.conn.released, database.conn.destroyed, database.conn.unlockContextErr, database.conn.unlockHasDeadline)
			}
			if !reflect.DeepEqual(database.conn.advisoryArgs, []string{"enterprise-1", "enterprise-1"}) {
				t.Fatalf("session lock/unlock keys = %#v", database.conn.advisoryArgs)
			}
		})
	}
}

func TestPostgresPublicationUnlockFailureDestroysConnectionAndJoinsErrors(t *testing.T) {
	t.Parallel()
	publicationErr := errors.New("memberships capture failed")
	unlockErr := errors.New("session unlock failed")
	destroyErr := errors.New("connection close failed")
	tx := &fakeIAMSnapshotTx{failAt: "memberships"}
	database := &fakeIAMSnapshotDB{tx: tx}
	database.conn = &fakeIAMPublicationConn{database: database, tx: tx, unlockErr: unlockErr, destroyErr: destroyErr}
	store := newPostgresStoreWithDB(database)

	_, err := store.PublishOrgVersion(context.Background(), OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
	if err == nil || !strings.Contains(err.Error(), publicationErr.Error()) || !errors.Is(err, unlockErr) || !errors.Is(err, destroyErr) {
		t.Fatalf("joined publication cleanup error = %v", err)
	}
	if database.conn.released || !database.conn.destroyed {
		t.Fatalf("unsafe connection cleanup: released=%t destroyed=%t calls=%#v", database.conn.released, database.conn.destroyed, database.calls)
	}
}

func TestPostgresPublicationConnectionSetupFailuresCleanUpSafely(t *testing.T) {
	t.Parallel()
	t.Run("acquire", func(t *testing.T) {
		acquireErr := errors.New("acquire failed")
		database := &fakeIAMSnapshotDB{tx: &fakeIAMSnapshotTx{}, acquireErr: acquireErr}
		_, err := newPostgresStoreWithDB(database).CreateOrgVersion(context.Background(), OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23})
		if !errors.Is(err, acquireErr) || !reflect.DeepEqual(database.calls, []string{"acquire"}) {
			t.Fatalf("error=%v calls=%#v", err, database.calls)
		}
	})
	t.Run("lock", func(t *testing.T) {
		lockErr := errors.New("session lock failed")
		destroyErr := errors.New("destroy failed")
		tx := &fakeIAMSnapshotTx{}
		database := &fakeIAMSnapshotDB{tx: tx}
		database.conn = &fakeIAMPublicationConn{database: database, tx: tx, lockErr: lockErr, destroyErr: destroyErr}
		_, err := newPostgresStoreWithDB(database).CreateOrgVersion(context.Background(), OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23})
		if !errors.Is(err, lockErr) || !errors.Is(err, destroyErr) || !reflect.DeepEqual(database.calls, []string{"acquire", "session-lock", "destroy"}) || database.conn.released {
			t.Fatalf("error=%v calls=%#v released=%t", err, database.calls, database.conn.released)
		}
	})
	t.Run("begin", func(t *testing.T) {
		beginErr := errors.New("begin failed")
		database := &fakeIAMSnapshotDB{tx: &fakeIAMSnapshotTx{}, beginErr: beginErr}
		_, err := newPostgresStoreWithDB(database).CreateOrgVersion(context.Background(), OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23})
		if !errors.Is(err, beginErr) || !reflect.DeepEqual(database.calls, []string{"acquire", "session-lock", "begin", "session-unlock", "release"}) {
			t.Fatalf("error=%v calls=%#v", err, database.calls)
		}
		if database.conn.unlockContextErr != nil || !database.conn.unlockHasDeadline || database.conn.destroyed {
			t.Fatalf("unlock context=%v deadline=%t destroyed=%t", database.conn.unlockContextErr, database.conn.unlockHasDeadline, database.conn.destroyed)
		}
	})
}

type serializedPublicationDB struct {
	db.DBTX
	mu               sync.Mutex
	maxVersion       int64
	acquires         int
	lockToken        chan struct{}
	highVersionSeen  chan struct{}
	allowHighCommit  chan struct{}
	lowLockAttempted chan struct{}
}

func newSerializedPublicationDB(maxVersion int64) *serializedPublicationDB {
	database := &serializedPublicationDB{
		maxVersion:       maxVersion,
		lockToken:        make(chan struct{}, 1),
		highVersionSeen:  make(chan struct{}),
		allowHighCommit:  make(chan struct{}),
		lowLockAttempted: make(chan struct{}),
	}
	database.lockToken <- struct{}{}
	return database
}

func (d *serializedPublicationDB) AcquireOrgPublicationConn(context.Context) (orgPublicationConn, error) {
	d.mu.Lock()
	d.acquires++
	label := "low"
	if d.acquires == 1 {
		label = "high"
	}
	d.mu.Unlock()
	return &serializedPublicationConn{database: d, label: label}, nil
}

type serializedPublicationConn struct {
	db.DBTX
	database *serializedPublicationDB
	label    string
	pending  int64
	tx       *fakeIAMSnapshotTx
}

func (c *serializedPublicationConn) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if strings.Contains(sql, "pg_advisory_lock") {
		if c.label == "low" {
			close(c.database.lowLockAttempted)
		}
		<-c.database.lockToken
		return fakeAdvisoryRow{locked: true}
	}
	if strings.Contains(sql, "pg_advisory_unlock") {
		c.database.lockToken <- struct{}{}
		return fakeAdvisoryRow{locked: true}
	}
	panic("unexpected serialized connection SQL: " + sql)
}

func (c *serializedPublicationConn) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	c.tx = &fakeIAMSnapshotTx{}
	c.tx.beforeVersion = func(version int64) error {
		if c.label == "high" {
			close(c.database.highVersionSeen)
			<-c.database.allowHighCommit
		}
		c.database.mu.Lock()
		defer c.database.mu.Unlock()
		if version <= c.database.maxVersion {
			return errors.New("organization version must strictly increase")
		}
		c.pending = version
		return nil
	}
	c.tx.afterCommit = func() {
		c.database.mu.Lock()
		c.database.maxVersion = c.pending
		c.database.mu.Unlock()
	}
	return c.tx, nil
}

func (c *serializedPublicationConn) Release() {}
func (c *serializedPublicationConn) Destroy(context.Context) error {
	return nil
}

func TestPostgresPublicationSerializesDifferentAndSameVersionsBeforeSnapshot(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		highVersion int64
		lowVersion  int64
	}{
		{name: "high 44 commits before waiting low 43", highVersion: 44, lowVersion: 43},
		{name: "same next only one succeeds", highVersion: 43, lowVersion: 43},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := newSerializedPublicationDB(42)
			store := newPostgresStoreWithDB(database)
			results := make(chan error, 2)
			publish := func(version int64) {
				_, err := store.PublishOrgVersion(context.Background(), OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: version, SourceEventID: "event-id"})
				results <- err
			}
			go publish(test.highVersion)
			<-database.highVersionSeen
			go publish(test.lowVersion)
			<-database.lowLockAttempted
			close(database.allowHighCommit)

			first, second := <-results, <-results
			successes := 0
			for _, err := range []error{first, second} {
				if err == nil {
					successes++
				} else if !strings.Contains(err.Error(), "strictly increase") {
					t.Fatalf("unexpected loser error: %v", err)
				}
			}
			database.mu.Lock()
			maxVersion := database.maxVersion
			database.mu.Unlock()
			if successes != 1 || maxVersion != test.highVersion {
				t.Fatalf("successes=%d maxVersion=%d", successes, maxVersion)
			}
		})
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
	database := &fakeIAMSnapshotDB{tx: tx}
	store := newPostgresStoreWithDB(database)
	_, err := store.PublishOrgVersion(ctx, OrgEvent{ID: "event-id", EnterpriseID: "enterprise-1", EventType: "org_import"}, OrgVersion{ID: "version-id", EnterpriseID: "enterprise-1", VersionNumber: 23, SourceEventID: "event-id"})
	if err == nil || !strings.Contains(err.Error(), "memberships capture failed") {
		t.Fatalf("error = %v", err)
	}
	if !tx.rolledBack || tx.rollbackContextErr != nil || !tx.rollbackHasDeadline {
		t.Fatalf("cleanup rollback=%t contextErr=%v deadline=%t calls=%#v", tx.rolledBack, tx.rollbackContextErr, tx.rollbackHasDeadline, tx.calls)
	}
	if database.conn.unlockContextErr != nil || !database.conn.unlockHasDeadline {
		t.Fatalf("unlock context error=%v deadline=%t", database.conn.unlockContextErr, database.conn.unlockHasDeadline)
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
