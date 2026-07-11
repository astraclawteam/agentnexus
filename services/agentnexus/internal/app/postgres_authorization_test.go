package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5"
)

type fakeAtlasPolicyPool struct {
	tx       *fakeAtlasPolicyTx
	options  []pgx.TxOptions
	beginErr error
}

func (f *fakeAtlasPolicyPool) BeginAtlasPolicyTx(_ context.Context, options pgx.TxOptions) (atlasPolicyTx, error) {
	f.options = append(f.options, options)
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	f.tx.calls = append(f.tx.calls, "begin")
	return f.tx, nil
}

type fakeAtlasPolicyTx struct {
	calls                []string
	latest               int64
	latestErr            error
	units                []db.OrgPolicySnapshotUnit
	memberships          []db.OrgPolicySnapshotMembership
	unitArgs             db.ListAuthorizationOrgUnitsParams
	memberArgs           db.ListAuthorizationMembershipsParams
	unitsByVersion       map[int64][]db.OrgPolicySnapshotUnit
	membershipsByVersion map[int64][]db.OrgPolicySnapshotMembership
	afterVersion         func()
	afterUnits           func()
	failAt               string
	committed            bool
	rolledBack           bool
}

func (f *fakeAtlasPolicyTx) GetLatestAuthorizationOrgVersion(context.Context, string) (int64, error) {
	f.calls = append(f.calls, "version")
	if f.failAt == "version" {
		return 0, errors.New("version query failed")
	}
	if f.latestErr != nil {
		return 0, f.latestErr
	}
	version := f.latest
	if f.afterVersion != nil {
		f.afterVersion()
	}
	return version, nil
}

func (f *fakeAtlasPolicyTx) ListAuthorizationOrgUnits(_ context.Context, arg db.ListAuthorizationOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error) {
	f.calls = append(f.calls, "units")
	f.unitArgs = arg
	if f.failAt == "units" {
		return nil, errors.New("units query failed")
	}
	if f.unitsByVersion != nil {
		units := f.unitsByVersion[arg.VersionNumber]
		if f.afterUnits != nil {
			f.afterUnits()
		}
		return units, nil
	}
	if f.afterUnits != nil {
		f.afterUnits()
	}
	return f.units, nil
}

func (f *fakeAtlasPolicyTx) ListAuthorizationMemberships(_ context.Context, arg db.ListAuthorizationMembershipsParams) ([]db.OrgPolicySnapshotMembership, error) {
	f.calls = append(f.calls, "memberships")
	f.memberArgs = arg
	if f.failAt == "memberships" {
		return nil, errors.New("memberships query failed")
	}
	if f.membershipsByVersion != nil {
		return f.membershipsByVersion[arg.VersionNumber], nil
	}
	return f.memberships, nil
}

func (f *fakeAtlasPolicyTx) Commit(context.Context) error {
	f.calls = append(f.calls, "commit")
	if f.failAt == "commit" {
		return errors.New("commit failed")
	}
	f.committed = true
	return nil
}

func (f *fakeAtlasPolicyTx) Rollback(context.Context) error {
	if f.committed || f.rolledBack {
		return pgx.ErrTxClosed
	}
	f.calls = append(f.calls, "rollback")
	f.rolledBack = true
	return nil
}

func TestPostgresAtlasPolicySourceReadsOneExactImmutableVersion(t *testing.T) {
	t.Parallel()
	tx := &fakeAtlasPolicyTx{
		latest:      17,
		units:       []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-1", VersionNumber: 17, OrgUnitID: "child"}, {EnterpriseID: "enterprise-1", VersionNumber: 17, OrgUnitID: "parent"}},
		memberships: []db.OrgPolicySnapshotMembership{{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "parent", Role: "edit"}},
	}
	pool := &fakeAtlasPolicyPool{tx: tx}
	source := newPostgresAtlasPolicySourceWithPool(pool)

	snapshot, err := source.LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.options) != 1 || pool.options[0].IsoLevel != pgx.RepeatableRead || pool.options[0].AccessMode != pgx.ReadOnly {
		t.Fatalf("transaction options = %#v", pool.options)
	}
	if !reflect.DeepEqual(tx.calls, []string{"begin", "version", "units", "memberships", "commit"}) {
		t.Fatalf("calls = %#v", tx.calls)
	}
	if tx.unitArgs.EnterpriseID != "enterprise-1" || tx.unitArgs.VersionNumber != 17 || tx.memberArgs.EnterpriseID != "enterprise-1" || tx.memberArgs.VersionNumber != 17 || tx.memberArgs.EnterpriseUserID != "user-1" {
		t.Fatalf("exact version was not propagated: units=%#v memberships=%#v", tx.unitArgs, tx.memberArgs)
	}
	if snapshot.EnterpriseID != "enterprise-1" || snapshot.OrgVersion != 17 || !reflect.DeepEqual(snapshot.Memberships, []policy.AtlasMembership{{OrgUnitID: "parent", Role: "edit"}}) {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestPostgresAtlasPolicySourceOldSnapshotCannotSeeLaterLiveGrant(t *testing.T) {
	t.Parallel()
	tx := &fakeAtlasPolicyTx{latest: 17}
	tx.unitsByVersion = map[int64][]db.OrgPolicySnapshotUnit{17: {{EnterpriseID: "enterprise-1", VersionNumber: 17, OrgUnitID: "dept"}}}
	tx.membershipsByVersion = map[int64][]db.OrgPolicySnapshotMembership{17: {{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: "suggest"}}}
	tx.afterVersion = func() {
		tx.latest = 18
		tx.unitsByVersion[18] = []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-1", VersionNumber: 18, OrgUnitID: "dept"}}
		tx.membershipsByVersion[18] = []db.OrgPolicySnapshotMembership{{EnterpriseID: "enterprise-1", VersionNumber: 18, EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: "edit"}}
	}
	source := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{tx: tx})
	snapshot, err := source.LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.Memberships, []policy.AtlasMembership{{OrgUnitID: "dept", Role: "suggest"}}) {
		t.Fatalf("old snapshot changed after later grant: %#v", snapshot.Memberships)
	}
}

func TestPostgresAtlasPolicySourceRollsBackEveryFailure(t *testing.T) {
	t.Parallel()
	for _, failAt := range []string{"version", "units", "memberships", "commit"} {
		t.Run(failAt, func(t *testing.T) {
			tx := &fakeAtlasPolicyTx{latest: 17, failAt: failAt}
			_, err := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{tx: tx}).LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
			if !errors.Is(err, policy.ErrAtlasPolicyUnavailable) {
				t.Fatalf("error = %v", err)
			}
			if tx.committed || !tx.rolledBack || tx.calls[len(tx.calls)-1] != "rollback" {
				t.Fatalf("calls=%#v committed=%t rolledBack=%t", tx.calls, tx.committed, tx.rolledBack)
			}
		})
	}

	beginErr := errors.New("begin failed")
	_, err := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{beginErr: beginErr}).LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if !errors.Is(err, policy.ErrAtlasPolicyUnavailable) || !errors.Is(err, beginErr) {
		t.Fatalf("begin error = %v", err)
	}
}

func TestPostgresAtlasPolicySourceRejectsCrossTenantOrVersionRows(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		units       []db.OrgPolicySnapshotUnit
		memberships []db.OrgPolicySnapshotMembership
	}{
		{name: "foreign org unit", units: []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-2", VersionNumber: 17, OrgUnitID: "dept"}}},
		{name: "stale org unit", units: []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-1", VersionNumber: 16, OrgUnitID: "dept"}}},
		{name: "foreign membership", units: []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-1", VersionNumber: 17, OrgUnitID: "dept"}}, memberships: []db.OrgPolicySnapshotMembership{{EnterpriseID: "enterprise-2", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: "suggest"}}},
		{name: "foreign user membership", units: []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-1", VersionNumber: 17, OrgUnitID: "dept"}}, memberships: []db.OrgPolicySnapshotMembership{{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-2", OrgUnitID: "dept", Role: "suggest"}}},
		{name: "stale membership", units: []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-1", VersionNumber: 17, OrgUnitID: "dept"}}, memberships: []db.OrgPolicySnapshotMembership{{EnterpriseID: "enterprise-1", VersionNumber: 16, EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: "suggest"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &fakeAtlasPolicyTx{latest: 17, units: test.units, memberships: test.memberships}
			_, err := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{tx: tx}).LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
			if !errors.Is(err, policy.ErrAtlasPolicyUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPostgresAtlasPolicySourceRequiresNewSealedPublication(t *testing.T) {
	t.Parallel()
	unsealed := &fakeAtlasPolicyTx{latestErr: pgx.ErrNoRows}
	_, err := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{tx: unsealed}).LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if !errors.Is(err, policy.ErrAtlasPolicyUnavailable) || !unsealed.rolledBack {
		t.Fatalf("unsealed legacy version error=%v calls=%#v", err, unsealed.calls)
	}

	sealed := &fakeAtlasPolicyTx{
		latest:      18,
		units:       []db.OrgPolicySnapshotUnit{{EnterpriseID: "enterprise-1", VersionNumber: 18, OrgUnitID: "dept"}},
		memberships: []db.OrgPolicySnapshotMembership{{EnterpriseID: "enterprise-1", VersionNumber: 18, EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: "edit"}},
	}
	snapshot, err := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{tx: sealed}).LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OrgVersion != 18 || !reflect.DeepEqual(snapshot.Memberships, []policy.AtlasMembership{{OrgUnitID: "dept", Role: "edit"}}) {
		t.Fatalf("sealed publication snapshot = %#v", snapshot)
	}
}

func TestPostgresAtlasPolicySourceRejectsOversizedSnapshotsBeforeConversion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		units       []db.OrgPolicySnapshotUnit
		memberships []db.OrgPolicySnapshotMembership
	}{
		{name: "units", units: make([]db.OrgPolicySnapshotUnit, policy.MaxAtlasOrgUnits+1)},
		{name: "memberships", units: []db.OrgPolicySnapshotUnit{}, memberships: make([]db.OrgPolicySnapshotMembership, policy.MaxAtlasMemberships+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &fakeAtlasPolicyTx{latest: 17, units: test.units, memberships: test.memberships}
			_, err := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{tx: tx}).LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
			if !errors.Is(err, policy.ErrAtlasPolicyUnavailable) || tx.committed {
				t.Fatalf("error=%v calls=%#v", err, tx.calls)
			}
		})
	}
}

func TestPostgresAtlasPolicySourceStopsWhenContextCanceledBetweenQueries(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	tx := &fakeAtlasPolicyTx{latest: 17, units: []db.OrgPolicySnapshotUnit{}}
	tx.afterUnits = cancel
	_, err := newPostgresAtlasPolicySourceWithPool(&fakeAtlasPolicyPool{tx: tx}).LoadAccessSnapshot(ctx, "enterprise-1", "user-1")
	if !errors.Is(err, policy.ErrAtlasPolicyUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if tx.committed || !tx.rolledBack || reflect.DeepEqual(tx.calls, []string{"begin", "version", "units", "memberships"}) {
		t.Fatalf("cancellation did not stop before memberships: %#v", tx.calls)
	}
}
