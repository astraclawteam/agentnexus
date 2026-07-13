package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresBrowserAuthDependenciesImplementProductionInterfaces(t *testing.T) {
	var _ ExternalIdentityResolver = (*PostgresBrowserDirectory)(nil)
	var _ BrowserProfileResolver = (*PostgresBrowserDirectory)(nil)
	var _ BrowserAuditSink = (*PostgresBrowserAuditSink)(nil)
}

type fakeBrowserProfileDB struct {
	tx      *fakeBrowserProfileTx
	options []pgx.TxOptions
}

func (f *fakeBrowserProfileDB) BeginBrowserProfileTx(_ context.Context, options pgx.TxOptions) (browserProfileTx, error) {
	f.options = append(f.options, options)
	return f.tx, nil
}

type fakeBrowserProfileTx struct {
	cancel              context.CancelFunc
	queryErr            error
	rollbackErr         error
	rollbackContextErr  error
	rollbackHasDeadline bool
	calls               []string
	profile             db.GetBrowserProfileRow
	units               []db.OrgPolicySnapshotMembership
	unitArgs            db.ListBrowserProfileOrgUnitsParams
	cancelOnUnits       context.CancelFunc
	commitErr           error
}

func (f *fakeBrowserProfileTx) GetBrowserProfile(context.Context, db.GetBrowserProfileParams) (db.GetBrowserProfileRow, error) {
	f.calls = append(f.calls, "profile")
	if f.cancel != nil {
		f.cancel()
	}
	return f.profile, f.queryErr
}

func (f *fakeBrowserProfileTx) ListBrowserProfileOrgUnits(_ context.Context, params db.ListBrowserProfileOrgUnitsParams) ([]db.OrgPolicySnapshotMembership, error) {
	f.calls = append(f.calls, "units")
	f.unitArgs = params
	if f.cancelOnUnits != nil {
		f.cancelOnUnits()
	}
	return f.units, nil
}

func (f *fakeBrowserProfileTx) Commit(context.Context) error {
	f.calls = append(f.calls, "commit")
	return f.commitErr
}

func TestPostgresBrowserProfileUsesExactVersionAndValidatesBoundedRows(t *testing.T) {
	t.Parallel()
	t.Run("exact version sorted deduplicated", func(t *testing.T) {
		tx := &fakeBrowserProfileTx{
			profile: db.GetBrowserProfileRow{DisplayName: "User", OrgVersion: 17},
			units: []db.OrgPolicySnapshotMembership{
				{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "z", Role: "publish_low_risk"},
				{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "a", Role: "service_mode"},
				{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "a", Role: "publish_low_risk"},
				{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "a", Role: "member"},
			},
		}
		profile, err := (&PostgresBrowserDirectory{profileDB: &fakeBrowserProfileDB{tx: tx}}).ResolveBrowserProfile(context.Background(), "enterprise-1", "user-1")
		if err != nil {
			t.Fatal(err)
		}
		if tx.unitArgs.VersionNumber != 17 || !reflect.DeepEqual(profile.OrgUnitIDs, []string{"a", "z"}) || !reflect.DeepEqual(profile.Permissions, []string{"publish_low_risk", "service_mode", "suggest"}) || !profile.AdvancedModeAllowed {
			t.Fatalf("args=%#v profile=%#v", tx.unitArgs, profile)
		}
	})

	for _, test := range []struct {
		name string
		row  db.OrgPolicySnapshotMembership
	}{
		{name: "cross enterprise", row: db.OrgPolicySnapshotMembership{EnterpriseID: "enterprise-2", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "a", Role: "member"}},
		{name: "cross version", row: db.OrgPolicySnapshotMembership{EnterpriseID: "enterprise-1", VersionNumber: 18, EnterpriseUserID: "user-1", OrgUnitID: "a", Role: "member"}},
		{name: "cross user", row: db.OrgPolicySnapshotMembership{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-2", OrgUnitID: "a", Role: "member"}},
		{name: "noncanonical unit", row: db.OrgPolicySnapshotMembership{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: " a", Role: "member"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &fakeBrowserProfileTx{profile: db.GetBrowserProfileRow{OrgVersion: 17}, units: []db.OrgPolicySnapshotMembership{test.row}}
			if _, err := (&PostgresBrowserDirectory{profileDB: &fakeBrowserProfileDB{tx: tx}}).ResolveBrowserProfile(context.Background(), "enterprise-1", "user-1"); err == nil {
				t.Fatal("malformed profile row was accepted")
			}
		})
	}

	t.Run("limit plus one", func(t *testing.T) {
		rows := make([]db.OrgPolicySnapshotMembership, policy.MaxSealedMemberships+1)
		for i := range rows {
			rows[i] = db.OrgPolicySnapshotMembership{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "unit", Role: "member"}
		}
		tx := &fakeBrowserProfileTx{profile: db.GetBrowserProfileRow{OrgVersion: 17}, units: rows}
		if _, err := (&PostgresBrowserDirectory{profileDB: &fakeBrowserProfileDB{tx: tx}}).ResolveBrowserProfile(context.Background(), "enterprise-1", "user-1"); err == nil {
			t.Fatal("max plus one profile memberships were accepted")
		}
	})

	t.Run("exact limit", func(t *testing.T) {
		rows := make([]db.OrgPolicySnapshotMembership, policy.MaxSealedMemberships)
		for i := range rows {
			rows[i] = db.OrgPolicySnapshotMembership{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "unit", Role: "member"}
		}
		tx := &fakeBrowserProfileTx{profile: db.GetBrowserProfileRow{OrgVersion: 17}, units: rows}
		profile, err := (&PostgresBrowserDirectory{profileDB: &fakeBrowserProfileDB{tx: tx}}).ResolveBrowserProfile(context.Background(), "enterprise-1", "user-1")
		if err != nil || !reflect.DeepEqual(profile.OrgUnitIDs, []string{"unit"}) {
			t.Fatalf("error=%v units=%#v", err, profile.OrgUnitIDs)
		}
	})

	t.Run("cancellation before conversion", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		tx := &fakeBrowserProfileTx{profile: db.GetBrowserProfileRow{OrgVersion: 17}, units: []db.OrgPolicySnapshotMembership{{EnterpriseID: "enterprise-1", VersionNumber: 17, EnterpriseUserID: "user-1", OrgUnitID: "a", Role: "member"}}, cancelOnUnits: cancel}
		if _, err := (&PostgresBrowserDirectory{profileDB: &fakeBrowserProfileDB{tx: tx}}).ResolveBrowserProfile(ctx, "enterprise-1", "user-1"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	})

	t.Run("commit and rollback errors are joined", func(t *testing.T) {
		commitErr := errors.New("commit failed")
		rollbackErr := errors.New("rollback failed")
		tx := &fakeBrowserProfileTx{profile: db.GetBrowserProfileRow{OrgVersion: 17}, commitErr: commitErr, rollbackErr: rollbackErr}
		_, err := (&PostgresBrowserDirectory{profileDB: &fakeBrowserProfileDB{tx: tx}}).ResolveBrowserProfile(context.Background(), "enterprise-1", "user-1")
		if !errors.Is(err, commitErr) || !errors.Is(err, rollbackErr) {
			t.Fatalf("joined cleanup error = %v", err)
		}
	})
}

func (f *fakeBrowserProfileTx) Rollback(ctx context.Context) error {
	f.calls = append(f.calls, "rollback")
	f.rollbackContextErr = ctx.Err()
	_, f.rollbackHasDeadline = ctx.Deadline()
	return f.rollbackErr
}

func TestPostgresBrowserProfileRollbackSurvivesCancellationAndJoinsErrors(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	queryErr := errors.New("profile query failed")
	cleanupErr := errors.New("profile rollback failed")
	tx := &fakeBrowserProfileTx{cancel: cancel, queryErr: queryErr, rollbackErr: cleanupErr}
	database := &fakeBrowserProfileDB{tx: tx}
	directory := &PostgresBrowserDirectory{profileDB: database}

	_, err := directory.ResolveBrowserProfile(ctx, "enterprise-1", "user-1")
	if !errors.Is(err, queryErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("joined profile error = %v", err)
	}
	if tx.rollbackContextErr != nil || !tx.rollbackHasDeadline {
		t.Fatalf("rollback context error=%v deadline=%t", tx.rollbackContextErr, tx.rollbackHasDeadline)
	}
	if len(database.options) != 1 || database.options[0].IsoLevel != pgx.RepeatableRead || database.options[0].AccessMode != pgx.ReadOnly {
		t.Fatalf("profile transaction options = %#v", database.options)
	}
	if strings.Join(tx.calls, ",") != "profile,rollback" {
		t.Fatalf("profile calls = %#v", tx.calls)
	}
}

func TestPostgresBrowserDirectoryClassifiesIdentityLookupErrors(t *testing.T) {
	tests := []struct {
		name string
		row  pgx.Row
		want error
	}{
		{name: "unknown external identity", row: identityLookupRow{err: pgx.ErrNoRows}, want: ErrUnknownExternalIdentity},
		{name: "database unavailable", row: identityLookupRow{err: errors.New("database offline")}, want: ErrIdentityDirectoryUnavailable},
		{name: "context deadline", row: identityLookupRow{err: context.DeadlineExceeded}, want: ErrIdentityDirectoryUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := &PostgresBrowserDirectory{identityDB: identityLookupDB{row: test.row}}
			_, _, err := directory.ResolveExternalIdentity(context.Background(), "ent-1", "https://issuer.example", "subject-1")
			if !errors.Is(err, test.want) {
				t.Fatalf("ResolveExternalIdentity error = %v, want %v", err, test.want)
			}
			other := ErrUnknownExternalIdentity
			if errors.Is(test.want, ErrUnknownExternalIdentity) {
				other = ErrIdentityDirectoryUnavailable
			}
			if errors.Is(err, other) {
				t.Fatalf("ResolveExternalIdentity error = %v, must not classify as %v", err, other)
			}
		})
	}

	t.Run("nil pool is unavailable", func(t *testing.T) {
		_, _, err := NewPostgresBrowserDirectory(nil).ResolveExternalIdentity(context.Background(), "ent-1", "https://issuer.example", "subject-1")
		if !errors.Is(err, ErrIdentityDirectoryUnavailable) || errors.Is(err, ErrUnknownExternalIdentity) {
			t.Fatalf("ResolveExternalIdentity error = %v", err)
		}
	})
}

type identityLookupDB struct{ row pgx.Row }

func (d identityLookupDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected Exec")
}
func (d identityLookupDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}
func (d identityLookupDB) QueryRow(context.Context, string, ...interface{}) pgx.Row { return d.row }

type identityLookupRow struct{ err error }

func (r identityLookupRow) Scan(...interface{}) error { return r.err }

func TestBrowserDirectoryAndAuditSQLAreQuerySpecificAndSerialized(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	auth, err := os.ReadFile(filepath.Join(root, "db", "queries", "auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(filepath.Join(root, "db", "queries", "audit.sql"))
	if err != nil {
		t.Fatal(err)
	}
	authSQL := strings.ToLower(string(auth))
	auditSQL := strings.ToLower(string(audit))
	migration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000002_browser_sessions_and_approvals.sql"))
	if err != nil {
		t.Fatal(err)
	}
	production, err := os.ReadFile(filepath.Join(root, "internal", "app", "postgres_browser_auth.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"resolveexternalidentity", "external_identities", "provider =", "external_subject =", "getbrowserprofile", "org_versions", "listbrowserprofileorgunits", "org_policy_snapshot_memberships", "policy_snapshot_sealed = true"} {
		if !strings.Contains(authSQL, required) {
			t.Errorf("auth SQL missing %q", required)
		}
	}
	normalized := strings.Join(strings.Fields(authSQL), " ")
	if !strings.Contains(normalized, "from external_identities where enterprise_id = $1 and provider = $2 and external_subject = $3") {
		t.Error("external identity lookup is not bound to the configured enterprise")
	}
	for _, required := range []string{"fk_org_memberships_enterprise_user foreign key (enterprise_id, enterprise_user_id) references enterprise_users(enterprise_id, id)", "fk_org_memberships_enterprise_unit foreign key (enterprise_id, org_unit_id) references org_units(enterprise_id, id)", "alter table org_memberships drop constraint"} {
		if !strings.Contains(strings.Join(strings.Fields(strings.ToLower(string(migration))), " "), required) {
			t.Errorf("migration missing %q", required)
		}
	}
	if !strings.Contains(normalized, "join org_versions as v on v.enterprise_id = m.enterprise_id and v.version_number = m.version_number and v.policy_snapshot_sealed = true") {
		t.Error("profile memberships are not bound to a sealed enterprise/version snapshot")
	}
	for _, required := range []string{"select m.enterprise_id, m.version_number, m.enterprise_user_id, m.org_unit_id, m.role", "m.version_number = $3", "limit 100001"} {
		if !strings.Contains(normalized, required) {
			t.Errorf("profile membership query missing exact bounded row contract %q", required)
		}
	}
	if strings.Contains(normalized, "select latest.version_number from org_versions as latest") {
		t.Error("profile membership query independently selects latest version")
	}
	productionSource := string(production)
	for _, required := range []string{"pgx.RepeatableRead", "tx.Commit(ctx)", "context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)", "errors.Join"} {
		if !strings.Contains(productionSource, required) {
			t.Errorf("profile snapshot missing %q", required)
		}
	}
	for _, required := range []string{"acquireenterpriseauditlock", "pg_advisory_xact_lock", "getlatestenterpriseaudithash", "order by created_at desc"} {
		if !strings.Contains(auditSQL, required) {
			t.Errorf("audit SQL missing %q", required)
		}
	}
	if !strings.Contains(auditSQL, "clock_timestamp()") {
		t.Error("audit insert timestamp must be taken after acquiring the serialization lock")
	}
	if !strings.Contains(strings.Join(strings.Fields(strings.ToLower(string(migration))), " "), "create index idx_audit_events_enterprise_chain on audit_events(enterprise_id, created_at desc, id desc)") {
		t.Error("audit chain lookup index missing")
	}
	if !strings.Contains(strings.ToLower(string(migration)), "drop index if exists idx_audit_events_enterprise_chain") {
		t.Error("audit chain index is not removed on down migration")
	}
}
