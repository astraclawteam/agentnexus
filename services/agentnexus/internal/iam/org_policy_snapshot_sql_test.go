package iam

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOrgPolicySnapshotMigrationContract(t *testing.T) {
	t.Parallel()
	root := agentnexusRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000004_versioned_org_policy_snapshots.sql"))
	if err != nil {
		t.Fatalf("read snapshot migration: %v", err)
	}
	migration := strings.ToLower(strings.Join(strings.Fields(string(raw)), " "))
	for _, required := range []string{
		"lock table org_versions, org_units, org_memberships in share row exclusive mode",
		"create table org_policy_snapshot_units",
		"primary key (enterprise_id, version_number, org_unit_id)",
		"foreign key (enterprise_id, version_number) references org_versions(enterprise_id, version_number)",
		"foreign key (enterprise_id, version_number, parent_id) references org_policy_snapshot_units(enterprise_id, version_number, org_unit_id)",
		"create table org_policy_snapshot_memberships",
		"foreign key (enterprise_id, version_number, org_unit_id) references org_policy_snapshot_units(enterprise_id, version_number, org_unit_id)",
		"create trigger reject_org_policy_snapshot_units_mutation",
		"create trigger reject_org_policy_snapshot_memberships_mutation",
		"select distinct on (enterprise_id) enterprise_id, version_number from org_versions",
		"insert into org_policy_snapshot_units",
		"insert into org_policy_snapshot_memberships",
		"create index idx_org_policy_snapshot_memberships_actor",
	} {
		if !strings.Contains(migration, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	membershipsDrop := strings.Index(migration, "drop table if exists org_policy_snapshot_memberships")
	unitsDrop := strings.Index(migration, "drop table if exists org_policy_snapshot_units")
	functionDrop := strings.Index(migration, "drop function if exists reject_org_policy_snapshot_mutation")
	if membershipsDrop < 0 || unitsDrop <= membershipsDrop || functionDrop <= unitsDrop {
		t.Fatalf("unsafe Down order: memberships=%d units=%d function=%d", membershipsDrop, unitsDrop, functionDrop)
	}
}

func TestAuthorizationSQLReadsExactImmutableVersion(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(agentnexusRoot(t), "db", "queries", "org.sql"))
	if err != nil {
		t.Fatal(err)
	}
	queries := strings.ToLower(string(raw))
	units := namedSQL(queries, "-- name: listauthorizationorgunits")
	memberships := namedSQL(queries, "-- name: listauthorizationmemberships")
	for name, query := range map[string]string{"units": units, "memberships": memberships} {
		if !strings.Contains(query, "version_number = $2") {
			t.Errorf("%s query does not bind exact version: %s", name, query)
		}
		if strings.Contains(query, "from org_units") || strings.Contains(query, "from org_memberships") {
			t.Errorf("%s query reads mutable live tables: %s", name, query)
		}
	}
	if !strings.Contains(units, "limit 10001") {
		t.Errorf("units query lacks max+1 bound: %s", units)
	}
	if !strings.Contains(memberships, "limit 100001") {
		t.Errorf("memberships query lacks max+1 bound: %s", memberships)
	}
	for _, required := range []string{"-- name: captureorgpolicysnapshotunits", "-- name: captureorgpolicysnapshotmemberships"} {
		if !strings.Contains(queries, required) {
			t.Errorf("publication query missing %q", required)
		}
	}
	captureMemberships := namedSQL(queries, "-- name: captureorgpolicysnapshotmemberships")
	if strings.Contains(captureMemberships, "join org_policy_snapshot_units") {
		t.Errorf("membership capture can silently omit incomplete live rows: %s", captureMemberships)
	}
}

func agentnexusRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func namedSQL(all, marker string) string {
	start := strings.Index(all, marker)
	if start < 0 {
		return ""
	}
	rest := all[start+len(marker):]
	if end := strings.Index(rest, "-- name:"); end >= 0 {
		return rest[:end]
	}
	return rest
}
