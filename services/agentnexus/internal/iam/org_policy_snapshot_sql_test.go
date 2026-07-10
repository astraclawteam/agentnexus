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
		"alter table org_versions add column policy_snapshot_sealed boolean not null default false",
		"add column policy_snapshot_publishable boolean not null default false",
		"create table org_policy_publication_heads",
		"enterprise_id text primary key references enterprises(id)",
		"last_version_number bigint not null check (last_version_number > 0)",
		"insert into org_policy_publication_heads (enterprise_id, last_version_number) select enterprise_id, max(version_number)",
		"from org_versions where version_number > 0 group by enterprise_id",
		"create table org_policy_snapshot_units",
		"primary key (enterprise_id, version_number, org_unit_id)",
		"foreign key (enterprise_id, version_number) references org_versions(enterprise_id, version_number)",
		"foreign key (enterprise_id, version_number, parent_id) references org_policy_snapshot_units(enterprise_id, version_number, org_unit_id)",
		"create table org_policy_snapshot_memberships",
		"foreign key (enterprise_id, version_number, org_unit_id) references org_policy_snapshot_units(enterprise_id, version_number, org_unit_id)",
		"create trigger guard_org_policy_snapshot_units_rows before insert or update or delete",
		"create trigger guard_org_policy_snapshot_memberships_rows before insert or update or delete",
		"create trigger reject_org_policy_snapshot_units_truncate before truncate",
		"create trigger reject_org_policy_snapshot_memberships_truncate before truncate",
		"create trigger guard_org_policy_version_seal before insert or update or delete",
		"pg_advisory_xact_lock(hashtextextended(new.enterprise_id, 0))",
		"new.version_number <= 0",
		"insert into org_policy_publication_heads as heads",
		"on conflict (enterprise_id) do update set last_version_number = excluded.last_version_number",
		"where heads.last_version_number < excluded.last_version_number",
		"returning last_version_number into advanced_version",
		"new.policy_snapshot_publishable := true",
		"new.policy_snapshot_sealed := false",
		"organization policy versions cannot be deleted",
		"legacy organization policy version cannot be sealed",
		"policy snapshot publishability cannot be changed",
		"policy snapshot is sealed",
		"for no key update",
		"create index idx_org_policy_snapshot_memberships_actor",
	} {
		if !strings.Contains(migration, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"select distinct on (enterprise_id)", "join org_units as u on u.enterprise_id = latest.enterprise_id", "join org_memberships as m on m.enterprise_id = latest.enterprise_id", "v.version_number >= new.version_number"} {
		if strings.Contains(migration, forbidden) {
			t.Errorf("migration fabricates an old snapshot via %q", forbidden)
		}
	}
	if strings.Count(migration, "for no key update") != 2 {
		t.Errorf("snapshot guard must lock the version row in both INSERT and UPDATE/DELETE branches: %s", migration)
	}
	lockAt := strings.Index(migration, "pg_advisory_xact_lock(hashtextextended(new.enterprise_id, 0))")
	monotonicAt := strings.Index(migration, "insert into org_policy_publication_heads as heads")
	if lockAt < 0 || monotonicAt <= lockAt {
		t.Errorf("version maximum is checked before publisher serialization: lock=%d monotonic=%d", lockAt, monotonicAt)
	}
	membershipsDrop := strings.Index(migration, "drop table if exists org_policy_snapshot_memberships")
	unitsDrop := strings.Index(migration, "drop table if exists org_policy_snapshot_units")
	functionDrop := strings.Index(migration, "drop function if exists guard_org_policy_snapshot_row")
	sealedColumnDrop := strings.Index(migration, "alter table org_versions drop column if exists policy_snapshot_sealed")
	publishableColumnDrop := strings.Index(migration, "alter table org_versions drop column if exists policy_snapshot_publishable")
	headDrop := strings.Index(migration, "drop table if exists org_policy_publication_heads")
	if membershipsDrop < 0 || unitsDrop <= membershipsDrop || functionDrop <= unitsDrop || headDrop <= functionDrop || sealedColumnDrop <= headDrop || publishableColumnDrop <= sealedColumnDrop {
		t.Fatalf("unsafe Down order: memberships=%d units=%d function=%d", membershipsDrop, unitsDrop, functionDrop)
	}
	for _, required := range []string{"drop function if exists reject_org_policy_snapshot_truncate", "drop trigger if exists guard_org_policy_version_seal on org_versions", "drop function if exists guard_org_policy_version_seal"} {
		if !strings.Contains(migration, required) {
			t.Errorf("Down migration leaves publication object %q", required)
		}
	}
}

func TestOrgPolicySnapshotDeploymentGuidanceIsExplicit(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(agentnexusRoot(t), "db", "migrations", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	guidance := strings.ToLower(string(raw))
	for _, required := range []string{"deployment prerequisite", "does not create environment-specific roles", "grant", "revoke", "two-connection", "mutation-first", "seal-first", "concurrent publishers"} {
		if !strings.Contains(guidance, required) {
			t.Errorf("deployment guidance missing %q", required)
		}
	}
}

func TestPostgresPublicationTakesSessionLockBeforeRepeatableReadSnapshot(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(agentnexusRoot(t), "internal", "iam", "store.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{"AcquireOrgPublicationConn", "pg_advisory_lock(hashtextextended($1, 0))", "pg_advisory_unlock(hashtextextended($1, 0))", "context.WithoutCancel", "Destroy"} {
		if !strings.Contains(source, required) {
			t.Errorf("publication connection lifecycle missing %q", required)
		}
	}
	lockAt := strings.Index(source, "acquireOrgPublicationSessionLock")
	beginAt := strings.Index(source, "BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead")
	if lockAt < 0 || beginAt <= lockAt {
		t.Errorf("RepeatableRead snapshot can start before session lock: lock=%d begin=%d", lockAt, beginAt)
	}
}

func TestAuthorizationSQLReadsExactImmutableVersion(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(agentnexusRoot(t), "db", "queries", "org.sql"))
	if err != nil {
		t.Fatal(err)
	}
	queries := strings.ToLower(string(raw))
	latest := namedSQL(queries, "-- name: getlatestauthorizationorgversion")
	if !strings.Contains(latest, "policy_snapshot_sealed = true") {
		t.Errorf("authorization can select an unsealed version: %s", latest)
	}
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
	for _, required := range []string{"-- name: captureorgpolicysnapshotunits", "-- name: captureorgpolicysnapshotmemberships", "-- name: sealorgpolicysnapshot"} {
		if !strings.Contains(queries, required) {
			t.Errorf("publication query missing %q", required)
		}
	}
	createVersion := namedSQL(queries, "-- name: createorgversion")
	if strings.Contains(createVersion, "policy_snapshot_sealed") && strings.Contains(createVersion, "values ($1, $2, $3, $4, $5") {
		t.Errorf("publisher can supply snapshot state flags: %s", createVersion)
	}
	seal := namedSQL(queries, "-- name: sealorgpolicysnapshot")
	if !strings.Contains(seal, "policy_snapshot_publishable = true") || !strings.Contains(seal, "policy_snapshot_sealed = false") {
		t.Errorf("seal query can seal legacy or already sealed versions: %s", seal)
	}
	captureMemberships := namedSQL(queries, "-- name: captureorgpolicysnapshotmemberships")
	if strings.Contains(captureMemberships, "join org_policy_snapshot_units") {
		t.Errorf("membership capture can silently omit incomplete live rows: %s", captureMemberships)
	}
}

func TestBrowserProfileSQLUsesLatestSealedPolicySnapshot(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(agentnexusRoot(t), "db", "queries", "auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	queries := strings.ToLower(string(raw))
	profile := namedSQL(queries, "-- name: getbrowserprofile")
	units := namedSQL(queries, "-- name: listbrowserprofileorgunits")
	if !strings.Contains(profile, "policy_snapshot_sealed = true") || !strings.Contains(profile, "order by v.version_number desc") || !strings.Contains(profile, "limit 1") {
		t.Errorf("profile does not require latest sealed policy version: %s", profile)
	}
	if !strings.Contains(units, "org_policy_snapshot_memberships") || !strings.Contains(units, "policy_snapshot_sealed = true") || strings.Contains(units, "from org_memberships") {
		t.Errorf("profile org units do not come from the sealed snapshot: %s", units)
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
