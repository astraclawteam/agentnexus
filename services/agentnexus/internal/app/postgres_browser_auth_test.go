package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPostgresBrowserAuthDependenciesImplementProductionInterfaces(t *testing.T) {
	var _ ExternalIdentityResolver = (*PostgresBrowserDirectory)(nil)
	var _ BrowserProfileResolver = (*PostgresBrowserDirectory)(nil)
	var _ BrowserAuditSink = (*PostgresBrowserAuditSink)(nil)
}

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
	for _, required := range []string{"resolveexternalidentity", "external_identities", "provider =", "external_subject =", "getbrowserprofile", "org_versions", "listbrowserprofileorgunits", "org_memberships"} {
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
	if !strings.Contains(normalized, "join org_units as u on u.enterprise_id = m.enterprise_id and u.id = m.org_unit_id") {
		t.Error("profile memberships are not joined on enterprise")
	}
	productionSource := string(production)
	for _, required := range []string{"pgx.RepeatableRead", "tx.Commit(ctx)"} {
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
