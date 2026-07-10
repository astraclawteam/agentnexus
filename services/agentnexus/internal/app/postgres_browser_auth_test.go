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
	for _, required := range []string{"resolveexternalidentity", "external_identities", "provider =", "external_subject =", "getbrowserprofile", "org_versions", "listbrowserprofileorgunits", "org_memberships"} {
		if !strings.Contains(authSQL, required) {
			t.Errorf("auth SQL missing %q", required)
		}
	}
	normalized := strings.Join(strings.Fields(authSQL), " ")
	if !strings.Contains(normalized, "from external_identities where enterprise_id = $1 and provider = $2 and external_subject = $3") {
		t.Error("external identity lookup is not bound to the configured enterprise")
	}
	for _, required := range []string{"acquireenterpriseauditlock", "pg_advisory_xact_lock", "getlatestenterpriseaudithash", "order by created_at desc"} {
		if !strings.Contains(auditSQL, required) {
			t.Errorf("audit SQL missing %q", required)
		}
	}
	if !strings.Contains(auditSQL, "clock_timestamp()") {
		t.Error("audit insert timestamp must be taken after acquiring the serialization lock")
	}
}
