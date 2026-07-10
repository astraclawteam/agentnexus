package browserauth

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMigrationAndQueriesUseHashOnlyAtomicPersistence(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	migration := mustRead(t, filepath.Join(root, "db", "migrations", "000002_browser_sessions_and_approvals.sql"))
	queries := mustRead(t, filepath.Join(root, "db", "queries", "auth.sql"))
	for _, required := range []string{"browser_sessions", "oauth_authorization_codes", "oidc_login_attempts", "approval_queue_items", "id_hash", "code_hash", "state_hash", "user_agent_hash", "foreign key (enterprise_id, enterprise_user_id)", "check (char_length(id_hash) = 64", "check (char_length(code_hash) = 64", "check (char_length(state_hash) = 64", "create index"} {
		if !strings.Contains(strings.ToLower(migration), required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"session_token", "authorization_code text", "user_agent text", "verifier text"} {
		if strings.Contains(strings.ToLower(migration), forbidden) {
			t.Errorf("migration persists plaintext field %q", forbidden)
		}
	}
	for _, name := range []string{"GetBrowserSessionForUpdate", "GetAuthorizationCodeForUpdate"} {
		if !strings.Contains(strings.ToUpper(namedQuery(t, queries, name)), "FOR UPDATE") {
			t.Errorf("%s must lock its record", name)
		}
	}
	consume := strings.ToLower(namedQuery(t, queries, "ConsumeAuthorizationCode"))
	if !strings.Contains(consume, "update oauth_authorization_codes") || !strings.Contains(consume, "consumed_at is null") {
		t.Error("ConsumeAuthorizationCode must atomically update only an unconsumed code")
	}
	loginConsume := strings.ToLower(namedQuery(t, queries, "ConsumeOIDCLoginAttempt"))
	if !strings.Contains(loginConsume, "delete from oidc_login_attempts") || !strings.Contains(loginConsume, "expires_at >") || !strings.Contains(loginConsume, "returning") {
		t.Error("ConsumeOIDCLoginAttempt must atomically delete and return only an unexpired attempt")
	}
	for _, required := range []string{
		"add constraint uq_org_units_enterprise_id_id unique (enterprise_id, id)",
		"foreign key (enterprise_id, org_unit_id)",
		"references org_units(enterprise_id, id)",
		"risk_level in ('low', 'medium', 'high')",
	} {
		if !strings.Contains(strings.ToLower(strings.Join(strings.Fields(migration), " ")), required) {
			t.Errorf("migration missing approval invariant %q", required)
		}
	}
}

func TestPostgresStoreImplementsStore(t *testing.T) {
	var _ Store = (*PostgresStore)(nil)
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func namedQuery(t *testing.T, queries, name string) string {
	t.Helper()
	marker := "-- name: " + name + " "
	start := strings.Index(queries, marker)
	if start < 0 {
		t.Fatalf("query %s not found", name)
	}
	rest := queries[start+len(marker):]
	if next := strings.Index(rest, "-- name:"); next >= 0 {
		rest = rest[:next]
	}
	return rest
}
