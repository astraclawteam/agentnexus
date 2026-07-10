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
	for _, required := range []string{"browser_sessions", "oauth_authorization_codes", "approval_queue_items", "id_hash", "code_hash", "user_agent_hash", "foreign key (enterprise_id, enterprise_user_id)", "check (char_length(id_hash) = 64", "check (char_length(code_hash) = 64", "create index"} {
		if !strings.Contains(strings.ToLower(migration), required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"session_token", "authorization_code text", "user_agent text", "verifier text"} {
		if strings.Contains(strings.ToLower(migration), forbidden) {
			t.Errorf("migration persists plaintext field %q", forbidden)
		}
	}
	if !strings.Contains(strings.ToUpper(queries), "FOR UPDATE") {
		t.Error("queries must lock authorization/session records")
	}
	if !strings.Contains(strings.ToLower(queries), "consumed_at") {
		t.Error("queries must consume authorization codes")
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
