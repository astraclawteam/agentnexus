package browserauth

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMigrationAndQueriesUseHashOnlyAtomicPersistence(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	migration := mustRead(t, filepath.Join(root, "db", "migrations", "000002_browser_sessions_and_approvals.sql"))
	queries := mustRead(t, filepath.Join(root, "db", "queries", "auth.sql"))
	for _, required := range []string{"browser_sessions", "oauth_authorization_codes", "oidc_login_attempts", "approval_queue_items", "id_hash", "code_hash", "state_hash", "binding_hash", "user_agent_hash", "foreign key (enterprise_id, enterprise_user_id)", "check (char_length(id_hash) = 64", "check (char_length(code_hash) = 64", "check (char_length(state_hash) = 64", "check (char_length(binding_hash) = 64", "create index"} {
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
	logout := strings.ToLower(namedQuery(t, queries, "RevokeAndGetBrowserSession"))
	if !strings.Contains(logout, "update browser_sessions") || !strings.Contains(logout, "returning") || !strings.Contains(logout, "revoked_at is null") {
		t.Error("logout must atomically revoke and return one live session")
	}
	loginGet := strings.ToLower(namedQuery(t, queries, "GetOIDCLoginAttemptForUpdate"))
	if !strings.Contains(loginGet, "for update") {
		t.Error("login attempt consume must lock its state row")
	}
	createAttempt := strings.ToLower(namedQuery(t, queries, "CreateOIDCLoginAttempt"))
	if strings.Contains(createAttempt, "delete from") || strings.Contains(createAttempt, "count(") || !strings.Contains(createAttempt, "insert into oidc_login_attempts") {
		t.Error("login attempt insertion must be separate from lock, cleanup, and count queries")
	}
	lockAttempt := strings.ToLower(namedQuery(t, queries, "LockOIDCLoginAttemptScope"))
	deleteExpired := strings.ToLower(namedQuery(t, queries, "DeleteExpiredOIDCLoginAttempts"))
	countAttempts := strings.ToLower(namedQuery(t, queries, "CountOIDCLoginAttempts"))
	if !strings.Contains(lockAttempt, "pg_advisory_xact_lock") || !strings.Contains(lockAttempt, "enterprise") || !strings.Contains(lockAttempt, "client") {
		t.Error("login attempt scope must use a transaction advisory lock keyed by enterprise and client")
	}
	if !strings.Contains(deleteExpired, "expires_at <=") || strings.Contains(deleteExpired, "enterprise_id") || strings.Contains(deleteExpired, "client_id") {
		t.Error("login attempt cleanup must delete all expired rows")
	}
	if !strings.Contains(countAttempts, "count(") || !strings.Contains(countAttempts, "enterprise_id") || !strings.Contains(countAttempts, "client_id") || !strings.Contains(countAttempts, "expires_at >") {
		t.Error("login attempt count must be scoped to unexpired enterprise/client rows")
	}
	postgresStore := strings.ToLower(mustRead(t, filepath.Join(root, "internal", "browserauth", "postgres_store.go")))
	createStart := strings.Index(postgresStore, "func (s *postgresstore) createloginattempt")
	consumeStart := strings.Index(postgresStore, "func (s *postgresstore) consumeloginattempt")
	if createStart >= 0 && consumeStart > createStart {
		postgresStore = postgresStore[createStart:consumeStart]
	}
	lockIndex := strings.Index(postgresStore, ".lockoidcloginattemptscope")
	deleteIndex := strings.Index(postgresStore, ".deleteexpiredoidcloginattempts")
	countIndex := strings.Index(postgresStore, ".countoidcloginattempts")
	insertIndex := strings.Index(postgresStore, ".createoidcloginattempt")
	commitIndex := strings.Index(postgresStore, ".commit(ctx)")
	if lockIndex < 0 || deleteIndex <= lockIndex || countIndex <= deleteIndex || insertIndex <= countIndex || commitIndex <= insertIndex {
		t.Errorf("postgres login-attempt transaction order is lock=%d delete=%d count=%d insert=%d commit=%d", lockIndex, deleteIndex, countIndex, insertIndex, commitIndex)
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

func TestNilPostgresStoreFailsWithoutPanic(t *testing.T) {
	store := NewPostgresStore(nil)
	ctx := context.Background()
	now := time.Now()
	checks := []func() error{func() error { _, err := store.EnterpriseUserBindingExists(ctx, "e", "u"); return err }, func() error { return store.CreateSession(ctx, storedSession{}) }, func() error { _, err := store.UseSession(ctx, "h", now, time.Hour); return err }, func() error { return store.RevokeSession(ctx, "h", now) }, func() error { _, err := store.RevokeAndGetSession(ctx, "h", now); return err }, func() error { return store.CreateAuthorizationCode(ctx, storedAuthorizationCode{}) }, func() error { _, err := store.ExchangeAuthorizationCode(ctx, exchangeRequest{}); return err }, func() error { return store.CreateLoginAttempt(ctx, storedLoginAttempt{}) }, func() error { _, err := store.ConsumeLoginAttempt(ctx, "s", "b", now); return err }}
	for index, check := range checks {
		if err := check(); err == nil {
			t.Fatalf("operation %d returned nil", index)
		}
	}
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
