package browserauth

import (
	"context"
	"errors"
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
	migration := mustRead(t, filepath.Join(root, "db", "migrations", "000002_browser_sessions_and_approvals.sql")) + "\n" + mustRead(t, filepath.Join(root, "db", "migrations", "000003_oidc_login_attempt_quota_counters.sql"))
	queries := mustRead(t, filepath.Join(root, "db", "queries", "auth.sql"))
	for _, required := range []string{"browser_sessions", "oauth_authorization_codes", "oidc_login_attempts", "oidc_login_attempt_scope_counters", "oidc_login_attempt_browser_counters", "approval_queue_items", "id_hash", "code_hash", "state_hash", "binding_hash", "browser_id_hash", "user_agent_hash", "foreign key (enterprise_id, enterprise_user_id)", "check (char_length(id_hash) = 64", "check (char_length(code_hash) = 64", "check (char_length(state_hash) = 64", "check (char_length(binding_hash) = 64", "check (char_length(browser_id_hash) = 64", "create index idx_oidc_login_attempts_scope_expiry", "create index idx_oidc_login_attempts_scope_browser", "create index idx_oidc_login_attempt_browser_counters_scope_expiry"} {
		if !strings.Contains(strings.ToLower(migration), required) {
			t.Errorf("migration missing %q", required)
		}
	}
	quotaMigration := strings.ToLower(mustRead(t, filepath.Join(root, "db", "migrations", "000003_oidc_login_attempt_quota_counters.sql")))
	for _, required := range []string{"update oidc_login_attempts", "date_trunc('second'", "insert into oidc_login_attempt_scope_counters", "insert into oidc_login_attempt_browser_counters", "count(*)", "group by", "drop table if exists oidc_login_attempt_browser_counters", "drop constraint if exists ck_oidc_login_attempts_second_aligned"} {
		if !strings.Contains(quotaMigration, required) {
			t.Errorf("quota migration/backfill missing %q", required)
		}
	}
	migrationLockIndex := strings.Index(quotaMigration, "lock table oidc_login_attempts in access exclusive mode")
	normalizeIndex := strings.Index(quotaMigration, "update oidc_login_attempts")
	if migrationLockIndex < 0 || normalizeIndex <= migrationLockIndex {
		t.Errorf("quota migration must exclusively lock attempts before normalization: lock=%d update=%d", migrationLockIndex, normalizeIndex)
	}
	for _, forbidden := range []string{"session_token", "authorization_code text", "user_agent text", "verifier text", "browser_id text"} {
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
		t.Error("login attempt insertion must be separate from lock, cleanup, and quota queries")
	}
	lockAttempt := strings.ToLower(namedQuery(t, queries, "LockOIDCLoginAttemptScope"))
	deleteExpired := strings.ToLower(namedQuery(t, queries, "DeleteExpiredOIDCLoginAttemptsBatch"))
	deleteScopeBuckets := strings.ToLower(namedQuery(t, queries, "DeleteExpiredOIDCLoginAttemptScopeCountersBatch"))
	deleteBrowserBuckets := strings.ToLower(namedQuery(t, queries, "DeleteExpiredOIDCLoginAttemptBrowserCountersBatch"))
	sumGlobal := strings.ToLower(namedQuery(t, queries, "SumActiveOIDCLoginAttemptScope"))
	sumBrowser := strings.ToLower(namedQuery(t, queries, "SumActiveOIDCLoginAttemptBrowser"))
	incrementGlobal := strings.ToLower(namedQuery(t, queries, "IncrementOIDCLoginAttemptScopeCounter"))
	incrementBrowser := strings.ToLower(namedQuery(t, queries, "IncrementOIDCLoginAttemptBrowserCounter"))
	if !strings.Contains(lockAttempt, "pg_advisory_xact_lock") || !strings.Contains(lockAttempt, "enterprise") || !strings.Contains(lockAttempt, "client") {
		t.Error("login attempt scope must use a transaction advisory lock keyed by enterprise and client")
	}
	for name, cleanup := range map[string]string{"attempt": deleteExpired, "scope counter": deleteScopeBuckets, "browser counter": deleteBrowserBuckets} {
		for _, required := range []string{"limit 256", "enterprise_id", "client_id", "expires_at <=", "using expired"} {
			if !strings.Contains(cleanup, required) {
				t.Errorf("%s cleanup missing %q", name, required)
			}
		}
	}
	if strings.Contains(strings.ToLower(queries), "countoidcloginattempt") || strings.Contains(strings.ToLower(queries), "count(*)\nfrom oidc_login_attempts") {
		t.Error("login-attempt quota must never COUNT rows from oidc_login_attempts")
	}
	for name, quota := range map[string]string{"scope": sumGlobal, "browser": sumBrowser} {
		for _, required := range []string{"sum(active_count)", "enterprise_id", "client_id", "expires_at >"} {
			if !strings.Contains(quota, required) {
				t.Errorf("%s quota sum missing %q", name, required)
			}
		}
	}
	if !strings.Contains(sumBrowser, "browser_id_hash") {
		t.Error("browser quota sum must include browser hash")
	}
	for name, increment := range map[string]string{"scope": incrementGlobal, "browser": incrementBrowser} {
		for _, required := range []string{"insert into oidc_login_attempt_", "on conflict", "active_count + 1"} {
			if !strings.Contains(increment, required) {
				t.Errorf("%s quota increment missing %q", name, required)
			}
		}
	}
	postgresStore := strings.ToLower(mustRead(t, filepath.Join(root, "internal", "browserauth", "postgres_store.go")))
	createStart := strings.Index(postgresStore, "func (s *postgresstore) createloginattempt")
	consumeStart := strings.Index(postgresStore, "func (s *postgresstore) consumeloginattempt")
	if createStart >= 0 && consumeStart > createStart {
		postgresStore = postgresStore[createStart:consumeStart]
	}
	lockIndex := strings.Index(postgresStore, ".lockoidcloginattemptscope")
	deleteIndex := strings.Index(postgresStore, ".deleteexpiredoidcloginattemptsbatch")
	deleteScopeIndex := strings.Index(postgresStore, ".deleteexpiredoidcloginattemptscopecountersbatch")
	deleteBrowserIndex := strings.Index(postgresStore, ".deleteexpiredoidcloginattemptbrowsercountersbatch")
	globalCountIndex := strings.Index(postgresStore, ".sumactiveoidcloginattemptscope")
	browserCountIndex := strings.Index(postgresStore, ".sumactiveoidcloginattemptbrowser")
	incrementGlobalIndex := strings.Index(postgresStore, ".incrementoidcloginattemptscopecounter")
	incrementBrowserIndex := strings.Index(postgresStore, ".incrementoidcloginattemptbrowsercounter")
	insertIndex := strings.Index(postgresStore, ".createoidcloginattempt")
	commitIndex := strings.Index(postgresStore, ".commit(ctx)")
	if lockIndex < 0 || deleteIndex <= lockIndex || deleteScopeIndex <= deleteIndex || deleteBrowserIndex <= deleteScopeIndex || globalCountIndex <= deleteBrowserIndex || browserCountIndex <= globalCountIndex || incrementGlobalIndex <= browserCountIndex || incrementBrowserIndex <= incrementGlobalIndex || insertIndex <= incrementBrowserIndex || commitIndex <= insertIndex {
		t.Errorf("postgres login-attempt transaction order is lock=%d delete=%d scope-clean=%d browser-clean=%d global=%d browser=%d scope-inc=%d browser-inc=%d insert=%d commit=%d", lockIndex, deleteIndex, deleteScopeIndex, deleteBrowserIndex, globalCountIndex, browserCountIndex, incrementGlobalIndex, incrementBrowserIndex, insertIndex, commitIndex)
	}
	consumeStore := strings.ToLower(mustRead(t, filepath.Join(root, "internal", "browserauth", "postgres_store.go")))
	consumeStart = strings.Index(consumeStore, "func (s *postgresstore) consumeloginattempt")
	if consumeStart >= 0 {
		consumeStore = consumeStore[consumeStart:]
	}
	for _, required := range []string{".getoidcloginattemptscope", ".lockoidcloginattemptscope", ".getoidcloginattemptforupdate", ".decrementoidcloginattemptscopecounter", ".decrementoidcloginattemptbrowsercounter", ".deleteoidcloginattempt", ".commit(ctx)"} {
		if !strings.Contains(consumeStore, required) {
			t.Errorf("postgres consume transaction missing %q", required)
		}
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

func TestAuthorizeRateLimitSchemaAndQueriesAreHashOnlyAndAtomic(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	migration := strings.ToLower(mustRead(t, filepath.Join(root, "db", "migrations", "000002_browser_sessions_and_approvals.sql")))
	queries := mustRead(t, filepath.Join(root, "db", "queries", "auth.sql"))
	for _, required := range []string{
		"create table oidc_authorize_rate_limits",
		"source_hash text not null check (char_length(source_hash) = 64",
		"primary key (enterprise_id, client_id, source_hash, window_start)",
		"drop table if exists oidc_authorize_rate_limits",
	} {
		if !strings.Contains(migration, required) {
			t.Errorf("authorize rate schema missing %q", required)
		}
	}
	tableStart := strings.Index(migration, "create table oidc_authorize_rate_limits")
	if tableStart >= 0 {
		tableEnd := strings.Index(migration[tableStart:], ");")
		if tableEnd > 0 {
			table := migration[tableStart : tableStart+tableEnd]
			for _, forbidden := range []string{"source_ip", "raw_ip", "remote_addr", "forwarded_for"} {
				if strings.Contains(table, forbidden) {
					t.Errorf("authorize rate table persists raw source field %q", forbidden)
				}
			}
		}
	}
	consume := strings.ToLower(namedQuery(t, queries, "ConsumeOIDCAuthorizeRateLimit"))
	for _, required := range []string{"insert into oidc_authorize_rate_limits", "on conflict (enterprise_id, client_id, source_hash, window_start)", "do update", "request_count + 1", "request_count <", "returning"} {
		if !strings.Contains(consume, required) {
			t.Errorf("atomic authorize rate query missing %q", required)
		}
	}
	cleanup := strings.ToLower(namedQuery(t, queries, "DeleteExpiredOIDCAuthorizeRateLimits"))
	for _, required := range []string{"delete from oidc_authorize_rate_limits", "window_start <", "using expired", "limit 256"} {
		if !strings.Contains(cleanup, required) {
			t.Errorf("authorize rate cleanup missing %q", required)
		}
	}
	postgresLimiter := strings.ToLower(mustRead(t, filepath.Join(root, "internal", "browserauth", "postgres_authorize_rate_limiter.go")))
	cleanupIndex := strings.Index(postgresLimiter, ".deleteexpiredoidcauthorizeratelimits")
	consumeIndex := strings.Index(postgresLimiter, ".consumeoidcauthorizeratelimit")
	if cleanupIndex < 0 || consumeIndex <= cleanupIndex || !strings.Contains(postgresLimiter, "errors.is(err, pgx.errnorows)") {
		t.Errorf("postgres limiter must cleanup then use conditional atomic upsert; cleanup=%d consume=%d", cleanupIndex, consumeIndex)
	}
}

func TestNilPostgresAuthorizeRateLimiterFailsUnavailableWithoutPanic(t *testing.T) {
	limiter, err := NewPostgresAuthorizeRateLimiter(nil, DefaultAuthorizeRateLimitPerMinute, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = limiter.AllowAuthorize(context.Background(), "ent-1", "atlas", strings.Repeat("a", 64))
	if !errors.Is(err, ErrAuthorizeRateUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestNilPostgresStoreFailsWithoutPanic(t *testing.T) {
	store := NewPostgresStore(nil)
	ctx := context.Background()
	now := time.Now()
	checks := []func() error{func() error { _, err := store.EnterpriseUserBindingExists(ctx, "e", "u"); return err }, func() error { return store.CreateSession(ctx, storedSession{}) }, func() error { _, err := store.UseSession(ctx, "h", now, time.Hour); return err }, func() error { return store.RevokeSession(ctx, "h", now) }, func() error { _, err := store.RevokeAndGetSession(ctx, "h", now); return err }, func() error { return store.CreateAuthorizationCode(ctx, storedAuthorizationCode{}) }, func() error { _, err := store.ExchangeAuthorizationCode(ctx, exchangeRequest{}); return err }, func() error { return store.CreateLoginAttempt(ctx, storedLoginAttempt{}, DefaultLoginAttemptLimits()) }, func() error { _, err := store.ConsumeLoginAttempt(ctx, "s", "b", now); return err }}
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
