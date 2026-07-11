package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

const (
	e2eEnterprise = "ent_e2e"
	e2eUser       = "user_manager"
	e2eReviewer   = "user_reviewer"
	e2eTeam       = "team_research"
	e2eRoot       = "company_root"
	e2eOrgVersion = int64(1)
	e2eVerifier   = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
)

func TestBrowserSessionAndApproval(t *testing.T) {
	pool := openMigratedPostgres(t)
	idp := newFakeOIDCProvider(t)
	seedGatewayFixture(t, pool, idp.server.URL)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("agentnexus-e2e-approval-facts-secret-v1")
	verifier, err := app.NewHMACChangeFactsVerifier(secret, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	gateway := httptest.NewUnstartedServer(nil)
	gatewayURL := "https://" + gateway.Listener.Addr().String()
	consoleRedirect := "http://127.0.0.1:43123/auth/callback"
	oidcContext := context.WithValue(context.Background(), oauth2.HTTPClient, idp.server.Client())
	router, err := app.NewPostgresGatewayRouter(oidcContext, pool, app.PostgresGatewayConfig{
		ServiceName: "gateway-api", Version: "e2e",
		OIDC: browserauth.OIDCConfig{
			EnterpriseID: e2eEnterprise, EnterpriseIssuerURL: idp.server.URL,
			PublicIssuerURL: gatewayURL, ClientID: "enterprise-console", ClientSecret: "upstream-secret",
			CallbackURL: gatewayURL + "/oauth2/idp/callback", ConsoleClients: map[string][]string{"agentatlas": {consoleRedirect}},
			SigningKeyID: "gateway-e2e", SigningPrivateKey: key, HTTPTimeout: 5 * time.Second,
		},
		LoginAttemptLimits: browserauth.DefaultLoginAttemptLimits(), AuthorizeRateLimitPerMinute: browserauth.DefaultAuthorizeRateLimitPerMinute,
		ApprovalFactsVerifier: verifier, RequestTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway.Config.Handler = router
	gateway.StartTLS()
	defer gateway.Close()

	jar, _ := cookiejar.New(nil)
	client := gateway.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	challenge := s256(e2eVerifier)

	// Unknown browser: the first same-page redirect bootstraps the HttpOnly
	// browser cookie, and the second request redirects the whole page to IdP.
	authorize := gatewayURL + "/oauth2/authorize?" + authorizeQuery(consoleRedirect, "console-state-1", "console-nonce-1", challenge).Encode()
	bootstrap := mustRequest(t, client, http.MethodGet, authorize, "", nil)
	assertRedirect(t, bootstrap, gatewayURL)
	assertNoStore(t, bootstrap)
	assertNoCredentialLeak(t, bootstrap)
	idpRedirect := mustRequest(t, client, http.MethodGet, resolveLocation(gatewayURL, bootstrap.Header.Get("Location")), "", nil)
	assertRedirect(t, idpRedirect, idp.server.URL)
	assertNoCredentialLeak(t, idpRedirect)

	idpClient := idp.server.Client()
	idpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	upstreamCallback := mustRequest(t, idpClient, http.MethodGet, idpRedirect.Header.Get("Location"), "", nil)
	assertRedirect(t, upstreamCallback, gatewayURL)
	callback := mustRequest(t, client, http.MethodGet, upstreamCallback.Header.Get("Location"), "", nil)
	assertRedirect(t, callback, consoleRedirect)
	assertNoStore(t, callback)
	assertNoCredentialLeak(t, callback)

	// The authenticated browser now authorizes silently; this code is bound to
	// the original S256 challenge and is the only artifact exchanged by JS.
	silentURL := gatewayURL + "/oauth2/authorize?" + authorizeQuery(consoleRedirect, "console-state-2", "console-nonce-2", challenge).Encode()
	silent := mustRequest(t, client, http.MethodGet, silentURL, "", nil)
	assertRedirect(t, silent, consoleRedirect)
	location, _ := url.Parse(silent.Header.Get("Location"))
	code := location.Query().Get("code")
	if code == "" || location.Query().Get("state") != "console-state-2" {
		t.Fatalf("silent redirect=%s", location)
	}
	silent.Body.Close()
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {e2eVerifier}, "client_id": {"agentatlas"}, "redirect_uri": {consoleRedirect}}
	token := mustRequest(t, client, http.MethodPost, gatewayURL+"/oauth2/token", tokenForm.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if token.StatusCode != http.StatusOK {
		t.Fatalf("token status=%d body=%s", token.StatusCode, readBody(t, token))
	}
	assertNoStore(t, token)
	var tokenPayload map[string]any
	decodeJSON(t, token, &tokenPayload)
	if tokenPayload["id_token"] == "" || tokenPayload["access_token"] != nil || tokenPayload["refresh_token"] != nil {
		t.Fatalf("unsafe token payload=%v", tokenPayload)
	}

	me := mustRequest(t, client, http.MethodGet, gatewayURL+"/v1/browser-sessions/me", "", nil)
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d body=%s", me.StatusCode, readBody(t, me))
	}
	assertNoStore(t, me)
	var profile struct {
		Authenticated bool     `json:"authenticated"`
		EnterpriseID  string   `json:"enterprise_id"`
		UserID        string   `json:"enterprise_user_id"`
		OrgVersion    int64    `json:"org_version"`
		OrgUnitIDs    []string `json:"org_unit_ids"`
	}
	decodeJSON(t, me, &profile)
	if !profile.Authenticated || profile.EnterpriseID != e2eEnterprise || profile.UserID != e2eUser || profile.OrgVersion != e2eOrgVersion || !contains(profile.OrgUnitIDs, e2eTeam) {
		t.Fatalf("profile=%+v", profile)
	}

	low := resolveApproval(t, client, gatewayURL, secret, "idem-low-1234567890", approvalFacts{ResourceID: "knowledge-low", RequestedRisk: approval.RiskLow})
	if low.Mode != approval.ModeSingleConfirmation || low.RiskLevel != approval.RiskLow || low.AutoPublish || low.RequesterUserID != e2eUser {
		t.Fatalf("low route=%+v", low)
	}
	high := resolveApproval(t, client, gatewayURL, secret, "idem-high-123456789", approvalFacts{ResourceID: "knowledge-high", RequestedRisk: approval.RiskHigh, ExternalSideEffect: true})
	if high.Mode != approval.ModeUpwardReview || high.RiskLevel != approval.RiskHigh || high.ReviewerUserID != e2eReviewer || high.AutoPublish {
		t.Fatalf("high route=%+v", high)
	}

	grantBody := `{"case_ticket_id":"ticket-e2e","org_unit_id":"team_research","org_version":1,"resource_type":"dream_evidence","resource_id":"dream-evidence-1","action":"read","ttl_seconds":300}`
	grant := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/step-grants", grantBody, map[string]string{"Content-Type": "application/json"})
	if grant.StatusCode != http.StatusCreated {
		t.Fatalf("grant status=%d body=%s", grant.StatusCode, readBody(t, grant))
	}
	assertNoStore(t, grant)
	var grantPayload struct {
		Token  string   `json:"token"`
		Scopes []string `json:"scopes"`
	}
	decodeJSON(t, grant, &grantPayload)
	if grantPayload.Token == "" || len(grantPayload.Scopes) != 1 || grantPayload.Scopes[0] != "dream:evidence:read" {
		t.Fatalf("grant payload=%+v", grantPayload)
	}
	verifyBody := fmt.Sprintf(`{"token":%q,"resource_type":"dream_evidence","resource_id":"dream-evidence-1","action":"read","scope":"dream:evidence:read"}`, grantPayload.Token)
	verify := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/tickets/verify", verifyBody, map[string]string{"Content-Type": "application/json"})
	if verify.StatusCode != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verify.StatusCode, readBody(t, verify))
	}
	assertNoStore(t, verify)

	assertOpaqueStorage(t, pool, grantPayload.Token)
	logout := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/browser-sessions/logout", "", nil)
	if logout.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d", logout.StatusCode)
	}
	logout.Body.Close()
	postLogout := mustRequest(t, client, http.MethodGet, gatewayURL+"/v1/browser-sessions/me", "", nil)
	if postLogout.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post logout me=%d", postLogout.StatusCode)
	}
	postLogout.Body.Close()
}

// These are the cross-transaction primitives used by Tasks 2-5. Each blocked
// acquisition has a short deadline so a lock-order regression cannot hang CI.
func TestPostgresContractSerializationAndRollback(t *testing.T) {
	pool := openMigratedPostgres(t)
	seedLockFixture(t, pool)
	t.Run("task2 login-attempt quota lock", func(t *testing.T) {
		assertSerialized(t, pool, "SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", e2eEnterprise, "agentatlas")
	})
	t.Run("task3 org publication trigger", func(t *testing.T) {
		assertStatementSerialized(t, pool, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", []any{e2eEnterprise}, `INSERT INTO org_versions(id,enterprise_id,version_number,source_event_id) VALUES ('lock-version-2',$1,2,'lock-event-2')`, []any{e2eEnterprise})
	})
	t.Run("task4 policy publication trigger", func(t *testing.T) {
		assertStatementSerialized(t, pool, "SELECT pg_advisory_xact_lock(hashtextextended($1, 2))", []any{e2eEnterprise}, `UPDATE enterprise_approval_policies SET policy_version=2,updated_at=clock_timestamp()+interval '1 second' WHERE enterprise_id=$1`, []any{e2eEnterprise})
	})
	t.Run("task5 ownership trigger", func(t *testing.T) {
		assertStatementSerialized(t, pool, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", []any{e2eEnterprise}, `INSERT INTO sensitive_resource_ownerships(enterprise_id,resource_type,resource_id,org_version,org_unit_id) VALUES ($1,'dream_evidence','lock-evidence',1,'company_root')`, []any{e2eEnterprise})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,enterprise_id,action,decision,event_hash) VALUES ('rolled-back-audit',$1,'e2e.rollback','deny',$2)`, e2eEnterprise, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE id='rolled-back-audit'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rollback count=%d err=%v", count, err)
	}

	// The snapshot parent FK is deferred: child-before-parent succeeds only if
	// the complete graph is valid at commit.
	_, err = pool.Exec(ctx, `INSERT INTO org_events(id,enterprise_id,event_type,source_hash) VALUES ('deferred-event',$1,'e2e','sha256:deferred')`, e2eEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO org_versions(id,enterprise_id,version_number,source_event_id) VALUES ('deferred-version',$1,3,'deferred-event')`, e2eEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO org_policy_snapshot_units(enterprise_id,version_number,org_unit_id,parent_id) VALUES ($1,3,'child','parent'),($1,3,'parent',NULL)`, e2eEnterprise); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatalf("deferred FK commit: %v", err)
	}
}

type approvalFacts struct {
	ResourceID         string
	RequestedRisk      approval.RiskLevel
	ExternalSideEffect bool
}

func resolveApproval(t *testing.T, client *http.Client, gatewayURL string, secret []byte, idempotency string, facts approvalFacts) approval.Route {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	idemSum := sha256.Sum256([]byte(idempotency))
	input := app.ChangeFactsVerificationInput{EnterpriseID: e2eEnterprise, ActorUserID: e2eUser, OrgVersion: e2eOrgVersion, OrgUnitID: e2eTeam, ResourceType: "knowledge", ResourceID: facts.ResourceID, Action: "knowledge.publish_low_risk", ChangedFields: []string{"title"}, ImpactedOrgUnitIDs: []string{e2eTeam}, ImpactedUserCount: 1, ExternalSideEffect: facts.ExternalSideEffect, FactsIssuedAt: now, FactsExpiresAt: now.Add(4 * time.Minute), FactsNonce: "nonce-approval-123456789", IdempotencyKeyHash: hex.EncodeToString(idemSum[:])}
	signature, err := app.ComputeChangeFactsAttestation(secret, input)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"org_version": input.OrgVersion, "org_unit_id": input.OrgUnitID, "resource_type": input.ResourceType, "resource_id": input.ResourceID, "action": input.Action, "changed_fields": input.ChangedFields, "impacted_org_unit_ids": input.ImpactedOrgUnitIDs, "impacted_user_count": input.ImpactedUserCount, "published_behavior_change": false, "external_side_effect": input.ExternalSideEffect, "requested_risk": facts.RequestedRisk, "facts_issued_at": input.FactsIssuedAt, "facts_expires_at": input.FactsExpiresAt, "facts_nonce": input.FactsNonce})
	resp := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/approvals/resolve", string(body), map[string]string{"Content-Type": "application/json", "Idempotency-Key": idempotency, "X-Approval-Facts-Attestation": signature})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approval status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	assertNoStore(t, resp)
	var route approval.Route
	decodeJSON(t, resp, &route)
	return route
}

func openMigratedPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTNEXUS_E2E_POSTGRES_DSN is required for the real-PostgreSQL acceptance suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("agentnexus_e2e_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		admin.Close()
		t.Fatal(err)
	}
	applyMigrations(t, pool)
	t.Cleanup(func() {
		pool.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, _ = admin.Exec(cleanup, `DROP SCHEMA IF EXISTS `+pgx.Identifier{schema}.Sanitize()+` CASCADE`)
		admin.Close()
	})
	return pool
}

func applyMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		up := strings.Index(text, "-- +goose Up")
		down := strings.Index(text, "-- +goose Down")
		if up < 0 || down <= up {
			t.Fatalf("migration %s lacks goose boundaries", name)
		}
		sql := text[up+len("-- +goose Up") : down]
		sql = strings.ReplaceAll(sql, "-- +goose StatementBegin", "")
		sql = strings.ReplaceAll(sql, "-- +goose StatementEnd", "")
		if _, err = pool.Exec(ctx, sql); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
}

func seedLockFixture(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	statements := []string{
		`INSERT INTO enterprises(id,name) VALUES ('ent_e2e','E2E Enterprise')`,
		`INSERT INTO enterprise_users(id,enterprise_id,display_name) VALUES ('user_manager','ent_e2e','Manager')`,
		`INSERT INTO org_units(id,enterprise_id,parent_id,name,unit_type) VALUES ('company_root','ent_e2e',NULL,'Company','company')`,
		`INSERT INTO org_events(id,enterprise_id,event_type,source_hash) VALUES ('lock-event-1','ent_e2e','e2e','sha256:one'),('lock-event-2','ent_e2e','e2e','sha256:two')`,
		`INSERT INTO org_versions(id,enterprise_id,version_number,source_event_id) VALUES ('lock-version-1','ent_e2e',1,'lock-event-1')`,
		`INSERT INTO org_policy_snapshot_units(enterprise_id,version_number,org_unit_id,parent_id) VALUES ('ent_e2e',1,'company_root',NULL)`,
		`INSERT INTO org_policy_snapshot_memberships(enterprise_id,version_number,enterprise_user_id,org_unit_id,role) VALUES ('ent_e2e',1,'user_manager','company_root','approve_high_risk')`,
		`UPDATE org_versions SET policy_snapshot_sealed=true WHERE enterprise_id='ent_e2e' AND version_number=1`,
		`INSERT INTO enterprise_approval_policies(enterprise_id,minimum_risk,max_low_impacted_users,max_low_impacted_org_units,policy_version) VALUES ('ent_e2e','low',25,1,1)`,
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
}

func seedGatewayFixture(t *testing.T, pool *pgxpool.Pool, issuer string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticketHash := tickets.HashCaseTicketToken("unused-e2e-ticket-token")
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO enterprises(id,name) VALUES ($1,'E2E Enterprise')`, []any{e2eEnterprise}},
		{`INSERT INTO enterprise_users(id,enterprise_id,display_name) VALUES ($1,$3,'Manager'),($2,$3,'Reviewer')`, []any{e2eUser, e2eReviewer, e2eEnterprise}},
		{`INSERT INTO external_identities(id,enterprise_id,enterprise_user_id,provider,external_subject) VALUES ('identity-e2e',$1,$2,$3,'subject-e2e')`, []any{e2eEnterprise, e2eUser, issuer}},
		{`INSERT INTO org_units(id,enterprise_id,parent_id,name,unit_type) VALUES ($1,$3,NULL,'Company','company'),($2,$3,$1,'Research','department')`, []any{e2eRoot, e2eTeam, e2eEnterprise}},
		{`INSERT INTO org_events(id,enterprise_id,event_type,source_hash) VALUES ('event-e2e',$1,'publish','sha256:e2e')`, []any{e2eEnterprise}},
		{`INSERT INTO org_versions(id,enterprise_id,version_number,source_event_id) VALUES ('version-e2e',$1,1,'event-e2e')`, []any{e2eEnterprise}},
		{`INSERT INTO org_policy_snapshot_units(enterprise_id,version_number,org_unit_id,parent_id) VALUES ($1,1,$2,NULL),($1,1,$3,$2)`, []any{e2eEnterprise, e2eRoot, e2eTeam}},
		{`INSERT INTO org_policy_snapshot_memberships(enterprise_id,version_number,enterprise_user_id,org_unit_id,role) VALUES ($1,1,$2,$3,'member'),($1,1,$2,$3,'publish_low_risk'),($1,1,$2,$3,'approve_high_risk'),($1,1,$4,$5,'manager'),($1,1,$4,$5,'approve_high_risk')`, []any{e2eEnterprise, e2eUser, e2eTeam, e2eReviewer, e2eRoot}},
		{`UPDATE org_versions SET policy_snapshot_sealed=true WHERE enterprise_id=$1 AND version_number=1`, []any{e2eEnterprise}},
		{`INSERT INTO enterprise_approval_policies(enterprise_id,minimum_risk,max_low_impacted_users,max_low_impacted_org_units,policy_version) VALUES ($1,'low',25,1,1)`, []any{e2eEnterprise}},
		{`INSERT INTO case_tickets(id,enterprise_id,actor_user_id,request_id,status,expires_at,token_hash) VALUES ('ticket-e2e',$1,$2,'request-e2e','active',now()+interval '30 minutes',$3)`, []any{e2eEnterprise, e2eUser, ticketHash}},
		{`INSERT INTO sensitive_resource_ownerships(enterprise_id,resource_type,resource_id,org_version,org_unit_id) VALUES ($1,'dream_evidence','dream-evidence-1',1,$2)`, []any{e2eEnterprise, e2eTeam}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", statement.sql, err)
		}
	}
}

func assertSerialized(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(context.Background())
	if _, err = first.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
	second, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(context.Background())
	blocked, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_, err = second.Exec(blocked, query, args...)
	stop()
	if err == nil {
		t.Fatal("second connection acquired serialized lock")
	}
	_ = second.Rollback(context.Background())
	if err = first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	acquire, release := context.WithTimeout(context.Background(), 2*time.Second)
	defer release()
	third, err := pool.Begin(acquire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = third.Exec(acquire, query, args...); err != nil {
		t.Fatalf("lock did not release: %v", err)
	}
	if err = third.Rollback(acquire); err != nil {
		t.Fatal(err)
	}
}

func assertStatementSerialized(t *testing.T, pool *pgxpool.Pool, lockQuery string, lockArgs []any, statement string, statementArgs []any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(context.Background())
	if _, err = first.Exec(ctx, lockQuery, lockArgs...); err != nil {
		t.Fatal(err)
	}
	second, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_, err = second.Exec(blocked, statement, statementArgs...)
	stop()
	if err == nil {
		t.Fatal("serialized database mutation did not block")
	}
	_ = second.Rollback(context.Background())
	if err = first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	acquire, release := context.WithTimeout(context.Background(), 2*time.Second)
	defer release()
	if _, err = pool.Exec(acquire, statement, statementArgs...); err != nil {
		t.Fatalf("serialized mutation did not complete after release: %v", err)
	}
}

func assertOpaqueStorage(t *testing.T, pool *pgxpool.Pool, grantToken string) {
	t.Helper()
	var invalid int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM browser_sessions WHERE id_hash !~ '^[0-9a-f]{64}$'`).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatalf("session hash contract count=%d err=%v", invalid, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM step_grant_issuances WHERE token_hash=$1`, grantToken).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatalf("raw grant token stored count=%d err=%v", invalid, err)
	}
}

func authorizeQuery(redirect, state, nonce, challenge string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {"agentatlas"}, "redirect_uri": {redirect}, "scope": {"openid profile"}, "state": {state}, "nonce": {nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
}
func s256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func resolveLocation(base, location string) string {
	parsed, _ := url.Parse(location)
	root, _ := url.Parse(base)
	return root.ResolveReference(parsed).String()
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mustRequest(t *testing.T, client *http.Client, method, target, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func assertRedirect(t *testing.T, resp *http.Response, prefix string) {
	t.Helper()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resolveLocation(resp.Request.URL.String(), resp.Header.Get("Location")), prefix) {
		t.Fatalf("redirect status=%d location=%q want prefix=%q", resp.StatusCode, resp.Header.Get("Location"), prefix)
	}
}
func assertNoStore(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control=%q path=%s", resp.Header.Get("Cache-Control"), resp.Request.URL.Path)
	}
}
func assertNoCredentialLeak(t *testing.T, resp *http.Response) {
	t.Helper()
	raw := readBody(t, resp)
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "window.open") || strings.Contains(lower, "manual ticket") || strings.Contains(lower, "session_token") {
		t.Fatalf("credential/manual flow leaked: %q", raw)
	}
}
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.Body == nil {
		return ""
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func decodeJSON(t *testing.T, resp *http.Response, target any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

type fakeOIDCProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
	mu     sync.Mutex
	nonces map[string]string
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "fake-idp"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDCProvider{key: key, signer: signer, nonces: map[string]string{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}
func (f *fakeOIDCProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeFakeJSON(w, map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/jwks":
		writeFakeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "fake-idp", Algorithm: "RS256", Use: "sig"}}})
	case "/authorize":
		code := "upstream-good"
		f.mu.Lock()
		f.nonces[code] = r.URL.Query().Get("nonce")
		f.mu.Unlock()
		target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		q := target.Query()
		q.Set("code", code)
		q.Set("state", r.URL.Query().Get("state"))
		target.RawQuery = q.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		code := r.Form.Get("code")
		f.mu.Lock()
		nonce := f.nonces[code]
		delete(f.nonces, code)
		f.mu.Unlock()
		if nonce == "" {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		now := time.Now().UTC()
		claims := struct {
			jwt.Claims
			Nonce string `json:"nonce"`
		}{jwt.Claims{Issuer: f.server.URL, Subject: "subject-e2e", Audience: jwt.Audience{"enterprise-console"}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute))}, nonce}
		raw, _ := jwt.Signed(f.signer).Claims(claims).Serialize()
		writeFakeJSON(w, map[string]any{"access_token": "upstream-only", "token_type": "Bearer", "expires_in": 300, "id_token": raw})
	default:
		http.NotFound(w, r)
	}
}
func writeFakeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
