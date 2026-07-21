package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
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
	approvalChannel := approvaltransport.NewMemoryChannel()

	gateway := httptest.NewUnstartedServer(nil)
	gatewayURL := "https://" + gateway.Listener.Addr().String()
	consoleRedirect := "http://127.0.0.1:43123/auth/callback"
	consoleSecret := "AgentAtlas-e2e-console-secret-N8xQ3vK7pT4yR9dF2"
	consoleCredentials, err := browserauth.NewConsoleClientCredentials(map[string][]string{"agentatlas": {consoleSecret}})
	if err != nil {
		t.Fatal(err)
	}
	oidcContext := context.WithValue(context.Background(), oauth2.HTTPClient, idp.server.Client())
	router, _, err := app.NewPostgresGatewayRouter(oidcContext, pool, app.PostgresGatewayConfig{
		ServiceName: "gateway-api", Version: "e2e",
		OIDC: browserauth.OIDCConfig{
			EnterpriseID: e2eEnterprise, EnterpriseIssuerURL: idp.server.URL,
			PublicIssuerURL: gatewayURL, ClientID: "enterprise-console", UpstreamClientSecret: "Upstream-e2e-IDP-secret-Q7mV2xK9pR4tY8dF3",
			CallbackURL: gatewayURL + "/oauth2/idp/callback", ConsoleClients: map[string][]string{"agentatlas": {consoleRedirect}},
			ConsoleCredentials: consoleCredentials,
			SigningKeyID:       "gateway-e2e", SigningPrivateKey: key, HTTPTimeout: 5 * time.Second,
		},
		LoginAttemptLimits: browserauth.DefaultLoginAttemptLimits(), AuthorizeRateLimitPerMinute: browserauth.DefaultAuthorizeRateLimitPerMinute,
		ApprovalChannel: approvalChannel, RequestTimeout: 10 * time.Second,
		AllowEphemeralAuditKey: true,
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
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {e2eVerifier}, "redirect_uri": {consoleRedirect}}
	token := mustRequest(t, client, http.MethodPost, gatewayURL+"/oauth2/token", tokenForm.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("agentatlas:"+consoleSecret))})
	if token.StatusCode != http.StatusOK {
		t.Fatalf("token status=%d body=%s", token.StatusCode, readBody(t, token))
	}
	assertNoStore(t, token)
	var tokenPayload map[string]any
	decodeJSON(t, token, &tokenPayload)
	accessToken, _ := tokenPayload["access_token"].(string)
	if tokenPayload["id_token"] == "" || accessToken == "" || tokenPayload["refresh_token"] != nil {
		t.Fatalf("token payload fields invalid id=%v access=%v refresh_present=%v", tokenPayload["id_token"] != "", accessToken != "", tokenPayload["refresh_token"] != nil)
	}
	assertBrowserAccessTokenStorage(t, pool, accessToken)
	bffClient := &http.Client{Transport: bearerTransport{base: client.Transport, token: accessToken}}

	me := mustRequest(t, bffClient, http.MethodGet, gatewayURL+"/v1/browser-sessions/me", "", nil)
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d body=%s", me.StatusCode, readBody(t, me))
	}
	assertNoStore(t, me)
	var profile struct {
		Authenticated       bool     `json:"authenticated"`
		EnterpriseID        string   `json:"enterprise_id"`
		UserID              string   `json:"enterprise_user_id"`
		OrgVersion          int64    `json:"org_version"`
		OrgUnitIDs          []string `json:"org_unit_ids"`
		Permissions         []string `json:"permissions"`
		AdvancedModeAllowed bool     `json:"advanced_mode_allowed"`
	}
	decodeJSON(t, me, &profile)
	if !profile.Authenticated || profile.EnterpriseID != e2eEnterprise || profile.UserID != e2eUser || profile.OrgVersion != e2eOrgVersion || !contains(profile.OrgUnitIDs, e2eTeam) {
		t.Fatalf("profile=%+v", profile)
	}
	if !profile.AdvancedModeAllowed || !equalStrings(profile.Permissions, []string{"approve_high_risk", "publish_low_risk", "service_mode", "suggest"}) {
		t.Fatalf("public profile permissions=%v advanced=%v", profile.Permissions, profile.AdvancedModeAllowed)
	}

	// Trusted context cutover: identity, org scope and sealed version derive
	// from the verified browser BFF token; the request carries only correlation, the
	// resource binding and the requested capability.
	decisionBody := `{"request_id":"decision-e2e-1","resource_type":"knowledge","resource_id":"knowledge-low","capability":"knowledge.suggest"}`
	decisionResponse := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/authorization/decisions", decisionBody, map[string]string{"Content-Type": "application/json"})
	if decisionResponse.StatusCode != http.StatusOK {
		t.Fatalf("decision status=%d body=%s", decisionResponse.StatusCode, readBody(t, decisionResponse))
	}
	assertNoStore(t, decisionResponse)
	var decision struct {
		Decision       string   `json:"decision"`
		Permissions    []string `json:"permissions"`
		OrgUnitIDs     []string `json:"org_unit_ids"`
		MaskFields     []string `json:"mask_fields"`
		RiskLevel      string   `json:"risk_level"`
		FallbackAction string   `json:"fallback_action"`
		OrgVersion     int64    `json:"org_version"`
	}
	decodeJSON(t, decisionResponse, &decision)
	if decision.Decision != "allow" || decision.RiskLevel != "low" || decision.OrgVersion != e2eOrgVersion || decision.FallbackAction != "" || !equalStrings(decision.Permissions, []string{"suggest"}) || !equalStrings(decision.OrgUnitIDs, []string{e2eTeam}) || decision.MaskFields == nil || len(decision.MaskFields) != 0 {
		t.Fatalf("low authorization decision=%+v", decision)
	}

	// GA Task 0E approval TRANSMISSION: the verified session transmits the
	// caller's signed plan UNCHANGED, records the authority's evidence and
	// revokes — AgentNexus never chooses an approver anywhere below.
	transmitted := transmitApprovalPlan(t, bffClient, gatewayURL)
	if transmitted.Status != "delivered" || transmitted.PlanRef != e2ePlanRef || transmitted.DeliveryAttempts != 1 || transmitted.Decision != "" {
		t.Fatalf("transmitted=%+v", transmitted)
	}
	deliveries := approvalChannel.Deliveries()
	if len(deliveries) != 1 || deliveries[0].PlanRef != e2ePlanRef || deliveries[0].PlanHash != e2ePlanHash || deliveries[0].Authority != "agentatlas" || deliveries[0].Capability != "knowledge.article.publish" || deliveries[0].ParameterHash != e2eParamHash {
		t.Fatalf("channel deliveries=%+v", deliveries)
	}
	statusResp := mustRequest(t, bffClient, http.MethodGet, gatewayURL+"/v1/approvals/transmissions/"+e2ePlanRef, "", nil)
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", statusResp.StatusCode, readBody(t, statusResp))
	}
	assertNoStore(t, statusResp)
	var transmissionStatus approvalTransmissionView
	decodeJSON(t, statusResp, &transmissionStatus)
	if transmissionStatus.Status != "delivered" {
		t.Fatalf("transmission status=%+v", transmissionStatus)
	}

	wrongHash := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/approvals/evidence", e2eEvidenceBody(t, "sha256:"+strings.Repeat("9", 64)), map[string]string{"Content-Type": "application/json"})
	if wrongHash.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong-hash evidence status=%d body=%s", wrongHash.StatusCode, readBody(t, wrongHash))
	}
	wrongHash.Body.Close()

	recorded := recordApprovalEvidence(t, bffClient, gatewayURL)
	if recorded.Status != "evidence_recorded" || recorded.Decision != "approved" {
		t.Fatalf("recorded=%+v", recorded)
	}
	duplicate := recordApprovalEvidence(t, bffClient, gatewayURL)
	if duplicate.Status != "evidence_recorded" {
		t.Fatalf("duplicate evidence=%+v", duplicate)
	}

	revokeResp := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/approvals/transmissions/"+e2ePlanRef+"/revocations", `{"request_id":"revoke-e2e-1","reason":"requester withdrew the change"}`, map[string]string{"Content-Type": "application/json"})
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revokeResp.StatusCode, readBody(t, revokeResp))
	}
	var revoked approvalTransmissionView
	decodeJSON(t, revokeResp, &revoked)
	if revoked.Status != "revoked" {
		t.Fatalf("revoked=%+v", revoked)
	}

	var transmissionRows, attemptRows, evidenceRows, revocationRows int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM approval_transmissions WHERE tenant_ref=$1 AND plan_ref=$2 AND status='revoked' AND decision='approved'`, e2eEnterprise, e2ePlanRef).Scan(&transmissionRows); err != nil || transmissionRows != 1 {
		t.Fatalf("transmission rows=%d err=%v", transmissionRows, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM approval_delivery_attempts WHERE tenant_ref=$1 AND plan_ref=$2 AND outcome='delivered'`, e2eEnterprise, e2ePlanRef).Scan(&attemptRows); err != nil || attemptRows != 1 {
		t.Fatalf("attempt rows=%d err=%v", attemptRows, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM approval_evidence_records WHERE tenant_ref=$1 AND plan_ref=$2 AND decision='approved' AND consumed_at IS NULL`, e2eEnterprise, e2ePlanRef).Scan(&evidenceRows); err != nil || evidenceRows != 1 {
		t.Fatalf("evidence rows=%d err=%v", evidenceRows, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM approval_transmission_revocations WHERE tenant_ref=$1 AND plan_ref=$2`, e2eEnterprise, e2ePlanRef).Scan(&revocationRows); err != nil || revocationRows != 1 {
		t.Fatalf("revocation rows=%d err=%v", revocationRows, err)
	}
	// Two submission acts were audited (the accepted record and its idempotent
	// duplicate) but exactly ONE acceptance marker exists: the lineage
	// distinguishes accepted evidence from resubmissions.
	for action, want := range map[string]int{"approval.plan.transmit": 1, "approval.evidence.submitted": 2, "approval.evidence.recorded": 1, "approval.transmission.revoke": 1} {
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_events WHERE enterprise_id=$1 AND action=$2`, e2eEnterprise, action).Scan(&count); err != nil || count != want {
			t.Fatalf("audit action=%s count=%d want=%d err=%v", action, count, want, err)
		}
	}

	grantBody := `{"case_ticket_id":"ticket-e2e","resource_type":"dream_evidence","resource_id":"dream-evidence-1","action":"read","ttl_seconds":300}`
	grant := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/step-grants", grantBody, map[string]string{"Content-Type": "application/json"})
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
	verify := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/tickets/verify", verifyBody, map[string]string{"Content-Type": "application/json"})
	if verify.StatusCode != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verify.StatusCode, readBody(t, verify))
	}
	assertNoStore(t, verify)
	repeatVerify := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/tickets/verify", verifyBody, map[string]string{"Content-Type": "application/json"})
	if repeatVerify.StatusCode != http.StatusOK {
		t.Fatalf("repeat verify status=%d body=%s", repeatVerify.StatusCode, readBody(t, repeatVerify))
	}
	repeatVerify.Body.Close()
	if _, err := pool.Exec(context.Background(), `CREATE FUNCTION fail_sensitive_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$; CREATE TRIGGER fail_sensitive_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_sensitive_audit()`); err != nil {
		t.Fatal(err)
	}
	failedVerify := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/tickets/verify", verifyBody, map[string]string{"Content-Type": "application/json"})
	if failedVerify.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("audit-failed verify status=%d body=%s", failedVerify.StatusCode, readBody(t, failedVerify))
	}
	failedVerify.Body.Close()

	assertOpaqueStorage(t, pool, grantPayload.Token)
	failedLogout := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/browser-sessions/logout", "", nil)
	if failedLogout.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("audit-failed logout status=%d body=%s", failedLogout.StatusCode, readBody(t, failedLogout))
	}
	failedLogout.Body.Close()
	stillActive := mustRequest(t, bffClient, http.MethodGet, gatewayURL+"/v1/browser-sessions/me", "", nil)
	if stillActive.StatusCode != http.StatusUnauthorized {
		t.Fatalf("audit-failed logout restored access: %d body=%s", stillActive.StatusCode, readBody(t, stillActive))
	}
	stillActive.Body.Close()
	if _, err := pool.Exec(context.Background(), `DROP TRIGGER fail_sensitive_audit ON audit_events; DROP FUNCTION fail_sensitive_audit()`); err != nil {
		t.Fatal(err)
	}
	retriedLogout := mustRequest(t, bffClient, http.MethodPost, gatewayURL+"/v1/browser-sessions/logout", "", nil)
	if retriedLogout.StatusCode != http.StatusNoContent {
		t.Fatalf("retried logout status=%d body=%s", retriedLogout.StatusCode, readBody(t, retriedLogout))
	}
	retriedLogout.Body.Close()
	for action, want := range map[string]int{"step_grant.verify": 2, "browser_session.logout": 1} {
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_events WHERE enterprise_id=$1 AND action=$2 AND event_hash ~ '^sha256:[0-9a-f]{64}$'`, e2eEnterprise, action).Scan(&count); err != nil || count != want {
			t.Fatalf("audit action=%s count=%d err=%v", action, count, err)
		}
	}
	postLogout := mustRequest(t, bffClient, http.MethodGet, gatewayURL+"/v1/browser-sessions/me", "", nil)
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
	t.Run("task2 production login-attempt quota serialization", func(t *testing.T) {
		assertProductionLoginAttemptQuota(t, pool)
	})
	t.Run("task3 org publication trigger", func(t *testing.T) {
		assertStatementSerialized(t, pool, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", []any{e2eEnterprise}, `INSERT INTO org_versions(id,enterprise_id,version_number,source_event_id) VALUES ('lock-version-2',$1,2,'lock-event-2')`, []any{e2eEnterprise})
	})
	// The former "task4 policy publication trigger" subtest is retired with
	// GA Task 0E: enterprise_approval_policies (and its advisory-lock domain
	// 2 serialization) existed only to feed the approval resolver, which
	// migration 000009 removes. Transmission-side serialization (per-plan
	// advisory lock domain 4) is exercised by the approvaltransport postgres
	// integration suite.
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

const (
	e2ePlanRef     = "apl_e2e0123456789abcdef"
	e2eApprovalRef = "apv_e2e0123456789abcdef"
)

var (
	e2ePlanHash  = "sha256:" + strings.Repeat("1", 64)
	e2eParamHash = "sha256:" + strings.Repeat("2", 64)
	// e2eDecidedAt is frozen at package init so the duplicate evidence
	// submission is byte-identical (idempotent), not a mutated replay.
	e2eDecidedAt = time.Now().UTC().Format(time.RFC3339)
)

// approvalTransmissionView is the transmission diagnostics response shape.
type approvalTransmissionView struct {
	PlanRef          string `json:"plan_ref"`
	Status           string `json:"status"`
	Decision         string `json:"decision"`
	DeliveryAttempts int    `json:"delivery_attempts"`
}

func transmitApprovalPlan(t *testing.T, client *http.Client, gatewayURL string) approvalTransmissionView {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"request_id":           "transmit-e2e-1",
		"business_context_ref": "wc_e2e0123456789abcdef",
		"capability":           "knowledge.article.publish",
		"parameter_hash":       e2eParamHash,
		"purpose":              "publish knowledge article 42",
		"plan":                 map[string]any{"plan_ref": e2ePlanRef, "plan_hash": e2ePlanHash, "authority": "agentatlas"},
		"expires_at":           time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339),
	})
	resp := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/approvals/transmissions", string(body), map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("transmit status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	assertNoStore(t, resp)
	var view approvalTransmissionView
	decodeJSON(t, resp, &view)
	return view
}

func e2eEvidenceBody(t *testing.T, parameterHash string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"request_id": "evidence-e2e-1",
		"evidence": map[string]any{
			"approval_ref":       e2eApprovalRef,
			"plan_ref":           e2ePlanRef,
			"plan_hash":          e2ePlanHash,
			"capability":         "knowledge.article.publish",
			"parameter_hash":     parameterHash,
			"decision":           "approved",
			"approver_authority": "agentatlas",
			"decided_at":         e2eDecidedAt,
			"attestation":        map[string]any{"algorithm": "ed25519", "key_id": "atlas-key-e2e", "value": "c2lnbmF0dXJl"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func recordApprovalEvidence(t *testing.T, client *http.Client, gatewayURL string) approvalTransmissionView {
	t.Helper()
	resp := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/approvals/evidence", e2eEvidenceBody(t, e2eParamHash), map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evidence status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	assertNoStore(t, resp)
	var view approvalTransmissionView
	decodeJSON(t, resp, &view)
	return view
}

func openMigratedPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTNEXUS_E2E_POSTGRES_DSN is required for the real-PostgreSQL acceptance suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, cleanup, err := openIsolatedPostgres(ctx, dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	applyMigrations(t, pool)
	return pool
}

func openIsolatedPostgres(ctx context.Context, dsn string, configure func(*pgxpool.Config) error) (*pgxpool.Pool, func(), error) {
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	schema := fmt.Sprintf("agentnexus_e2e_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		return nil, nil, err
	}
	var pool *pgxpool.Pool
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if pool != nil {
				pool.Close()
			}
			cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			_, _ = admin.Exec(cleanupCtx, `DROP SCHEMA IF EXISTS `+pgx.Identifier{schema}.Sanitize()+` CASCADE`)
			admin.Close()
		})
	}
	fail := func(err error) (*pgxpool.Pool, func(), error) {
		cleanup()
		return nil, nil, err
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fail(err)
	}
	if configure != nil {
		if err := configure(config); err != nil {
			return fail(err)
		}
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fail(err)
	}
	if err = pool.Ping(ctx); err != nil {
		return fail(err)
	}
	return pool, cleanup, nil
}

func TestOpenIsolatedPostgresCleansSchemaOnPostCreateSetupFailure(t *testing.T) {
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTNEXUS_E2E_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := countE2ESchemas(t, ctx, dsn)
	sentinel := errors.New("injected post-create setup failure")
	pool, cleanup, err := openIsolatedPostgres(ctx, dsn, func(*pgxpool.Config) error { return sentinel })
	if pool != nil || cleanup != nil || !errors.Is(err, sentinel) {
		t.Fatalf("pool=%v cleanup=%v err=%v", pool, cleanup != nil, err)
	}
	after := countE2ESchemas(t, ctx, dsn)
	if after != before {
		t.Fatalf("isolated schemas leaked after setup failure: before=%d after=%d", before, after)
	}
}

func countE2ESchemas(t *testing.T, ctx context.Context, dsn string) int {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM pg_namespace WHERE nspname LIKE 'agentnexus_e2e_%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
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
		{`INSERT INTO org_policy_snapshot_memberships(enterprise_id,version_number,enterprise_user_id,org_unit_id,role) VALUES ($1,1,$2,$3,'member'),($1,1,$2,$3,'publish_low_risk'),($1,1,$2,$3,'approve_high_risk'),($1,1,$2,$3,'service_mode'),($1,1,$4,$5,'manager'),($1,1,$4,$5,'approve_high_risk')`, []any{e2eEnterprise, e2eUser, e2eTeam, e2eReviewer, e2eRoot}},
		{`UPDATE org_versions SET policy_snapshot_sealed=true WHERE enterprise_id=$1 AND version_number=1`, []any{e2eEnterprise}},
		{`INSERT INTO case_tickets(id,enterprise_id,actor_user_id,request_id,status,expires_at,token_hash) VALUES ('ticket-e2e',$1,$2,'request-e2e','active',now()+interval '30 minutes',$3)`, []any{e2eEnterprise, e2eUser, ticketHash}},
		{`INSERT INTO sensitive_resource_ownerships(enterprise_id,resource_type,resource_id,org_version,org_unit_id) VALUES ($1,'dream_evidence','dream-evidence-1',1,$2)`, []any{e2eEnterprise, e2eTeam}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", statement.sql, err)
		}
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
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("serialized database mutation returned non-timeout error: %v", err)
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

func equalStrings(got, want []string) bool {
	if got == nil || len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func assertProductionLoginAttemptQuota(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	limits, err := browserauth.NewLoginAttemptLimits(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	service := browserauth.NewService(browserauth.NewPostgresStore(pool), browserauth.WithLoginAttemptLimits(limits))
	input := func(browser byte) browserauth.CreateLoginAttemptInput {
		return browserauth.CreateLoginAttemptInput{EnterpriseID: e2eEnterprise, ClientID: "agentatlas-quota", BrowserID: opaqueBrowserID(browser), RedirectURI: "https://atlas.example/auth/callback", ConsoleState: "state", ConsoleNonce: "nonce", CodeChallenge: s256(e2eVerifier)}
	}
	var success, limited, unexpected atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _, _, createErr := service.CreateLoginAttempt(ctx, input('a'))
			switch {
			case createErr == nil:
				success.Add(1)
			case errors.Is(createErr, browserauth.ErrLoginAttemptLimited):
				limited.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	wg.Wait()
	if pool.Stat().TotalConns() < 2 {
		t.Fatalf("production quota concurrency used fewer than two PostgreSQL connections: %d", pool.Stat().TotalConns())
	}
	if success.Load() != 2 || limited.Load() != 2 || unexpected.Load() != 0 {
		t.Fatalf("per-browser production quota success=%d limited=%d unexpected=%d", success.Load(), limited.Load(), unexpected.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, _, err := service.CreateLoginAttempt(ctx, input('b')); err != nil {
		t.Fatalf("independent browser within global quota: %v", err)
	}
	if _, _, _, err := service.CreateLoginAttempt(ctx, input('c')); !errors.Is(err, browserauth.ErrLoginAttemptLimited) {
		t.Fatalf("global production quota err=%v", err)
	}
	var attempts, scopeCount, browserCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM oidc_login_attempts WHERE enterprise_id=$1 AND client_id='agentatlas-quota'`, e2eEnterprise).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(SUM(active_count),0) FROM oidc_login_attempt_scope_counters WHERE enterprise_id=$1 AND client_id='agentatlas-quota'`, e2eEnterprise).Scan(&scopeCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(SUM(active_count),0) FROM oidc_login_attempt_browser_counters WHERE enterprise_id=$1 AND client_id='agentatlas-quota'`, e2eEnterprise).Scan(&browserCount); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || scopeCount != 3 || browserCount != 3 {
		t.Fatalf("production quota persistence attempts=%d scope=%d browser=%d", attempts, scopeCount, browserCount)
	}
}

func opaqueBrowserID(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
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

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func assertBrowserAccessTokenStorage(t *testing.T, pool *pgxpool.Pool, raw string) {
	t.Helper()
	digest := sha256.Sum256([]byte(raw))
	wantHash := hex.EncodeToString(digest[:])
	var tokenHash, clientID, audience, enterpriseID, userID string
	var expiresAt, absoluteExpiresAt time.Time
	err := pool.QueryRow(context.Background(), `SELECT t.token_hash,t.client_id,t.audience,t.enterprise_id,t.enterprise_user_id,t.expires_at,s.absolute_expires_at FROM browser_access_tokens t JOIN browser_sessions s ON s.id_hash=t.browser_session_id_hash WHERE t.token_hash=$1`, wantHash).Scan(&tokenHash, &clientID, &audience, &enterpriseID, &userID, &expiresAt, &absoluteExpiresAt)
	if err != nil || tokenHash != wantHash || clientID != "agentatlas" || audience != "agentatlas" || enterpriseID != e2eEnterprise || userID != e2eUser || !expiresAt.Equal(absoluteExpiresAt) {
		t.Fatalf("access token storage binding invalid hash=%s client=%s audience=%s enterprise=%s user=%s expiry_equal=%v err=%v", tokenHash, clientID, audience, enterpriseID, userID, expiresAt.Equal(absoluteExpiresAt), err)
	}
	var rawRows int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM browser_access_tokens WHERE token_hash=$1`, raw).Scan(&rawRows); err != nil || rawRows != 0 {
		t.Fatalf("raw access token persisted rows=%d err=%v", rawRows, err)
	}
}

func (t bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	if clone.Header.Get("Authorization") == "" {
		clone.Header.Set("Authorization", "Bearer "+t.token)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

func writeFakeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
