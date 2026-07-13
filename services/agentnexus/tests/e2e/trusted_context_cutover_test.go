package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"golang.org/x/oauth2"
)

// TestTrustedContextCutover proves the credential-derived trusted-context
// cutover end-to-end against the real PostgreSQL gateway wiring: a verified
// browser session mints one immutable context at ingress, forged identity
// headers and legacy org-fact envelopes are rejected (and audited), the
// neutral capability decision is credential-derived, and an AstraClaw origin
// carries zero connector capability. Postgres-gated: skips without a DSN,
// mirroring TestBrowserSessionAndApproval.
func TestTrustedContextCutover(t *testing.T) {
	pool := openMigratedPostgres(t)
	idp := newFakeOIDCProvider(t)
	seedGatewayFixture(t, pool, idp.server.URL)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := app.NewHMACChangeFactsVerifier([]byte("agentnexus-e2e-approval-facts-secret-v1"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewUnstartedServer(nil)
	gatewayURL := "https://" + gateway.Listener.Addr().String()
	consoleRedirect := "http://127.0.0.1:43123/auth/callback"
	consoleSecret := "AgentAtlas-e2e-console-secret-N8xQ3vK7pT4yR9dF2"
	consoleCredentials, err := browserauth.NewConsoleClientCredentials(map[string][]string{"agentatlas": {consoleSecret}})
	if err != nil {
		t.Fatal(err)
	}
	oidcContext := context.WithValue(context.Background(), oauth2.HTTPClient, idp.server.Client())
	router, err := app.NewPostgresGatewayRouter(oidcContext, pool, app.PostgresGatewayConfig{
		ServiceName: "gateway-api", Version: "e2e-cutover",
		OIDC: browserauth.OIDCConfig{
			EnterpriseID: e2eEnterprise, EnterpriseIssuerURL: idp.server.URL,
			PublicIssuerURL: gatewayURL, ClientID: "enterprise-console", UpstreamClientSecret: "Upstream-e2e-IDP-secret-Q7mV2xK9pR4tY8dF3",
			CallbackURL: gatewayURL + "/oauth2/idp/callback", ConsoleClients: map[string][]string{"agentatlas": {consoleRedirect}},
			ConsoleCredentials: consoleCredentials,
			SigningKeyID:       "gateway-e2e", SigningPrivateKey: key, HTTPTimeout: 5 * time.Second,
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

	// A forged identity header is screened at ingress before any credential is
	// even resolved (unauthenticated request still rejected 400).
	forged := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/authorization/decisions",
		`{"request_id":"decision-forge","resource_type":"knowledge","resource_id":"knowledge-low","capability":"knowledge.suggest"}`,
		map[string]string{"Content-Type": "application/json", "X-Org-Version": "999"})
	if forged.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged X-Org-Version header status=%d body=%s", forged.StatusCode, readBody(t, forged))
	}
	forged.Body.Close()

	establishBrowserSession(t, client, idp, gatewayURL, consoleRedirect, consoleSecret)

	// Legacy org-fact envelope on a verified session is rejected: caller JSON
	// can never supply org_unit_id / org_version / action.
	legacy := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/authorization/decisions",
		`{"org_unit_id":"team_research","org_version":1,"resource_type":"knowledge","resource_id":"knowledge-low","action":"knowledge.suggest"}`,
		map[string]string{"Content-Type": "application/json"})
	if legacy.StatusCode != http.StatusBadRequest {
		t.Fatalf("legacy org-fact envelope status=%d body=%s", legacy.StatusCode, readBody(t, legacy))
	}
	legacy.Body.Close()

	// The credential-derived capability request is allowed; identity, scope and
	// sealed version all come from the verified session.
	decision := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/authorization/decisions",
		`{"request_id":"decision-ok","resource_type":"knowledge","resource_id":"knowledge-low","capability":"knowledge.suggest"}`,
		map[string]string{"Content-Type": "application/json"})
	if decision.StatusCode != http.StatusOK {
		t.Fatalf("credential decision status=%d body=%s", decision.StatusCode, readBody(t, decision))
	}
	var allow struct {
		Decision    string   `json:"decision"`
		Permissions []string `json:"permissions"`
		OrgUnitIDs  []string `json:"org_unit_ids"`
		OrgVersion  int64    `json:"org_version"`
	}
	decodeJSON(t, decision, &allow)
	if allow.Decision != "allow" || allow.OrgVersion != e2eOrgVersion || !equalStrings(allow.Permissions, []string{"suggest"}) || !equalStrings(allow.OrgUnitIDs, []string{e2eTeam}) {
		t.Fatalf("credential decision=%+v", allow)
	}

	// AstraClaw origin is trace metadata only: a connector capability request
	// is denied with zero connector capability even on a first-party session.
	astra := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/authorization/decisions",
		`{"request_id":"decision-connector","resource_type":"service","resource_id":"erp-1","capability":"connector.erp.read"}`,
		map[string]string{"Content-Type": "application/json", "X-Agent-Origin": "astraclaw"})
	if astra.StatusCode != http.StatusOK {
		t.Fatalf("astraclaw connector decision status=%d body=%s", astra.StatusCode, readBody(t, astra))
	}
	var connectorDecision struct {
		Decision  string `json:"decision"`
		RiskLevel string `json:"risk_level"`
	}
	decodeJSON(t, astra, &connectorDecision)
	if connectorDecision.Decision != "deny" || connectorDecision.RiskLevel != "high" {
		t.Fatalf("astraclaw connector must be a high-risk deny: %+v", connectorDecision)
	}

	// A step grant with caller-supplied org facts is rejected before the
	// service runs; the credential-derived form succeeds.
	forgedGrant := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/step-grants",
		`{"case_ticket_id":"ticket-e2e","org_unit_id":"team_research","org_version":1,"resource_type":"dream_evidence","resource_id":"dream-evidence-1","action":"read","ttl_seconds":300}`,
		map[string]string{"Content-Type": "application/json"})
	if forgedGrant.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged-org-fact grant status=%d body=%s", forgedGrant.StatusCode, readBody(t, forgedGrant))
	}
	forgedGrant.Body.Close()

	grant := mustRequest(t, client, http.MethodPost, gatewayURL+"/v1/step-grants",
		`{"case_ticket_id":"ticket-e2e","resource_type":"dream_evidence","resource_id":"dream-evidence-1","action":"read","ttl_seconds":300}`,
		map[string]string{"Content-Type": "application/json"})
	if grant.StatusCode != http.StatusCreated {
		t.Fatalf("credential grant status=%d body=%s", grant.StatusCode, readBody(t, grant))
	}
	var grantPayload struct {
		Token  string   `json:"token"`
		Scopes []string `json:"scopes"`
	}
	decodeJSON(t, grant, &grantPayload)
	if grantPayload.Token == "" || !equalStrings(grantPayload.Scopes, []string{"dream:evidence:read"}) {
		t.Fatalf("credential grant payload=%+v", grantPayload)
	}
}

// establishBrowserSession runs the full OIDC login so the client jar holds a
// verified browser session cookie, mirroring TestBrowserSessionAndApproval.
func establishBrowserSession(t *testing.T, client *http.Client, idp *fakeOIDCProvider, gatewayURL, consoleRedirect, consoleSecret string) {
	t.Helper()
	challenge := s256(e2eVerifier)
	authorize := gatewayURL + "/oauth2/authorize?" + authorizeQuery(consoleRedirect, "console-state-1", "console-nonce-1", challenge).Encode()
	bootstrap := mustRequest(t, client, http.MethodGet, authorize, "", nil)
	assertRedirect(t, bootstrap, gatewayURL)
	idpRedirect := mustRequest(t, client, http.MethodGet, resolveLocation(gatewayURL, bootstrap.Header.Get("Location")), "", nil)
	assertRedirect(t, idpRedirect, idp.server.URL)

	idpClient := idp.server.Client()
	idpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	upstreamCallback := mustRequest(t, idpClient, http.MethodGet, idpRedirect.Header.Get("Location"), "", nil)
	assertRedirect(t, upstreamCallback, gatewayURL)
	callback := mustRequest(t, client, http.MethodGet, upstreamCallback.Header.Get("Location"), "", nil)
	assertRedirect(t, callback, consoleRedirect)

	silentURL := gatewayURL + "/oauth2/authorize?" + authorizeQuery(consoleRedirect, "console-state-2", "console-nonce-2", challenge).Encode()
	silent := mustRequest(t, client, http.MethodGet, silentURL, "", nil)
	assertRedirect(t, silent, consoleRedirect)
	location, _ := url.Parse(silent.Header.Get("Location"))
	code := location.Query().Get("code")
	silent.Body.Close()
	if code == "" {
		t.Fatal("silent authorization returned no code")
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {e2eVerifier}, "redirect_uri": {consoleRedirect}}
	token := mustRequest(t, client, http.MethodPost, gatewayURL+"/oauth2/token", tokenForm.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("agentatlas:"+consoleSecret))})
	if token.StatusCode != http.StatusOK {
		t.Fatalf("token status=%d body=%s", token.StatusCode, readBody(t, token))
	}
	token.Body.Close()
}
