package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testVerifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"

func TestBrowserAuthAuthorizeUsesEnterpriseIdPOrSilentSession(t *testing.T) {
	h := newBrowserHarness(t)
	query := h.authorizeQuery("console-state", "console-nonce")
	rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+query.Encode(), "", nil)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	location, _ := url.Parse(rr.Header().Get("Location"))
	if location.Scheme+"://"+location.Host != h.idp.server.URL || location.Path != "/authorize" {
		t.Fatalf("location=%s", location)
	}
	if location.Query().Get("state") == "console-state" || location.Query().Get("state") == "" || location.Query().Get("nonce") == "" {
		t.Fatalf("unsafe upstream query=%s", location.RawQuery)
	}
	if location.Query().Get("redirect_uri") != h.config.CallbackURL {
		t.Fatalf("callback=%q", location.Query().Get("redirect_uri"))
	}

	token, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1", UserAgent: "ua"})
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: browserSessionCookie, Value: token}
	rr = perform(h.router, http.MethodGet, "/oauth2/authorize?"+query.Encode(), "", cookie)
	if rr.Code != http.StatusFound {
		t.Fatalf("silent status=%d body=%s", rr.Code, rr.Body.String())
	}
	location, _ = url.Parse(rr.Header().Get("Location"))
	if location.String() == "" || location.Scheme != "https" || location.Host != "atlas.example.com" || location.Query().Get("code") == "" || location.Query().Get("state") != "console-state" {
		t.Fatalf("silent location=%s", location)
	}
}

func TestBrowserAuthAuthorizeRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	h := newBrowserHarness(t)
	base := h.authorizeQuery("s", "n")
	cases := map[string]func(url.Values){
		"open redirect":   func(v url.Values) { v.Set("redirect_uri", "https://evil.example/cb") },
		"duplicate state": func(v url.Values) { v.Add("state", "other") },
		"plain challenge": func(v url.Values) { v.Set("code_challenge_method", "plain") },
		"missing nonce":   func(v url.Values) { v.Del("nonce") },
		"wrong response":  func(v url.Values) { v.Set("response_type", "token") },
		"missing openid":  func(v url.Values) { v.Set("scope", "profile") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := cloneValues(base)
			mutate(v)
			rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+v.Encode(), "", nil)
			if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
				t.Fatalf("status=%d location=%q", rr.Code, rr.Header().Get("Location"))
			}
		})
	}
}

func TestBrowserAuthCallbackTokenMeAndLogout(t *testing.T) {
	h := newBrowserHarness(t)
	idpRedirect := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("state-1", "nonce-1").Encode(), "", nil)
	upstream, _ := url.Parse(idpRedirect.Header().Get("Location"))
	h.idp.setNonce(upstream.Query().Get("nonce"))
	callback := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(upstream.Query().Get("state")), "", nil)
	if callback.Code != http.StatusFound {
		t.Fatalf("callback=%d body=%s", callback.Code, callback.Body.String())
	}
	location, _ := url.Parse(callback.Header().Get("Location"))
	if location.Query().Get("state") != "state-1" || location.Query().Get("code") == "" {
		t.Fatalf("location=%s", location)
	}
	cookies := callback.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != browserSessionCookie || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Value == "" {
		t.Fatalf("cookie=%+v", cookie)
	}
	if strings.Contains(callback.Body.String(), cookie.Value) {
		t.Fatal("raw session leaked in response")
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "code_verifier": {testVerifier}, "client_id": {"agentatlas"}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
	token := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded")
	if token.Code != http.StatusOK {
		t.Fatalf("token=%d body=%s", token.Code, token.Body.String())
	}
	if token.Header().Get("Cache-Control") != "no-store" || token.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers=%v", token.Header())
	}
	var payload map[string]any
	if err := json.Unmarshal(token.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["id_token"] == "" || payload["token_type"] != "Bearer" || payload["access_token"] != nil || payload["refresh_token"] != nil {
		t.Fatalf("payload=%v", payload)
	}

	me := perform(h.router, http.MethodGet, "/v1/browser-sessions/me", "", cookie)
	if me.Code != http.StatusOK {
		t.Fatalf("me=%d body=%s", me.Code, me.Body.String())
	}
	if me.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("me cache=%q", me.Header().Get("Cache-Control"))
	}
	var profile struct {
		Authenticated bool     `json:"authenticated"`
		EnterpriseID  string   `json:"enterprise_id"`
		OrgVersion    int64    `json:"org_version"`
		OrgUnitIDs    []string `json:"org_unit_ids"`
		Permissions   []string `json:"permissions"`
	}
	if err := json.Unmarshal(me.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if !profile.Authenticated || profile.EnterpriseID != "ent-1" || profile.OrgVersion != 7 || profile.OrgUnitIDs == nil || profile.Permissions == nil {
		t.Fatalf("profile=%+v", profile)
	}

	logout := perform(h.router, http.MethodPost, "/v1/browser-sessions/logout", "", cookie)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout=%d", logout.Code)
	}
	cleared := logout.Result().Cookies()[0]
	if cleared.Name != browserSessionCookie || cleared.MaxAge >= 0 || !cleared.HttpOnly || !cleared.Secure || cleared.SameSite != http.SameSiteLaxMode || cleared.Path != "/" {
		t.Fatalf("cleared=%+v", cleared)
	}
	if got := perform(h.router, http.MethodGet, "/v1/browser-sessions/me", "", cookie).Code; got != http.StatusUnauthorized {
		t.Fatalf("post logout=%d", got)
	}
}

func TestBrowserAuthCallbackFailuresNeverSetSessionCookie(t *testing.T) {
	for _, code := range []string{"exchange-fail", "bad-signature", "bad-audience", "expired", "bad-issuer", "bad-nonce", "unknown"} {
		t.Run(code, func(t *testing.T) {
			h := newBrowserHarness(t)
			start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
			location, _ := url.Parse(start.Header().Get("Location"))
			h.idp.setNonce(location.Query().Get("nonce"))
			rr := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code="+code+"&state="+url.QueryEscape(location.Query().Get("state")), "", nil)
			if rr.Code == http.StatusFound || len(rr.Result().Cookies()) != 0 {
				t.Fatalf("status=%d cookies=%v", rr.Code, rr.Result().Cookies())
			}
		})
	}
}

func TestBrowserAuthDiscoveryIgnoresHostAndLogoutAuditFailureFailsClosed(t *testing.T) {
	h := newBrowserHarness(t)
	req := httptest.NewRequest(http.MethodGet, "https://attacker.invalid/.well-known/openid-configuration", nil)
	req.Host = "attacker.invalid"
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "attacker.invalid") || !strings.Contains(rr.Body.String(), h.config.PublicIssuerURL) {
		t.Fatalf("discovery=%d %s", rr.Code, rr.Body.String())
	}

	raw, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	h.audit.err = fmt.Errorf("audit unavailable")
	cookie := &http.Cookie{Name: browserSessionCookie, Value: raw}
	logout := perform(h.router, http.MethodPost, "/v1/browser-sessions/logout", "", cookie)
	if logout.Code != http.StatusServiceUnavailable || len(logout.Result().Cookies()) == 0 {
		t.Fatalf("logout=%d cookies=%v", logout.Code, logout.Result().Cookies())
	}
	if _, err := h.sessions.GetSession(context.Background(), raw); err == nil {
		t.Fatal("session survived failed audit")
	}
}

func TestBrowserAuthTokenRejectsWrongBindingReuseAmbiguityAndOversize(t *testing.T) {
	cases := map[string]func(*browserHarness, url.Values) (string, string){
		"wrong verifier": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("code_verifier", strings.Repeat("w", 43))
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"wrong client": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("client_id", "other")
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"wrong redirect": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("redirect_uri", "https://evil.example/cb")
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"duplicate code": func(_ *browserHarness, v url.Values) (string, string) {
			v.Add("code", "other")
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"wrong content type": func(_ *browserHarness, v url.Values) (string, string) { return "application/json", v.Encode() },
		"oversize": func(_ *browserHarness, v url.Values) (string, string) {
			return "application/x-www-form-urlencoded", strings.Repeat("x", maxTokenRequestBytes+1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newBrowserHarness(t)
			code := issueSilentCode(t, h)
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier}, "client_id": {"agentatlas"}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
			contentType, body := mutate(h, form)
			rr := perform(h.router, http.MethodPost, "/oauth2/token", body, nil, "Content-Type", contentType)
			if rr.Code < 400 || rr.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d headers=%v", rr.Code, rr.Header())
			}
		})
	}
	h := newBrowserHarness(t)
	code := issueSilentCode(t, h)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier}, "client_id": {"agentatlas"}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
	if got := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded").Code; got != http.StatusOK {
		t.Fatalf("first=%d", got)
	}
	if got := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded").Code; got != http.StatusBadRequest {
		t.Fatalf("reuse=%d", got)
	}
	if got := perform(h.router, http.MethodGet, "/oauth2/token", "", nil).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("method=%d", got)
	}
}

func TestBrowserAuthCallbackConsumesStateBeforeAuditAndNeverSetsCookieOnAuditFailure(t *testing.T) {
	h := newBrowserHarness(t)
	start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
	location, _ := url.Parse(start.Header().Get("Location"))
	h.idp.setNonce(location.Query().Get("nonce"))
	h.audit.err = fmt.Errorf("audit unavailable")
	target := "/oauth2/idp/callback?code=good&state=" + url.QueryEscape(location.Query().Get("state"))
	first := perform(h.router, http.MethodGet, target, "", nil)
	if first.Code != http.StatusServiceUnavailable || len(first.Result().Cookies()) != 0 {
		t.Fatalf("first=%d cookies=%v", first.Code, first.Result().Cookies())
	}
	h.audit.err = nil
	second := perform(h.router, http.MethodGet, target, "", nil)
	if second.Code != http.StatusUnauthorized || len(second.Result().Cookies()) != 0 {
		t.Fatalf("replay=%d cookies=%v", second.Code, second.Result().Cookies())
	}
}

func TestBrowserAuthMeFailsClosedWhenProfileUnavailable(t *testing.T) {
	h := newBrowserHarnessWithProfiles(t, failingProfiles{})
	raw, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	rr := perform(h.router, http.MethodGet, "/v1/browser-sessions/me", "", &http.Cookie{Name: browserSessionCookie, Value: raw})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", rr.Code)
	}
}

type browserHarness struct {
	router   http.Handler
	sessions *browserauth.Service
	config   browserauth.OIDCConfig
	idp      *fakeIDP
	audit    *memoryAudit
}

func newBrowserHarness(t *testing.T) *browserHarness {
	return newBrowserHarnessWithProfiles(t, testProfiles{})
}

func newBrowserHarnessWithProfiles(t *testing.T, profiles BrowserProfileResolver) *browserHarness {
	t.Helper()
	idp := newFakeIDP(t)
	downstreamKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config := browserauth.OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: idp.server.URL, PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus-client", ClientSecret: "nexus-secret", CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"agentatlas": {"https://atlas.example.com/auth/callback"}}, SigningKeyID: "key-current", SigningPrivateKey: downstreamKey}
	ctx := oidc.ClientContext(context.Background(), idp.server.Client())
	upstream, err := browserauth.NewEnterpriseOIDC(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	store := browserauth.NewMemoryStore()
	store.AddEnterpriseUser("ent-1", "user-1")
	sessions := browserauth.NewService(store)
	audit := &memoryAudit{}
	router, err := NewGatewayAPIRouterWithDependencies("gateway-api", "test", BrowserAuthDependencies{Config: config, Sessions: sessions, Upstream: upstream, Identities: testIdentities{}, Profiles: profiles, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	return &browserHarness{router: router, sessions: sessions, config: config, idp: idp, audit: audit}
}

func (h *browserHarness) authorizeQuery(state, nonce string) url.Values {
	return url.Values{"client_id": {"agentatlas"}, "redirect_uri": {"https://atlas.example.com/auth/callback"}, "state": {state}, "nonce": {nonce}, "code_challenge": {testS256(testVerifier)}, "code_challenge_method": {"S256"}, "response_type": {"code"}, "scope": {"openid"}}
}

type testIdentities struct{}

func (testIdentities) ResolveExternalIdentity(_ context.Context, enterpriseID, issuer, subject string) (string, string, error) {
	if enterpriseID != "ent-1" {
		return "", "", fmt.Errorf("wrong enterprise")
	}
	if subject != "external-user" {
		return "", "", fmt.Errorf("unknown identity")
	}
	return "ent-1", "user-1", nil
}

type testProfiles struct{}

func (testProfiles) ResolveBrowserProfile(_ context.Context, enterpriseID, userID string) (BrowserProfile, error) {
	return BrowserProfile{EnterpriseID: enterpriseID, EnterpriseUserID: userID, DisplayName: "User One", OrgVersion: 7, OrgUnitIDs: []string{"dept-1"}, Permissions: []string{}}, nil
}

type failingProfiles struct{}

func (failingProfiles) ResolveBrowserProfile(context.Context, string, string) (BrowserProfile, error) {
	return BrowserProfile{}, fmt.Errorf("profile unavailable")
}

type memoryAudit struct {
	mu     sync.Mutex
	events []BrowserAuditEvent
	err    error
}

func (a *memoryAudit) AppendBrowserAudit(_ context.Context, event BrowserAuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, event)
	return nil
}

type fakeIDP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	badKey *rsa.PrivateKey
	mu     sync.Mutex
	nonce  string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	f := &fakeIDP{t: t}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.badKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}
func (f *fakeIDP) setNonce(n string) { f.mu.Lock(); f.nonce = n; f.mu.Unlock() }
func (f *fakeIDP) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, http.StatusOK, map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/jwks":
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "idp", Algorithm: "RS256", Use: "sig"}}})
	case "/token":
		_ = r.ParseForm()
		code := r.Form.Get("code")
		if code == "exchange-fail" {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		nonce := f.nonce
		f.mu.Unlock()
		issuer, audience, subject, expiry, signingKey := f.server.URL, "nexus-client", "external-user", time.Now().Add(5*time.Minute), f.key
		switch code {
		case "bad-signature":
			signingKey = f.badKey
		case "bad-audience":
			audience = "other"
		case "expired":
			expiry = time.Now().Add(-time.Minute)
		case "bad-issuer":
			issuer = "https://other.example"
		case "bad-nonce":
			nonce = "wrong"
		case "unknown":
			subject = "missing-user"
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "idp"))
		claims := struct {
			jwt.Claims
			Nonce string `json:"nonce"`
		}{Claims: jwt.Claims{Issuer: issuer, Subject: subject, Audience: jwt.Audience{audience}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(expiry)}, Nonce: nonce}
		raw, _ := jwt.Signed(signer).Claims(claims).Serialize()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "upstream-only", "token_type": "Bearer", "expires_in": 300, "id_token": raw})
	default:
		http.NotFound(w, r)
	}
}

func perform(handler http.Handler, method, target, body string, cookie *http.Cookie, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}
func cloneValues(in url.Values) url.Values {
	out := url.Values{}
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}
func issueSilentCode(t *testing.T, h *browserHarness) string {
	t.Helper()
	raw, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", &http.Cookie{Name: browserSessionCookie, Value: raw})
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize=%d", rr.Code)
	}
	location, _ := url.Parse(rr.Header().Get("Location"))
	return location.Query().Get("code")
}
func testS256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
