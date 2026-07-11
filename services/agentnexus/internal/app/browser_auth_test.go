package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
const testConsoleClientSecret = "AgentAtlas-console-secret-C7mQ4vN8xR2pT6yK9dF3"

func tokenBasicHeader(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

func TestBrowserAuthAuthorizeBootstrapsCanonicalBrowserWithSingleQueryMarker(t *testing.T) {
	var counting *countingSessionService
	h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
		counting = &countingSessionService{BrowserSessionService: service}
		return counting
	})
	target := "/oauth2/authorize?" + h.authorizeQuery("console-state", "console-nonce").Encode() + "&prompt=select%20account"
	bootstrapTarget := target + "&nexus_bootstrap=1"

	first := performOnce(h.router, http.MethodGet, target, "", nil)
	if first.Code != http.StatusFound || first.Header().Get("Location") != bootstrapTarget {
		t.Fatalf("bootstrap status=%d location=%q", first.Code, first.Header().Get("Location"))
	}
	if first.Header().Get("Cache-Control") != "no-store" || counting.createAttempts != 0 {
		t.Fatalf("cache=%q attempts=%d", first.Header().Get("Cache-Control"), counting.createAttempts)
	}
	browserCookie := namedCookie(t, first, "nexus_oidc_browser")
	if !browserCookie.HttpOnly || !browserCookie.Secure || browserCookie.SameSite != http.SameSiteLaxMode || browserCookie.Path != "/oauth2/authorize" || browserCookie.MaxAge != 24*60*60 || browserCookie.Expires.IsZero() || !canonicalOpaque(browserCookie.Value) {
		t.Fatalf("browser cookie=%+v", browserCookie)
	}

	second := performOnce(h.router, http.MethodGet, bootstrapTarget, "", []*http.Cookie{browserCookie})
	location, _ := url.Parse(second.Header().Get("Location"))
	if second.Code != http.StatusFound || location.Scheme+"://"+location.Host != h.idp.server.URL || counting.createAttempts != 1 {
		t.Fatalf("second status=%d location=%s attempts=%d", second.Code, location, counting.createAttempts)
	}
	if counting.lastAttempt.RedirectURI != "https://atlas.example.com/auth/callback" || counting.lastAttempt.ConsoleState != "console-state" || counting.lastAttempt.ConsoleNonce != "console-nonce" {
		t.Fatalf("bootstrap marker polluted login attempt: %+v", counting.lastAttempt)
	}
}

func TestBrowserAuthAuthorizeStopsWhenBootstrapCookieIsRejected(t *testing.T) {
	var counting *countingSessionService
	h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
		counting = &countingSessionService{BrowserSessionService: service}
		return counting
	})
	target := "/oauth2/authorize?" + h.authorizeQuery("s", "n").Encode() + "&nexus_bootstrap=1"
	rr := performOnce(h.router, http.MethodGet, target, "", []*http.Cookie{{Name: "nexus_oidc_browser", Value: "not-canonical"}})
	if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" || counting.createAttempts != 0 || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d location=%q attempts=%d headers=%v", rr.Code, rr.Header().Get("Location"), counting.createAttempts, rr.Header())
	}
	if !strings.Contains(rr.Body.String(), `"error":"browser_cookie_required"`) {
		t.Fatalf("body=%s", rr.Body.String())
	}
	cleared := namedCookie(t, rr, oidcBrowserCookie)
	if cleared.MaxAge >= 0 || cleared.Path != "/oauth2/authorize" {
		t.Fatalf("browser cookie not cleared: %+v", cleared)
	}
}

func TestBrowserAuthAuthorizeRejectsInvalidBootstrapMarkerBeforeLimiter(t *testing.T) {
	cases := map[string][]string{
		"empty":     {""},
		"unknown":   {"2"},
		"duplicate": {"1", "1"},
	}
	for name, marker := range cases {
		t.Run(name, func(t *testing.T) {
			limiter := &stubAuthorizeRateLimiter{}
			var counting *countingSessionService
			h := newBrowserHarnessWithRateLimit(t, limiter, NewAuthorizeSourceResolver(nil), func(service *browserauth.Service) BrowserSessionService {
				counting = &countingSessionService{BrowserSessionService: service}
				return counting
			})
			query := h.authorizeQuery("s", "n")
			query["nexus_bootstrap"] = marker
			rr := performOnce(h.router, http.MethodGet, "/oauth2/authorize?"+query.Encode(), "", nil)
			if rr.Code != http.StatusBadRequest || limiter.calls != 0 || counting.createAttempts != 0 || rr.Header().Get("Location") != "" || len(rr.Result().Cookies()) != 0 {
				t.Fatalf("status=%d limiter=%d attempts=%d location=%q cookies=%v", rr.Code, limiter.calls, counting.createAttempts, rr.Header().Get("Location"), rr.Result().Cookies())
			}
		})
	}
}

func TestBrowserAuthAuthorizeCountsEachValidBootstrapRequestBeforeSideEffects(t *testing.T) {
	limiter := &stubAuthorizeRateLimiter{}
	var counting *countingSessionService
	h := newBrowserHarnessWithRateLimit(t, limiter, NewAuthorizeSourceResolver(nil), func(service *browserauth.Service) BrowserSessionService {
		counting = &countingSessionService{BrowserSessionService: service}
		return counting
	})
	target := "/oauth2/authorize?" + h.authorizeQuery("s", "n").Encode()
	first := performOnce(h.router, http.MethodGet, target, "", nil)
	if first.Code != http.StatusFound || limiter.calls != 1 || counting.createAttempts != 0 {
		t.Fatalf("first status=%d limiter=%d attempts=%d", first.Code, limiter.calls, counting.createAttempts)
	}
	second := performOnce(h.router, http.MethodGet, first.Header().Get("Location"), "", nil)
	if second.Code != http.StatusBadRequest || limiter.calls != 2 || counting.createAttempts != 0 {
		t.Fatalf("second status=%d limiter=%d attempts=%d", second.Code, limiter.calls, counting.createAttempts)
	}
}

func TestBrowserAuthAuthorizeUsesEnterpriseIdPOrSilentSession(t *testing.T) {
	h := newBrowserHarness(t)
	query := h.authorizeQuery("console-state", "console-nonce")
	rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+query.Encode(), "", nil)
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("authorize cache=%v", rr.Header())
	}
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

func TestBrowserAuthCallbackRequiresSameBrowserBindingAndClearsTemporaryCookie(t *testing.T) {
	h := newBrowserHarness(t)
	start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
	location, _ := url.Parse(start.Header().Get("Location"))
	state := location.Query().Get("state")
	h.idp.setNonce(location.Query().Get("nonce"))
	binding := loginBindingCookie(t, start)
	if binding.Path != "/oauth2/idp/callback" || !binding.HttpOnly || !binding.Secure || binding.SameSite != http.SameSiteLaxMode || binding.Expires.IsZero() {
		t.Fatalf("binding=%+v", binding)
	}
	fresh := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(state), "", nil)
	if fresh.Code != http.StatusUnauthorized {
		t.Fatalf("fresh browser=%d", fresh.Code)
	}
	cleared := loginBindingCookie(t, fresh)
	if cleared.MaxAge >= 0 || cleared.Path != "/oauth2/idp/callback" {
		t.Fatalf("fresh clear=%+v", cleared)
	}
	valid := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(state), "", binding)
	if valid.Code != http.StatusFound {
		t.Fatalf("valid=%d body=%s", valid.Code, valid.Body.String())
	}
	if clear := loginBindingCookie(t, valid); clear.MaxAge >= 0 {
		t.Fatalf("success did not clear: %+v", clear)
	}
}

func TestBrowserAuthLoginBindingCookiesSupportMultipleTabs(t *testing.T) {
	h := newBrowserHarness(t)
	first := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s1", "n1").Encode(), "", nil)
	second := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s2", "n2").Encode(), "", nil)
	firstLocation, _ := url.Parse(first.Header().Get("Location"))
	firstCookie := loginBindingCookie(t, first)
	secondCookie := loginBindingCookie(t, second)
	if firstCookie.Name == secondCookie.Name {
		t.Fatalf("tabs share cookie %q", firstCookie.Name)
	}
	h.idp.setNonce(firstLocation.Query().Get("nonce"))
	wrong := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(firstLocation.Query().Get("state")), "", secondCookie)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tab=%d", wrong.Code)
	}
	h.idp.setNonce(firstLocation.Query().Get("nonce"))
	correct := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(firstLocation.Query().Get("state")), "", firstCookie)
	if correct.Code != http.StatusFound {
		t.Fatalf("first tab=%d", correct.Code)
	}
}

func TestBrowserAuthAuthorizeRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	h := newBrowserHarness(t)
	base := h.authorizeQuery("s", "n")
	cases := map[string]func(url.Values){
		"open redirect":      func(v url.Values) { v.Set("redirect_uri", "https://evil.example/cb") },
		"duplicate state":    func(v url.Values) { v.Add("state", "other") },
		"plain challenge":    func(v url.Values) { v.Set("code_challenge_method", "plain") },
		"missing nonce":      func(v url.Values) { v.Del("nonce") },
		"wrong response":     func(v url.Values) { v.Set("response_type", "token") },
		"missing openid":     func(v url.Values) { v.Set("scope", "profile") },
		"empty response":     func(v url.Values) { v.Set("response_type", "") },
		"empty scope":        func(v url.Values) { v.Set("scope", "") },
		"missing response":   func(v url.Values) { v.Del("response_type") },
		"missing scope":      func(v url.Values) { v.Del("scope") },
		"duplicate response": func(v url.Values) { v.Add("response_type", "code") },
		"duplicate scope":    func(v url.Values) { v.Add("scope", "openid") },
		"oversized state":    func(v url.Values) { v.Set("state", strings.Repeat("s", maxAuthorizeStateLength+1)) },
		"oversized nonce":    func(v url.Values) { v.Set("nonce", strings.Repeat("n", maxAuthorizeNonceLength+1)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := cloneValues(base)
			mutate(v)
			rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+v.Encode(), "", nil)
			if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
				t.Fatalf("status=%d location=%q", rr.Code, rr.Header().Get("Location"))
			}
			for _, cookie := range rr.Result().Cookies() {
				if cookie.Name == oidcBrowserCookie {
					t.Fatalf("invalid request bootstrapped browser cookie: %+v", cookie)
				}
			}
		})
	}
}

func TestBrowserAuthTokenRequiresConfidentialBasicBeforeCodeConsumption(t *testing.T) {
	var counting *countingSessionService
	h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
		counting = &countingSessionService{BrowserSessionService: service}
		return counting
	})
	code := issueSilentCode(t, h)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
	cases := map[string][]string{
		"missing":   nil,
		"wrong":     {"Basic " + base64.StdEncoding.EncodeToString([]byte("agentatlas:wrong-secret"))},
		"duplicate": {tokenBasicHeader("agentatlas", testConsoleClientSecret), tokenBasicHeader("agentatlas", testConsoleClientSecret)},
		"malformed": {"Basic !!!"},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, value := range values {
				req.Header.Add("Authorization", value)
			}
			rr := httptest.NewRecorder()
			h.router.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized || responseError(t, rr) != "invalid_client" || rr.Header().Get("WWW-Authenticate") != `Basic realm="AgentNexus token"` {
				t.Fatalf("status=%d headers=%v body=%s", rr.Code, rr.Header(), rr.Body.String())
			}
		})
	}
	if counting.exchangeCodes != 0 {
		t.Fatalf("invalid confidential authentication consumed code %d times", counting.exchangeCodes)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", tokenBasicHeader("agentatlas", testConsoleClientSecret))
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || counting.exchangeCodes != 1 {
		t.Fatalf("status=%d exchanges=%d body=%s", rr.Code, counting.exchangeCodes, rr.Body.String())
	}
}

func TestConfidentialBasicAndAuthorizeRejectNonCanonicalClientIDsBeforeSideEffects(t *testing.T) {
	invalid := []string{"bad:client", "bad%client", "bad+client", " bad", "客户端", strings.Repeat("a", 257)}
	for _, clientID := range invalid {
		if !strings.Contains(clientID, ":") {
			header := http.Header{"Authorization": {tokenBasicHeader(clientID, testConsoleClientSecret)}}
			if _, _, ok := confidentialBasicCredentials(header); ok {
				t.Fatalf("Basic parser accepted unsafe client id %q", clientID)
			}
		}
		limiter := &stubAuthorizeRateLimiter{}
		var counting *countingSessionService
		h := newBrowserHarnessWithRateLimit(t, limiter, NewAuthorizeSourceResolver(nil), func(service *browserauth.Service) BrowserSessionService {
			counting = &countingSessionService{BrowserSessionService: service}
			return counting
		})
		query := h.authorizeQuery("state", "nonce")
		query.Set("client_id", clientID)
		rr := performOnce(h.router, http.MethodGet, "/oauth2/authorize?"+query.Encode(), "", nil)
		if rr.Code != http.StatusBadRequest || limiter.calls != 0 || counting.createAttempts != 0 || len(rr.Result().Cookies()) != 0 {
			t.Fatalf("client=%q status=%d limiter=%d attempts=%d cookies=%v", clientID, rr.Code, limiter.calls, counting.createAttempts, rr.Result().Cookies())
		}
	}
}

func TestBrowserAuthCallbackTokenMeAndLogout(t *testing.T) {
	h := newBrowserHarness(t)
	idpRedirect := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("state-1", "nonce-1").Encode(), "", nil)
	upstream, _ := url.Parse(idpRedirect.Header().Get("Location"))
	h.idp.setNonce(upstream.Query().Get("nonce"))
	callback := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(upstream.Query().Get("state")), "", loginBindingCookie(t, idpRedirect))
	if callback.Code != http.StatusFound {
		t.Fatalf("callback=%d body=%s", callback.Code, callback.Body.String())
	}
	location, _ := url.Parse(callback.Header().Get("Location"))
	if location.Query().Get("state") != "state-1" || location.Query().Get("code") == "" {
		t.Fatalf("location=%s", location)
	}
	cookies := callback.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies=%v", cookies)
	}
	var cookie *http.Cookie
	for _, candidate := range cookies {
		if candidate.Name == browserSessionCookie {
			cookie = candidate
		}
	}
	if cookie == nil {
		t.Fatalf("session cookie missing: %v", cookies)
	}
	if cookie.Name != browserSessionCookie || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Value == "" {
		t.Fatalf("cookie=%+v", cookie)
	}
	if strings.Contains(callback.Body.String(), cookie.Value) {
		t.Fatal("raw session leaked in response")
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
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
	for _, code := range []string{"exchange-fail", "bad-signature", "bad-audience", "expired", "bad-issuer", "bad-nonce", "unknown", "single-bad-azp", "multi-no-azp", "multi-bad-azp"} {
		t.Run(code, func(t *testing.T) {
			h := newBrowserHarness(t)
			start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
			location, _ := url.Parse(start.Header().Get("Location"))
			h.idp.setNonce(location.Query().Get("nonce"))
			rr := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code="+code+"&state="+url.QueryEscape(location.Query().Get("state")), "", loginBindingCookie(t, start))
			if rr.Code == http.StatusFound || hasSessionCookie(rr) || loginBindingCookie(t, rr).MaxAge >= 0 {
				t.Fatalf("status=%d cookies=%v", rr.Code, rr.Result().Cookies())
			}
		})
	}
}

func TestBrowserAuthCallbackClassifiesIdentityDirectoryErrorsWithoutLeakingCredentials(t *testing.T) {
	tests := []struct {
		name       string
		resolveErr error
		wantStatus int
	}{
		{name: "unknown identity", resolveErr: ErrUnknownExternalIdentity, wantStatus: http.StatusUnauthorized},
		{name: "directory unavailable", resolveErr: ErrIdentityDirectoryUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "unclassified resolver failure", resolveErr: errors.New("resolver failed without classification"), wantStatus: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newBrowserHarnessRuntimeWithIdentities(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService { return service }, nil, func(upstream UpstreamOIDC) UpstreamOIDC { return upstream }, failingIdentities{err: test.resolveErr}, 0, nil, nil)
			start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("state-identity", "nonce-identity").Encode(), "", nil)
			location, _ := url.Parse(start.Header().Get("Location"))
			h.idp.setNonce(location.Query().Get("nonce"))
			target := "/oauth2/idp/callback?code=good&state=" + url.QueryEscape(location.Query().Get("state"))
			callback := perform(h.router, http.MethodGet, target, "", loginBindingCookie(t, start))
			if callback.Code != test.wantStatus || callback.Header().Get("Location") != "" || hasSessionCookie(callback) || strings.Contains(callback.Body.String(), "code") {
				t.Fatalf("callback status=%d headers=%v cookies=%v body=%q", callback.Code, callback.Header(), callback.Result().Cookies(), callback.Body.String())
			}
			replay := perform(h.router, http.MethodGet, target, "", loginBindingCookie(t, start))
			if replay.Code != http.StatusUnauthorized || replay.Header().Get("Location") != "" || hasSessionCookie(replay) {
				t.Fatalf("replay status=%d headers=%v cookies=%v body=%q", replay.Code, replay.Header(), replay.Result().Cookies(), replay.Body.String())
			}
		})
	}
}

func TestBrowserAuthCallbackAcceptsMultipleAudiencesWithMatchingAuthorizedParty(t *testing.T) {
	h := newBrowserHarness(t)
	start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
	location, _ := url.Parse(start.Header().Get("Location"))
	h.idp.setNonce(location.Query().Get("nonce"))
	rr := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=multi-good&state="+url.QueryEscape(location.Query().Get("state")), "", loginBindingCookie(t, start))
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBrowserAuthCallbackBoundsUpstreamExchangeAndJWKSContext(t *testing.T) {
	var checking *deadlineOIDC
	h := newBrowserHarnessRuntime(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService { return service }, nil, func(upstream UpstreamOIDC) UpstreamOIDC {
		checking = &deadlineOIDC{UpstreamOIDC: upstream}
		return checking
	}, 0)
	start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
	location, _ := url.Parse(start.Header().Get("Location"))
	h.idp.setNonce(location.Query().Get("nonce"))
	rr := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(location.Query().Get("state")), "", loginBindingCookie(t, start))
	if rr.Code != http.StatusFound || !checking.sawDeadline {
		t.Fatalf("status=%d deadline=%v", rr.Code, checking.sawDeadline)
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
	if logout.Code != http.StatusServiceUnavailable || len(logout.Result().Cookies()) != 0 {
		t.Fatalf("logout=%d cookies=%v", logout.Code, logout.Result().Cookies())
	}
	if _, err := h.sessions.GetSession(context.Background(), raw); err != nil {
		t.Fatalf("audit failure revoked session before atomic commit: %v", err)
	}
}

func TestBrowserAuthDiscoveryAdvertisesAllRotatedAlgorithms(t *testing.T) {
	h := newBrowserHarnessConfigured(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService { return service }, staticTokenIssuer{algorithms: []string{"RS256", "ES384", "EdDSA"}})
	rr := perform(h.router, http.MethodGet, "/.well-known/openid-configuration", "", nil)
	for _, alg := range []string{"RS256", "ES384", "EdDSA"} {
		if !strings.Contains(rr.Body.String(), alg) {
			t.Fatalf("discovery missing %s: %s", alg, rr.Body.String())
		}
	}
}

func TestBrowserAuthTokenSigningFailureIsTemporarilyUnavailable(t *testing.T) {
	h := newBrowserHarnessConfigured(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService { return service }, staticTokenIssuer{signErr: errors.New("signer unavailable"), algorithms: []string{"RS256"}})
	code := issueSilentCode(t, h)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
	rr := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded")
	if rr.Code != http.StatusServiceUnavailable || responseError(t, rr) != "temporarily_unavailable" {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBrowserAuthLogoutStoreUnavailablePreservesSessionAndReturns503(t *testing.T) {
	var failing *failingSessionService
	h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
		failing = &failingSessionService{Service: service, logoutErrs: []error{browserauth.ErrSessionUnavailable}}
		return failing
	})
	raw, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	rr := perform(h.router, http.MethodPost, "/v1/browser-sessions/logout", "", &http.Cookie{Name: browserSessionCookie, Value: raw})
	if rr.Code != http.StatusServiceUnavailable || len(rr.Result().Cookies()) != 0 || len(failing.logoutDeadlines) != 1 || !failing.logoutDeadlines[0] {
		t.Fatalf("status=%d cookies=%v deadlines=%v", rr.Code, rr.Result().Cookies(), failing.logoutDeadlines)
	}
	if _, err := h.sessions.GetSession(context.Background(), raw); err != nil {
		t.Fatalf("store failure destroyed session: %v", err)
	}
}

func TestBrowserAuthRoutesDistinguishStoreUnavailableFromInvalidCredentials(t *testing.T) {
	t.Run("authorize", func(t *testing.T) {
		h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
			return &failingSessionService{Service: service, getErr: browserauth.ErrSessionUnavailable}
		})
		raw, _, _ := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
		rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", &http.Cookie{Name: browserSessionCookie, Value: raw})
		if rr.Code != http.StatusServiceUnavailable || hasClearedCookie(rr, browserSessionCookie) {
			t.Fatalf("status=%d cookies=%v", rr.Code, rr.Result().Cookies())
		}
	})
	t.Run("me", func(t *testing.T) {
		h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
			return &failingSessionService{Service: service, getErr: browserauth.ErrSessionUnavailable}
		})
		rr := perform(h.router, http.MethodGet, "/v1/browser-sessions/me", "", &http.Cookie{Name: browserSessionCookie, Value: secretValueForTest()})
		if rr.Code != http.StatusServiceUnavailable || hasClearedCookie(rr, browserSessionCookie) {
			t.Fatalf("status=%d cookies=%v", rr.Code, rr.Result().Cookies())
		}
	})
	t.Run("token", func(t *testing.T) {
		h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
			return &failingSessionService{Service: service, exchangeErr: browserauth.ErrGrantUnavailable}
		})
		form := url.Values{"grant_type": {"authorization_code"}, "code": {secretValueForTest()}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
		rr := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded")
		if rr.Code != http.StatusServiceUnavailable || responseError(t, rr) != "temporarily_unavailable" {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
	t.Run("callback", func(t *testing.T) {
		h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
			return &failingSessionService{Service: service, consumeErr: browserauth.ErrLoginAttemptUnavailable}
		})
		start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
		location, _ := url.Parse(start.Header().Get("Location"))
		rr := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(location.Query().Get("state")), "", loginBindingCookie(t, start))
		if rr.Code != http.StatusServiceUnavailable || hasSessionCookie(rr) {
			t.Fatalf("status=%d cookies=%v", rr.Code, rr.Result().Cookies())
		}
	})
}

func TestBrowserAuthAuthorizeReturns429ForLoginAttemptLimit(t *testing.T) {
	h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
		return &failingSessionService{Service: service, createAttemptErr: browserauth.ErrLoginAttemptLimited}
	})
	rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") != "300" {
		t.Fatalf("Retry-After=%q", rr.Header().Get("Retry-After"))
	}
	if rr.Header().Get("Location") != "" {
		t.Fatalf("unexpected IdP redirect: %q", rr.Header().Get("Location"))
	}
	for _, cookie := range rr.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "nexus_oidc_binding_") && cookie.Value != "" {
			t.Fatalf("binding cookie set: %+v", cookie)
		}
	}
}

func TestBrowserAuthAuthorizeLimitsOneBrowserWithoutBlockingAnother(t *testing.T) {
	h := newBrowserHarness(t)
	browserA := &http.Cookie{Name: oidcBrowserCookie, Value: secretValueForTest()}
	browserB := &http.Cookie{Name: oidcBrowserCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("y", 32)))}
	for i := range 8 {
		rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery(fmt.Sprintf("state-%d", i), fmt.Sprintf("nonce-%d", i)).Encode(), "", browserA)
		location, _ := url.Parse(rr.Header().Get("Location"))
		if rr.Code != http.StatusFound || location.Host == "" || location.Path != "/authorize" {
			t.Fatalf("attempt %d status=%d location=%s", i, rr.Code, location)
		}
	}
	limited := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("state-9", "nonce-9").Encode(), "", browserA)
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "300" || limited.Header().Get("Location") != "" {
		t.Fatalf("limited status=%d retry=%q location=%q", limited.Code, limited.Header().Get("Retry-After"), limited.Header().Get("Location"))
	}
	other := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("other-state", "other-nonce").Encode(), "", browserB)
	location, _ := url.Parse(other.Header().Get("Location"))
	if other.Code != http.StatusFound || location.Path != "/authorize" {
		t.Fatalf("other status=%d location=%s", other.Code, location)
	}
}

func TestBrowserAuthRequestDeadlineReachesBlockingDependencies(t *testing.T) {
	const timeout = 30 * time.Millisecond
	t.Run("authorize", func(t *testing.T) {
		var blocking *blockingSessionService
		h := newBrowserHarnessRuntime(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
			blocking = &blockingSessionService{Service: service, blockGet: true, done: make(chan struct{})}
			return blocking
		}, nil, func(upstream UpstreamOIDC) UpstreamOIDC { return upstream }, timeout)
		started := time.Now()
		rr := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", &http.Cookie{Name: browserSessionCookie, Value: secretValueForTest()})
		assertDeadlineResponse(t, rr, started, blocking.done)
	})
	t.Run("token", func(t *testing.T) {
		var blocking *blockingSessionService
		h := newBrowserHarnessRuntime(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
			blocking = &blockingSessionService{Service: service, blockExchange: true, done: make(chan struct{})}
			return blocking
		}, nil, func(upstream UpstreamOIDC) UpstreamOIDC { return upstream }, timeout)
		form := url.Values{"grant_type": {"authorization_code"}, "code": {secretValueForTest()}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
		started := time.Now()
		rr := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded")
		assertDeadlineResponse(t, rr, started, blocking.done)
		if responseError(t, rr) != "temporarily_unavailable" {
			t.Fatalf("body=%s", rr.Body.String())
		}
	})
	t.Run("callback", func(t *testing.T) {
		var blocking *blockingSessionService
		h := newBrowserHarnessRuntime(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
			blocking = &blockingSessionService{Service: service, done: make(chan struct{})}
			return blocking
		}, nil, func(upstream UpstreamOIDC) UpstreamOIDC { return upstream }, timeout)
		start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
		location, _ := url.Parse(start.Header().Get("Location"))
		blocking.blockConsume = true
		started := time.Now()
		rr := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(location.Query().Get("state")), "", loginBindingCookie(t, start))
		assertDeadlineResponse(t, rr, started, blocking.done)
	})
	t.Run("me-profile", func(t *testing.T) {
		profile := &blockingProfile{done: make(chan struct{})}
		h := newBrowserHarnessRuntime(t, profile, func(service *browserauth.Service) BrowserSessionService { return service }, nil, func(upstream UpstreamOIDC) UpstreamOIDC { return upstream }, timeout)
		raw, _, _ := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
		started := time.Now()
		rr := perform(h.router, http.MethodGet, "/v1/browser-sessions/me", "", &http.Cookie{Name: browserSessionCookie, Value: raw})
		assertDeadlineResponse(t, rr, started, profile.done)
	})
}

func TestBrowserAuthCallbackAuditFailureRetriesAtomicSessionCleanupWithoutLeaks(t *testing.T) {
	tests := map[string][]error{
		"transient unavailable then success": {browserauth.ErrSessionUnavailable, nil},
		"persistent unavailable":             {browserauth.ErrSessionUnavailable, browserauth.ErrSessionUnavailable},
	}
	for name, logoutErrs := range tests {
		t.Run(name, func(t *testing.T) {
			var failing *failingSessionService
			h := newBrowserHarnessWithOptions(t, testProfiles{}, func(service *browserauth.Service) BrowserSessionService {
				failing = &failingSessionService{Service: service, logoutErrs: logoutErrs}
				return failing
			})
			start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
			location, _ := url.Parse(start.Header().Get("Location"))
			h.idp.setNonce(location.Query().Get("nonce"))
			h.audit.err = errors.New("audit unavailable")
			rr := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(location.Query().Get("state")), "", loginBindingCookie(t, start))
			if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Location") != "" || hasSessionCookie(rr) || strings.Contains(rr.Body.String(), "code") {
				t.Fatalf("status=%d headers=%v cookies=%v body=%q", rr.Code, rr.Header(), rr.Result().Cookies(), rr.Body.String())
			}
			if failing.logoutCalls != 2 || len(failing.logoutDeadlines) != 2 || !failing.logoutDeadlines[0] || !failing.logoutDeadlines[1] {
				t.Fatalf("logout calls=%d deadlines=%v", failing.logoutCalls, failing.logoutDeadlines)
			}
			if failing.revokeCalls != 0 {
				t.Fatalf("RevokeSession calls=%d", failing.revokeCalls)
			}
		})
	}
}

func TestBrowserAuthTokenRejectsWrongBindingReuseAmbiguityAndOversize(t *testing.T) {
	cases := map[string]func(*browserHarness, url.Values) (string, string){
		"wrong verifier": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("code_verifier", strings.Repeat("w", 43))
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"body client id forbidden": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("client_id", "other")
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"wrong redirect": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("redirect_uri", "https://evil.example/cb")
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"oversized body client forbidden": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("client_id", strings.Repeat("c", 257))
			return "application/x-www-form-urlencoded", v.Encode()
		},
		"oversized redirect": func(_ *browserHarness, v url.Values) (string, string) {
			v.Set("redirect_uri", strings.Repeat("r", 2049))
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
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
			contentType, body := mutate(h, form)
			rr := perform(h.router, http.MethodPost, "/oauth2/token", body, nil, "Content-Type", contentType)
			wantError := "invalid_grant"
			if name == "duplicate code" || name == "wrong content type" || name == "oversize" || strings.Contains(name, "forbidden") || strings.HasPrefix(name, "oversized ") {
				wantError = "invalid_request"
			}
			if rr.Code < 400 || rr.Header().Get("Cache-Control") != "no-store" || responseError(t, rr) != wantError {
				t.Fatalf("status=%d headers=%v", rr.Code, rr.Header())
			}
		})
	}
	h := newBrowserHarness(t)
	code := issueSilentCode(t, h)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
	if got := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded").Code; got != http.StatusOK {
		t.Fatalf("first=%d", got)
	}
	if rr := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded"); rr.Code != http.StatusBadRequest || responseError(t, rr) != "invalid_grant" {
		t.Fatalf("reuse=%d body=%s", rr.Code, rr.Body.String())
	}
	badGrant := cloneValues(form)
	badGrant.Set("grant_type", "client_credentials")
	if rr := perform(h.router, http.MethodPost, "/oauth2/token", badGrant.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded"); responseError(t, rr) != "unsupported_grant_type" {
		t.Fatalf("grant=%s", rr.Body.String())
	}
	if rr := perform(h.router, http.MethodGet, "/oauth2/token", "", nil); rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("method=%d headers=%v", rr.Code, rr.Header())
	}
}

func TestBrowserAuthRejectsCrossEnterpriseSessionsAndCodes(t *testing.T) {
	h := newBrowserHarness(t)
	raw, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-2", UserID: "user-2"})
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: browserSessionCookie, Value: raw}
	authorize := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", cookie)
	location, _ := url.Parse(authorize.Header().Get("Location"))
	if location.Host == "atlas.example.com" || location.Path != "/authorize" {
		t.Fatalf("cross tenant silent=%s", location)
	}
	if !hasClearedCookie(authorize, browserSessionCookie) {
		t.Fatalf("session not cleared: %v", authorize.Result().Cookies())
	}
	me := perform(h.router, http.MethodGet, "/v1/browser-sessions/me", "", cookie)
	if me.Code != http.StatusUnauthorized || !hasClearedCookie(me, browserSessionCookie) {
		t.Fatalf("me=%d cookies=%v", me.Code, me.Result().Cookies())
	}
	code, err := h.sessions.IssueCode(context.Background(), browserauth.IssueCodeInput{EnterpriseID: "ent-2", UserID: "user-2", ClientID: "agentatlas", RedirectURI: "https://atlas.example.com/auth/callback", Nonce: "n", CodeChallenge: testS256(testVerifier)})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {testVerifier}, "redirect_uri": {"https://atlas.example.com/auth/callback"}}
	token := perform(h.router, http.MethodPost, "/oauth2/token", form.Encode(), nil, "Content-Type", "application/x-www-form-urlencoded")
	if token.Code != http.StatusBadRequest || responseError(t, token) != "invalid_grant" {
		t.Fatalf("token=%d %s", token.Code, token.Body.String())
	}
}

func TestBrowserAuthCallbackBoundsCodeAndAlwaysClearsBindingCookie(t *testing.T) {
	h := newBrowserHarness(t)
	start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
	location, _ := url.Parse(start.Header().Get("Location"))
	binding := loginBindingCookie(t, start)
	tooLong := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code="+strings.Repeat("c", maxUpstreamCodeLength+1)+"&state="+url.QueryEscape(location.Query().Get("state")), "", binding)
	if tooLong.Code != http.StatusBadRequest || loginBindingCookie(t, tooLong).MaxAge >= 0 {
		t.Fatalf("long code=%d cookies=%v", tooLong.Code, tooLong.Result().Cookies())
	}
	h.idp.setNonce(location.Query().Get("nonce"))
	valid := perform(h.router, http.MethodGet, "/oauth2/idp/callback?code=good&state="+url.QueryEscape(location.Query().Get("state")), "", binding)
	if valid.Code != http.StatusFound {
		t.Fatalf("attempt consumed by invalid code: %d", valid.Code)
	}
}

func TestBrowserAuthCallbackConsumesStateBeforeAuditAndNeverSetsCookieOnAuditFailure(t *testing.T) {
	h := newBrowserHarness(t)
	start := perform(h.router, http.MethodGet, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "", nil)
	location, _ := url.Parse(start.Header().Get("Location"))
	h.idp.setNonce(location.Query().Get("nonce"))
	h.audit.err = fmt.Errorf("audit unavailable")
	target := "/oauth2/idp/callback?code=good&state=" + url.QueryEscape(location.Query().Get("state"))
	first := perform(h.router, http.MethodGet, target, "", loginBindingCookie(t, start))
	if first.Code != http.StatusServiceUnavailable || hasSessionCookie(first) || loginBindingCookie(t, first).MaxAge >= 0 {
		t.Fatalf("first=%d cookies=%v", first.Code, first.Result().Cookies())
	}
	if !h.audit.sawDeadline {
		t.Fatal("callback audit context is unbounded")
	}
	h.audit.err = nil
	second := perform(h.router, http.MethodGet, target, "", loginBindingCookie(t, start))
	if second.Code != http.StatusUnauthorized || hasSessionCookie(second) || loginBindingCookie(t, second).MaxAge >= 0 {
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
	return newBrowserHarnessWithOptions(t, profiles, func(service *browserauth.Service) BrowserSessionService { return service })
}

func newBrowserHarnessWithOptions(t *testing.T, profiles BrowserProfileResolver, wrap func(*browserauth.Service) BrowserSessionService) *browserHarness {
	return newBrowserHarnessConfigured(t, profiles, wrap, nil)
}

func newBrowserHarnessConfigured(t *testing.T, profiles BrowserProfileResolver, wrap func(*browserauth.Service) BrowserSessionService, issuer IDTokenIssuer) *browserHarness {
	return newBrowserHarnessRuntime(t, profiles, wrap, issuer, func(upstream UpstreamOIDC) UpstreamOIDC { return upstream }, 0)
}

func newBrowserHarnessRuntime(t *testing.T, profiles BrowserProfileResolver, wrap func(*browserauth.Service) BrowserSessionService, issuer IDTokenIssuer, upstreamWrap func(UpstreamOIDC) UpstreamOIDC, requestTimeout time.Duration) *browserHarness {
	return newBrowserHarnessRuntimeWithIdentities(t, profiles, wrap, issuer, upstreamWrap, testIdentities{}, requestTimeout, nil, nil)
}

func newBrowserHarnessWithRateLimit(t *testing.T, limiter browserauth.AuthorizeRateLimiter, sourceResolver AuthorizeSourceResolver, wrap func(*browserauth.Service) BrowserSessionService) *browserHarness {
	return newBrowserHarnessRuntimeWithIdentities(t, testProfiles{}, wrap, nil, func(upstream UpstreamOIDC) UpstreamOIDC { return upstream }, testIdentities{}, 0, limiter, sourceResolver)
}

func newBrowserHarnessRuntimeWithIdentities(t *testing.T, profiles BrowserProfileResolver, wrap func(*browserauth.Service) BrowserSessionService, issuer IDTokenIssuer, upstreamWrap func(UpstreamOIDC) UpstreamOIDC, identities ExternalIdentityResolver, requestTimeout time.Duration, limiter browserauth.AuthorizeRateLimiter, sourceResolver AuthorizeSourceResolver) *browserHarness {
	t.Helper()
	idp := newFakeIDP(t)
	downstreamKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := browserauth.NewConsoleClientCredentials(map[string][]string{"agentatlas": {testConsoleClientSecret}})
	if err != nil {
		t.Fatal(err)
	}
	config := browserauth.OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: idp.server.URL, PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus-client", UpstreamClientSecret: "Upstream-IDP-secret-N8xQ3vK7pT4yR9dF2", CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"agentatlas": {"https://atlas.example.com/auth/callback"}}, ConsoleCredentials: credentials, SigningKeyID: "key-current", SigningPrivateKey: downstreamKey}
	ctx := oidc.ClientContext(context.Background(), idp.server.Client())
	upstream, err := browserauth.NewEnterpriseOIDC(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	store := browserauth.NewMemoryStore()
	store.AddEnterpriseUser("ent-1", "user-1")
	store.AddEnterpriseUser("ent-2", "user-2")
	sessions := browserauth.NewService(store)
	audit := &memoryAudit{}
	wrappedSessions := wrap(sessions)
	audit.sessions = wrappedSessions
	if limiter == nil {
		limiter, err = browserauth.NewMemoryAuthorizeRateLimiter(browserauth.DefaultAuthorizeRateLimitPerMinute, time.Now)
		if err != nil {
			t.Fatal(err)
		}
	}
	if sourceResolver == nil {
		sourceResolver = NewAuthorizeSourceResolver(nil)
	}
	router, err := NewGatewayAPIRouterWithDependencies("gateway-api", "test", BrowserAuthDependencies{Config: config, Sessions: wrappedSessions, Upstream: upstreamWrap(upstream), Identities: identities, Profiles: profiles, Audit: audit, TokenIssuer: issuer, RequestTimeout: requestTimeout, AuthorizeRateLimiter: limiter, AuthorizeSourceResolver: sourceResolver, AuthorizationPolicy: authorizationPolicySource(), TicketActors: RejectTicketActorAuthenticator{}})
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

type failingIdentities struct{ err error }

func (f failingIdentities) ResolveExternalIdentity(context.Context, string, string, string) (string, string, error) {
	return "", "", f.err
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
	mu          sync.Mutex
	events      []BrowserAuditEvent
	err         error
	sawDeadline bool
	sessions    BrowserSessionService
}

func (m *memoryAudit) LogoutBrowserSession(ctx context.Context, token string, event BrowserAuditEvent) (browserauth.BrowserSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, m.sawDeadline = ctx.Deadline()
	if m.err != nil {
		return browserauth.BrowserSession{}, m.err
	}
	session, err := m.sessions.LogoutSession(ctx, token)
	if err != nil {
		return browserauth.BrowserSession{}, err
	}
	event.ActorUserID = session.UserID
	m.events = append(m.events, event)
	return session, nil
}

type failingSessionService struct {
	*browserauth.Service
	logoutErrs                                        []error
	logoutCalls, revokeCalls                          int
	logoutDeadlines                                   []bool
	revokeErr                                         error
	revokeDeadline                                    bool
	getErr, exchangeErr, consumeErr, createAttemptErr error
}
type countingSessionService struct {
	BrowserSessionService
	createAttempts int
	getSessions    int
	exchangeCodes  int
	lastAttempt    browserauth.CreateLoginAttemptInput
}

func (s *countingSessionService) ExchangeCode(ctx context.Context, input browserauth.ExchangeCodeInput) (browserauth.ExchangeResult, error) {
	s.exchangeCodes++
	return s.BrowserSessionService.ExchangeCode(ctx, input)
}

func (s *countingSessionService) GetSession(ctx context.Context, token string) (browserauth.BrowserSession, error) {
	s.getSessions++
	return s.BrowserSessionService.GetSession(ctx, token)
}

func (s *countingSessionService) CreateLoginAttempt(ctx context.Context, input browserauth.CreateLoginAttemptInput) (string, string, browserauth.LoginAttempt, error) {
	s.createAttempts++
	s.lastAttempt = input
	return s.BrowserSessionService.CreateLoginAttempt(ctx, input)
}

type blockingSessionService struct {
	*browserauth.Service
	blockGet, blockExchange, blockConsume bool
	done                                  chan struct{}
	once                                  sync.Once
}

func (s *blockingSessionService) finish() { s.once.Do(func() { close(s.done) }) }
func (s *blockingSessionService) GetSession(ctx context.Context, token string) (browserauth.BrowserSession, error) {
	if s.blockGet {
		<-ctx.Done()
		s.finish()
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	return s.Service.GetSession(ctx, token)
}
func (s *blockingSessionService) ExchangeCode(ctx context.Context, input browserauth.ExchangeCodeInput) (browserauth.ExchangeResult, error) {
	if s.blockExchange {
		<-ctx.Done()
		s.finish()
		return browserauth.ExchangeResult{}, browserauth.ErrGrantUnavailable
	}
	return s.Service.ExchangeCode(ctx, input)
}
func (s *blockingSessionService) ConsumeLoginAttempt(ctx context.Context, state, binding string) (browserauth.LoginAttempt, error) {
	if s.blockConsume {
		<-ctx.Done()
		s.finish()
		return browserauth.LoginAttempt{}, browserauth.ErrLoginAttemptUnavailable
	}
	return s.Service.ConsumeLoginAttempt(ctx, state, binding)
}

type blockingProfile struct {
	done chan struct{}
	once sync.Once
}

func (p *blockingProfile) ResolveBrowserProfile(ctx context.Context, _, _ string) (BrowserProfile, error) {
	<-ctx.Done()
	p.once.Do(func() { close(p.done) })
	return BrowserProfile{}, ctx.Err()
}

type staticTokenIssuer struct {
	signErr    error
	algorithms []string
}
type deadlineOIDC struct {
	UpstreamOIDC
	sawDeadline bool
}

func (d *deadlineOIDC) ExchangeAndVerify(ctx context.Context, code string) (browserauth.VerifiedIdentity, string, error) {
	_, d.sawDeadline = ctx.Deadline()
	return d.UpstreamOIDC.ExchangeAndVerify(ctx, code)
}

func (s staticTokenIssuer) SignIDToken(browserauth.IDTokenInput) (string, time.Duration, error) {
	if s.signErr != nil {
		return "", 0, s.signErr
	}
	return "token", 5 * time.Minute, nil
}
func (s staticTokenIssuer) JWKS() ([]byte, error) { return []byte(`{"keys":[]}`), nil }
func (s staticTokenIssuer) Algorithms() []string  { return append([]string(nil), s.algorithms...) }

func (s *failingSessionService) LogoutSession(ctx context.Context, token string) (browserauth.BrowserSession, error) {
	_, hasDeadline := ctx.Deadline()
	s.logoutDeadlines = append(s.logoutDeadlines, hasDeadline)
	call := s.logoutCalls
	s.logoutCalls++
	if call < len(s.logoutErrs) && s.logoutErrs[call] != nil {
		return browserauth.BrowserSession{}, s.logoutErrs[call]
	}
	return s.Service.LogoutSession(ctx, token)
}
func (s *failingSessionService) GetSession(ctx context.Context, token string) (browserauth.BrowserSession, error) {
	if s.getErr != nil {
		return browserauth.BrowserSession{}, s.getErr
	}
	return s.Service.GetSession(ctx, token)
}
func (s *failingSessionService) ExchangeCode(ctx context.Context, input browserauth.ExchangeCodeInput) (browserauth.ExchangeResult, error) {
	if s.exchangeErr != nil {
		return browserauth.ExchangeResult{}, s.exchangeErr
	}
	return s.Service.ExchangeCode(ctx, input)
}
func (s *failingSessionService) ConsumeLoginAttempt(ctx context.Context, state, binding string) (browserauth.LoginAttempt, error) {
	if s.consumeErr != nil {
		return browserauth.LoginAttempt{}, s.consumeErr
	}
	return s.Service.ConsumeLoginAttempt(ctx, state, binding)
}
func (s *failingSessionService) CreateLoginAttempt(ctx context.Context, input browserauth.CreateLoginAttemptInput) (string, string, browserauth.LoginAttempt, error) {
	if s.createAttemptErr != nil {
		return "", "", browserauth.LoginAttempt{}, s.createAttemptErr
	}
	return s.Service.CreateLoginAttempt(ctx, input)
}
func (s *failingSessionService) RevokeSession(ctx context.Context, token string) error {
	s.revokeCalls++
	_, s.revokeDeadline = ctx.Deadline()
	if s.revokeErr != nil {
		return s.revokeErr
	}
	return s.Service.RevokeSession(ctx, token)
}

func (a *memoryAudit) AppendBrowserAudit(ctx context.Context, event BrowserAuditEvent) error {
	_, a.sawDeadline = ctx.Deadline()
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
		issuer, audience, subject, expiry, signingKey := f.server.URL, jwt.Audience{"nexus-client"}, "external-user", time.Now().Add(5*time.Minute), f.key
		azp := ""
		switch code {
		case "bad-signature":
			signingKey = f.badKey
		case "bad-audience":
			audience = jwt.Audience{"other"}
		case "expired":
			expiry = time.Now().Add(-time.Minute)
		case "bad-issuer":
			issuer = "https://other.example"
		case "bad-nonce":
			nonce = "wrong"
		case "unknown":
			subject = "missing-user"
		case "single-bad-azp":
			azp = "other"
		case "multi-no-azp":
			audience = jwt.Audience{"nexus-client", "other"}
		case "multi-bad-azp":
			audience = jwt.Audience{"nexus-client", "other"}
			azp = "other"
		case "multi-good":
			audience = jwt.Audience{"nexus-client", "other"}
			azp = "nexus-client"
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "idp"))
		claims := struct {
			jwt.Claims
			Nonce           string `json:"nonce"`
			AuthorizedParty string `json:"azp,omitempty"`
		}{Claims: jwt.Claims{Issuer: issuer, Subject: subject, Audience: audience, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(expiry)}, Nonce: nonce, AuthorizedParty: azp}
		raw, _ := jwt.Signed(signer).Claims(claims).Serialize()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "upstream-only", "token_type": "Bearer", "expires_in": 300, "id_token": raw})
	default:
		http.NotFound(w, r)
	}
}

func perform(handler http.Handler, method, target, body string, cookie *http.Cookie, headers ...string) *httptest.ResponseRecorder {
	cookies := []*http.Cookie{}
	if cookie != nil {
		cookies = append(cookies, cookie)
	}
	rr := performOnce(handler, method, target, body, cookies, headers...)
	if method == http.MethodGet && strings.HasPrefix(target, "/oauth2/authorize?") && rr.Code == http.StatusFound && rr.Header().Get("Location") == target+"&nexus_bootstrap=1" {
		for _, candidate := range rr.Result().Cookies() {
			if candidate.Name == oidcBrowserCookie && canonicalOpaque(candidate.Value) {
				cookies = append(cookies, candidate)
				return performOnce(handler, method, rr.Header().Get("Location"), body, cookies, headers...)
			}
		}
	}
	return rr
}

func performOnce(handler http.Handler, method, target, body string, cookies []*http.Cookie, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if method == http.MethodPost && target == "/oauth2/token" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", tokenBasicHeader("agentatlas", testConsoleClientSecret))
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
func loginBindingCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rr.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "nexus_oidc_binding_") {
			return cookie
		}
	}
	t.Fatalf("binding cookie missing: %v", rr.Header())
	return nil
}
func namedCookie(t *testing.T, rr *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q missing: %v", name, rr.Header())
	return nil
}
func hasSessionCookie(rr *httptest.ResponseRecorder) bool {
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == browserSessionCookie && cookie.Value != "" {
			return true
		}
	}
	return false
}
func hasClearedCookie(rr *httptest.ResponseRecorder, name string) bool {
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == name && cookie.Value == "" && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}
func responseError(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	value, _ := payload["error"].(string)
	return value
}
func secretValueForTest() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
}
func assertDeadlineResponse(t *testing.T, rr *httptest.ResponseRecorder, started time.Time, done <-chan struct{}) {
	t.Helper()
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatalf("deadline response took %s", time.Since(started))
	}
	select {
	case <-done:
	default:
		t.Fatal("dependency goroutine still blocked")
	}
}
