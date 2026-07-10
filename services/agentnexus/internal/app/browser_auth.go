package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
)

const browserSessionCookie = "nexus_browser_session"
const oidcBrowserCookie = "nexus_oidc_browser"
const oidcBootstrapQuery = "nexus_bootstrap"
const loginBindingCookiePrefix = "nexus_oidc_binding_"
const maxTokenRequestBytes = 16 << 10
const maxAuthorizeStateLength = 1024
const maxAuthorizeNonceLength = 512
const maxUpstreamCodeLength = 4096
const mandatoryCleanupTimeout = 5 * time.Second
const upstreamRequestTimeout = 15 * time.Second
const defaultBrowserRequestTimeout = 20 * time.Second
const loginAttemptRetryAfterSeconds = "300"
const oidcBrowserCookieTTL = 24 * time.Hour

type BrowserSessionService interface {
	GetSession(context.Context, string) (browserauth.BrowserSession, error)
	CreateSession(context.Context, browserauth.CreateSessionInput) (string, browserauth.BrowserSession, error)
	RevokeSession(context.Context, string) error
	LogoutSession(context.Context, string) (browserauth.BrowserSession, error)
	IssueCode(context.Context, browserauth.IssueCodeInput) (string, error)
	ExchangeCode(context.Context, browserauth.ExchangeCodeInput) (browserauth.ExchangeResult, error)
	CreateLoginAttempt(context.Context, browserauth.CreateLoginAttemptInput) (string, string, browserauth.LoginAttempt, error)
	ConsumeLoginAttempt(context.Context, string, string) (browserauth.LoginAttempt, error)
}
type IDTokenIssuer interface {
	SignIDToken(browserauth.IDTokenInput) (string, time.Duration, error)
	JWKS() ([]byte, error)
	Algorithms() []string
}

type UpstreamOIDC interface {
	AuthCodeURL(state, nonce string) string
	ExchangeAndVerify(context.Context, string) (browserauth.VerifiedIdentity, string, error)
}

var (
	ErrUnknownExternalIdentity      = errors.New("unknown external identity")
	ErrIdentityDirectoryUnavailable = errors.New("identity directory unavailable")
)

type ExternalIdentityResolver interface {
	ResolveExternalIdentity(context.Context, string, string, string) (enterpriseID, userID string, err error)
}

type BrowserProfile struct {
	EnterpriseID        string
	EnterpriseUserID    string
	DisplayName         string
	OrgVersion          int64
	OrgUnitIDs          []string
	Permissions         []string
	AdvancedModeAllowed bool
}

type BrowserProfileResolver interface {
	ResolveBrowserProfile(context.Context, string, string) (BrowserProfile, error)
}

type BrowserAuditEvent struct {
	EnterpriseID string
	ActorUserID  string
	Action       string
	Decision     string
}

type BrowserAuditSink interface {
	AppendBrowserAudit(context.Context, BrowserAuditEvent) error
}

type BrowserAuthDependencies struct {
	Config                  browserauth.OIDCConfig
	Sessions                BrowserSessionService
	Upstream                UpstreamOIDC
	Identities              ExternalIdentityResolver
	Profiles                BrowserProfileResolver
	Audit                   BrowserAuditSink
	TokenIssuer             IDTokenIssuer
	RequestTimeout          time.Duration
	AuthorizeRateLimiter    browserauth.AuthorizeRateLimiter
	AuthorizeSourceResolver AuthorizeSourceResolver
}

type browserAuthHandler struct {
	config                  browserauth.OIDCConfig
	sessions                BrowserSessionService
	upstream                UpstreamOIDC
	identities              ExternalIdentityResolver
	profiles                BrowserProfileResolver
	audit                   BrowserAuditSink
	issuer                  IDTokenIssuer
	authorizeRateLimiter    browserauth.AuthorizeRateLimiter
	authorizeSourceResolver AuthorizeSourceResolver
}

func newBrowserAuthHandler(deps BrowserAuthDependencies) (*browserAuthHandler, error) {
	if deps.Sessions == nil || deps.Upstream == nil || deps.Identities == nil || deps.Profiles == nil || deps.Audit == nil || deps.AuthorizeRateLimiter == nil || deps.AuthorizeSourceResolver == nil {
		return nil, errors.New("browser auth dependencies incomplete")
	}
	issuer := deps.TokenIssuer
	if issuer == nil {
		var err error
		issuer, err = browserauth.NewTokenIssuer(deps.Config, time.Now)
		if err != nil {
			return nil, err
		}
	}
	return &browserAuthHandler{config: deps.Config, sessions: deps.Sessions, upstream: deps.Upstream, identities: deps.Identities, profiles: deps.Profiles, audit: deps.Audit, issuer: issuer, authorizeRateLimiter: deps.AuthorizeRateLimiter, authorizeSourceResolver: deps.AuthorizeSourceResolver}, nil
}

func browserRequestTimeout(value time.Duration) (time.Duration, error) {
	if value == 0 {
		return defaultBrowserRequestTimeout, nil
	}
	if value < 0 || value > 2*time.Minute {
		return 0, errors.New("browser request timeout is out of range")
	}
	return value, nil
}

func (h *browserAuthHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /oauth2/jwks", h.jwks)
	mux.HandleFunc("GET /oauth2/authorize", h.authorize)
	mux.HandleFunc("GET /oauth2/idp/callback", h.callback)
	mux.HandleFunc("POST /oauth2/token", h.token)
	mux.HandleFunc("GET /v1/browser-sessions/me", h.me)
	mux.HandleFunc("POST /v1/browser-sessions/logout", h.logout)
}

func (h *browserAuthHandler) authorize(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	query := r.URL.Query()
	clientID, ok := requiredSingle(query, "client_id")
	if !ok || len(clientID) > 256 {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	redirectURI, ok := requiredSingle(query, "redirect_uri")
	if !ok || len(redirectURI) > 2048 || !h.config.AllowsRedirect(clientID, redirectURI) {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	state, ok := requiredSingle(query, "state")
	if !ok || len(state) > maxAuthorizeStateLength {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	nonce, ok := requiredSingle(query, "nonce")
	if !ok || len(nonce) > maxAuthorizeNonceLength {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	challenge, ok := requiredSingle(query, "code_challenge")
	if !ok {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	method, ok := requiredSingle(query, "code_challenge_method")
	if !ok || method != "S256" {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	if values, present := query["response_type"]; present && (len(values) != 1 || values[0] != "code") {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	if values, present := query["scope"]; present && (len(values) != 1 || values[0] == "" || !slices.Contains(strings.Fields(values[0]), "openid")) {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	if !validChallenge(challenge) {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	bootstrap := false
	if values, present := query[oidcBootstrapQuery]; present {
		if len(values) != 1 || values[0] != "1" {
			writeOAuthError(w, http.StatusBadRequest)
			return
		}
		bootstrap = true
	}
	sourceHash, err := h.authorizeSourceResolver.ResolveAuthorizeSource(r)
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	retryAfter, err := h.authorizeRateLimiter.AllowAuthorize(r.Context(), h.config.EnterpriseID, clientID, sourceHash)
	if err != nil {
		if errors.Is(err, browserauth.ErrAuthorizeRateLimited) {
			seconds := int64((retryAfter + time.Second - 1) / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			writeOAuthError(w, http.StatusTooManyRequests)
			return
		}
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	browserCookie, browserCookieErr := r.Cookie(oidcBrowserCookie)
	if browserCookieErr != nil || !canonicalOpaque(browserCookie.Value) {
		if bootstrap {
			clearOIDCBrowserCookie(w)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "browser_cookie_required"})
			return
		}
		browserID, err := newBrowserID()
		if err != nil {
			writeOAuthError(w, http.StatusServiceUnavailable)
			return
		}
		setOIDCBrowserCookie(w, browserID, time.Now().Add(oidcBrowserCookieTTL))
		http.Redirect(w, r, r.URL.RequestURI()+"&"+oidcBootstrapQuery+"=1", http.StatusFound)
		return
	}

	if cookie, err := r.Cookie(browserSessionCookie); err == nil {
		session, sessionErr := h.sessions.GetSession(r.Context(), cookie.Value)
		if sessionErr == nil && session.EnterpriseID == h.config.EnterpriseID {
			code, err := h.sessions.IssueCode(r.Context(), browserauth.IssueCodeInput{EnterpriseID: session.EnterpriseID, UserID: session.UserID, ClientID: clientID, RedirectURI: redirectURI, Nonce: nonce, CodeChallenge: challenge})
			if err != nil {
				writeOAuthError(w, http.StatusServiceUnavailable)
				return
			}
			redirectWithCode(w, r, redirectURI, code, state)
			return
		}
		if errors.Is(sessionErr, browserauth.ErrSessionUnavailable) {
			writeOAuthError(w, http.StatusServiceUnavailable)
			return
		}
		clearSessionCookie(w)
	}
	attemptState, binding, attempt, err := h.sessions.CreateLoginAttempt(r.Context(), browserauth.CreateLoginAttemptInput{EnterpriseID: h.config.EnterpriseID, ClientID: clientID, BrowserID: browserCookie.Value, RedirectURI: redirectURI, ConsoleState: state, ConsoleNonce: nonce, CodeChallenge: challenge})
	if err != nil {
		if errors.Is(err, browserauth.ErrLoginAttemptLimited) {
			w.Header().Set("Retry-After", loginAttemptRetryAfterSeconds)
			writeOAuthError(w, http.StatusTooManyRequests)
			return
		}
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	setLoginBindingCookie(w, attemptState, binding, attempt.ExpiresAt)
	http.Redirect(w, r, h.upstream.AuthCodeURL(attemptState, attempt.UpstreamNonce), http.StatusFound)
}

func (h *browserAuthHandler) callback(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	query := r.URL.Query()
	state, ok := requiredSingle(query, "state")
	if !ok || !canonicalOpaque(state) {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	bindingCookie, cookieErr := r.Cookie(loginBindingCookieName(state))
	clearLoginBindingCookie(w, state)
	if cookieErr != nil || !canonicalOpaque(bindingCookie.Value) {
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	code, ok := requiredSingle(query, "code")
	if !ok || len(code) > maxUpstreamCodeLength {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	attempt, err := h.sessions.ConsumeLoginAttempt(r.Context(), state, bindingCookie.Value)
	if err != nil {
		if errors.Is(err, browserauth.ErrLoginAttemptUnavailable) {
			writeOAuthError(w, http.StatusServiceUnavailable)
			return
		}
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	upstreamCtx, upstreamCancel := context.WithTimeout(r.Context(), upstreamRequestTimeout)
	defer upstreamCancel()
	identity, nonce, err := h.upstream.ExchangeAndVerify(upstreamCtx, code)
	if err != nil || !constantTimeEqual(nonce, attempt.UpstreamNonce) {
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	enterpriseID, userID, err := h.identities.ResolveExternalIdentity(r.Context(), attempt.EnterpriseID, identity.Issuer, identity.Subject)
	if err != nil && !errors.Is(err, ErrUnknownExternalIdentity) {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	if err != nil || enterpriseID != attempt.EnterpriseID || userID == "" {
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	sessionToken, session, err := h.sessions.CreateSession(r.Context(), browserauth.CreateSessionInput{EnterpriseID: enterpriseID, UserID: userID, UserAgent: r.UserAgent()})
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	fail := func(status int) {
		for attempt := 0; attempt < 2; attempt++ {
			cleanupCtx, cancel := boundedCleanupContext(r.Context())
			_, cleanupErr := h.sessions.LogoutSession(cleanupCtx, sessionToken)
			cancel()
			if !errors.Is(cleanupErr, browserauth.ErrSessionUnavailable) {
				break
			}
		}
		writeOAuthError(w, status)
	}
	downstreamCode, err := h.sessions.IssueCode(r.Context(), browserauth.IssueCodeInput{EnterpriseID: enterpriseID, UserID: userID, ClientID: attempt.ClientID, RedirectURI: attempt.RedirectURI, Nonce: attempt.ConsoleNonce, CodeChallenge: attempt.CodeChallenge})
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	auditCtx, auditCancel := boundedCleanupContext(r.Context())
	auditErr := h.audit.AppendBrowserAudit(auditCtx, BrowserAuditEvent{EnterpriseID: enterpriseID, ActorUserID: userID, Action: "browser_session.create", Decision: "allow"})
	auditCancel()
	if auditErr != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	setSessionCookie(w, sessionToken, session.AbsoluteExpiresAt)
	redirectWithCode(w, r, attempt.RedirectURI, downstreamCode, attempt.ConsoleState)
}

func (h *browserAuthHandler) token(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeTokenError(w, http.StatusUnsupportedMediaType, "invalid_request")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTokenRequestBytes+1))
	if err != nil || len(body) > maxTokenRequestBytes {
		writeTokenError(w, http.StatusRequestEntityTooLarge, "invalid_request")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	grant, ok := requiredSingle(form, "grant_type")
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if grant != "authorization_code" {
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	code, ok := requiredSingle(form, "code")
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	verifier, ok := requiredSingle(form, "code_verifier")
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, ok := requiredSingle(form, "client_id")
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(clientID) > 256 {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	redirectURI, ok := requiredSingle(form, "redirect_uri")
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(redirectURI) > 2048 {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.config.AllowsRedirect(clientID, redirectURI) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if len(form) != 5 {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.sessions.ExchangeCode(r.Context(), browserauth.ExchangeCodeInput{Code: code, Verifier: verifier, ClientID: clientID, RedirectURI: redirectURI})
	if err != nil {
		if errors.Is(err, browserauth.ErrGrantUnavailable) {
			writeTokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if result.EnterpriseID != h.config.EnterpriseID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	idToken, ttl, err := h.issuer.SignIDToken(browserauth.IDTokenInput{Subject: result.UserID, Audience: clientID, Nonce: result.Nonce, EnterpriseID: result.EnterpriseID, EnterpriseUserID: result.UserID})
	if err != nil {
		writeTokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id_token": idToken, "token_type": "Bearer", "expires_in": int(ttl.Seconds())})
}

func (h *browserAuthHandler) discovery(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.config.PublicIssuerURL, "/")
	writeJSON(w, http.StatusOK, map[string]any{"issuer": h.config.PublicIssuerURL, "authorization_endpoint": issuer + "/oauth2/authorize", "token_endpoint": issuer + "/oauth2/token", "jwks_uri": issuer + "/oauth2/jwks", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": h.issuer.Algorithms()})
}

func (h *browserAuthHandler) jwks(w http.ResponseWriter, _ *http.Request) {
	payload, err := h.issuer.JWKS()
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (h *browserAuthHandler) me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	session, err := h.sessions.GetSession(r.Context(), cookie.Value)
	if err != nil {
		if errors.Is(err, browserauth.ErrSessionUnavailable) {
			writeOAuthError(w, http.StatusServiceUnavailable)
			return
		}
		clearSessionCookie(w)
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	if session.EnterpriseID != h.config.EnterpriseID {
		clearSessionCookie(w)
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	profile, err := h.profiles.ResolveBrowserProfile(r.Context(), session.EnterpriseID, session.UserID)
	if err != nil || profile.EnterpriseID != session.EnterpriseID || profile.EnterpriseUserID != session.UserID || profile.OrgVersion < 1 {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	if profile.OrgUnitIDs == nil {
		profile.OrgUnitIDs = []string{}
	}
	if profile.Permissions == nil {
		profile.Permissions = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "enterprise_id": profile.EnterpriseID, "enterprise_user_id": profile.EnterpriseUserID, "display_name": profile.DisplayName, "org_version": profile.OrgVersion, "org_unit_ids": profile.OrgUnitIDs, "permissions": profile.Permissions, "advanced_mode_allowed": profile.AdvancedModeAllowed, "idle_expires_at": session.IdleExpiresAt, "absolute_expires_at": session.AbsoluteExpiresAt})
}

func (h *browserAuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	logoutCtx, cancel := boundedCleanupContext(r.Context())
	session, err := h.sessions.LogoutSession(logoutCtx, cookie.Value)
	cancel()
	if errors.Is(err, browserauth.ErrInvalidSession) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	auditCtx, auditCancel := boundedCleanupContext(r.Context())
	defer auditCancel()
	if err := h.audit.AppendBrowserAudit(auditCtx, BrowserAuditEvent{EnterpriseID: session.EnterpriseID, ActorUserID: session.UserID, Action: "browser_session.logout", Decision: "allow"}); err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func boundedCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), mandatoryCleanupTimeout)
}

func requiredSingle(values url.Values, key string) (string, bool) {
	items, ok := values[key]
	returnValue := ""
	if ok && len(items) == 1 {
		returnValue = items[0]
	}
	return returnValue, ok && len(items) == 1 && returnValue != ""
}
func constantTimeEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}
func validChallenge(value string) bool {
	decoded, err := browserauth.DecodeS256Challenge(value)
	return err == nil && len(decoded) == 32
}
func redirectWithCode(w http.ResponseWriter, r *http.Request, target, code, state string) {
	u, _ := url.Parse(target)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
func setSessionCookie(w http.ResponseWriter, value string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{Name: browserSessionCookie, Value: value, Path: "/", Expires: expiry, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: browserSessionCookie, Value: "", Path: "/", Expires: time.Unix(1, 0), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}
func writeOAuthError(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": "request_failed"})
}
func writeTokenError(w http.ResponseWriter, status int, code string) {
	setNoStore(w)
	writeJSON(w, status, map[string]string{"error": code})
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func canonicalOpaque(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

func newBrowserID() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func setOIDCBrowserCookie(w http.ResponseWriter, value string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{Name: oidcBrowserCookie, Value: value, Path: "/oauth2/authorize", Expires: expiry, MaxAge: int(oidcBrowserCookieTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func clearOIDCBrowserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: oidcBrowserCookie, Value: "", Path: "/oauth2/authorize", Expires: time.Unix(1, 0), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func loginBindingCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return loginBindingCookiePrefix + hex.EncodeToString(sum[:])
}

func setLoginBindingCookie(w http.ResponseWriter, state, binding string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: loginBindingCookieName(state), Value: binding, Path: "/oauth2/idp/callback", Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func clearLoginBindingCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{Name: loginBindingCookieName(state), Value: "", Path: "/oauth2/idp/callback", Expires: time.Unix(1, 0), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}
