package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
)

const browserSessionCookie = "nexus_browser_session"
const maxTokenRequestBytes = 16 << 10

type UpstreamOIDC interface {
	AuthCodeURL(state, nonce string) string
	ExchangeAndVerify(context.Context, string) (browserauth.VerifiedIdentity, string, error)
}

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
	Config     browserauth.OIDCConfig
	Sessions   *browserauth.Service
	Upstream   UpstreamOIDC
	Identities ExternalIdentityResolver
	Profiles   BrowserProfileResolver
	Audit      BrowserAuditSink
}

type browserAuthHandler struct {
	config     browserauth.OIDCConfig
	sessions   *browserauth.Service
	upstream   UpstreamOIDC
	identities ExternalIdentityResolver
	profiles   BrowserProfileResolver
	audit      BrowserAuditSink
	issuer     *browserauth.TokenIssuer
}

func newBrowserAuthHandler(deps BrowserAuthDependencies) (*browserAuthHandler, error) {
	if deps.Sessions == nil || deps.Upstream == nil || deps.Identities == nil || deps.Profiles == nil || deps.Audit == nil {
		return nil, errors.New("browser auth dependencies incomplete")
	}
	issuer, err := browserauth.NewTokenIssuer(deps.Config, time.Now)
	if err != nil {
		return nil, err
	}
	return &browserAuthHandler{config: deps.Config, sessions: deps.Sessions, upstream: deps.Upstream, identities: deps.Identities, profiles: deps.Profiles, audit: deps.Audit, issuer: issuer}, nil
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
	query := r.URL.Query()
	clientID, ok := requiredSingle(query, "client_id")
	if !ok {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	redirectURI, ok := requiredSingle(query, "redirect_uri")
	if !ok || !h.config.AllowsRedirect(clientID, redirectURI) {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	state, ok := requiredSingle(query, "state")
	if !ok {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	nonce, ok := requiredSingle(query, "nonce")
	if !ok {
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
	if value, valid := optionalSingle(query, "response_type"); !valid || (value != "" && value != "code") {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	if scope, valid := optionalSingle(query, "scope"); !valid || (scope != "" && !slices.Contains(strings.Fields(scope), "openid")) {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	if !validChallenge(challenge) {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}

	if cookie, err := r.Cookie(browserSessionCookie); err == nil {
		if session, err := h.sessions.GetSession(r.Context(), cookie.Value); err == nil {
			code, err := h.sessions.IssueCode(r.Context(), browserauth.IssueCodeInput{EnterpriseID: session.EnterpriseID, UserID: session.UserID, ClientID: clientID, RedirectURI: redirectURI, Nonce: nonce, CodeChallenge: challenge})
			if err != nil {
				writeOAuthError(w, http.StatusServiceUnavailable)
				return
			}
			redirectWithCode(w, r, redirectURI, code, state)
			return
		}
		clearSessionCookie(w)
	}
	attemptState, attempt, err := h.sessions.CreateLoginAttempt(r.Context(), browserauth.CreateLoginAttemptInput{EnterpriseID: h.config.EnterpriseID, ClientID: clientID, RedirectURI: redirectURI, ConsoleState: state, ConsoleNonce: nonce, CodeChallenge: challenge})
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, h.upstream.AuthCodeURL(attemptState, attempt.UpstreamNonce), http.StatusFound)
}

func (h *browserAuthHandler) callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	code, ok := requiredSingle(query, "code")
	if !ok {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	state, ok := requiredSingle(query, "state")
	if !ok {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	attempt, err := h.sessions.ConsumeLoginAttempt(r.Context(), state)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	identity, nonce, err := h.upstream.ExchangeAndVerify(r.Context(), code)
	if err != nil || !constantTimeEqual(nonce, attempt.UpstreamNonce) {
		writeOAuthError(w, http.StatusUnauthorized)
		return
	}
	enterpriseID, userID, err := h.identities.ResolveExternalIdentity(r.Context(), attempt.EnterpriseID, identity.Issuer, identity.Subject)
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
		_ = h.sessions.RevokeSession(context.WithoutCancel(r.Context()), sessionToken)
		writeOAuthError(w, status)
	}
	downstreamCode, err := h.sessions.IssueCode(r.Context(), browserauth.IssueCodeInput{EnterpriseID: enterpriseID, UserID: userID, ClientID: attempt.ClientID, RedirectURI: attempt.RedirectURI, Nonce: attempt.ConsoleNonce, CodeChallenge: attempt.CodeChallenge})
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	if err := h.audit.AppendBrowserAudit(r.Context(), BrowserAuditEvent{EnterpriseID: enterpriseID, ActorUserID: userID, Action: "browser_session.create", Decision: "allow"}); err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	setSessionCookie(w, sessionToken, session.AbsoluteExpiresAt)
	redirectWithCode(w, r, attempt.RedirectURI, downstreamCode, attempt.ConsoleState)
}

func (h *browserAuthHandler) token(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeTokenError(w, http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTokenRequestBytes+1))
	if err != nil || len(body) > maxTokenRequestBytes {
		writeTokenError(w, http.StatusRequestEntityTooLarge)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	grant, ok := requiredSingle(form, "grant_type")
	if !ok || grant != "authorization_code" {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	code, ok := requiredSingle(form, "code")
	if !ok {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	verifier, ok := requiredSingle(form, "code_verifier")
	if !ok {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	clientID, ok := requiredSingle(form, "client_id")
	if !ok {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	redirectURI, ok := requiredSingle(form, "redirect_uri")
	if !ok || !h.config.AllowsRedirect(clientID, redirectURI) {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	if len(form) != 5 {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	result, err := h.sessions.ExchangeCode(r.Context(), browserauth.ExchangeCodeInput{Code: code, Verifier: verifier, ClientID: clientID, RedirectURI: redirectURI})
	if err != nil {
		writeTokenError(w, http.StatusBadRequest)
		return
	}
	idToken, ttl, err := h.issuer.SignIDToken(browserauth.IDTokenInput{Subject: result.UserID, Audience: clientID, Nonce: result.Nonce, EnterpriseID: result.EnterpriseID, EnterpriseUserID: result.UserID})
	if err != nil {
		writeTokenError(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{"id_token": idToken, "token_type": "Bearer", "expires_in": int(ttl.Seconds())})
}

func (h *browserAuthHandler) discovery(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.config.PublicIssuerURL, "/")
	writeJSON(w, http.StatusOK, map[string]any{"issuer": h.config.PublicIssuerURL, "authorization_endpoint": issuer + "/oauth2/authorize", "token_endpoint": issuer + "/oauth2/token", "jwks_uri": issuer + "/oauth2/jwks", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{h.issuer.Algorithm()}})
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
	session, err := h.sessions.GetSession(r.Context(), cookie.Value)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := h.sessions.RevokeSession(context.WithoutCancel(r.Context()), cookie.Value); err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	if err := h.audit.AppendBrowserAudit(r.Context(), BrowserAuditEvent{EnterpriseID: session.EnterpriseID, ActorUserID: session.UserID, Action: "browser_session.logout", Decision: "allow"}); err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func requiredSingle(values url.Values, key string) (string, bool) {
	items, ok := values[key]
	returnValue := ""
	if ok && len(items) == 1 {
		returnValue = items[0]
	}
	return returnValue, ok && len(items) == 1 && returnValue != ""
}
func optionalSingle(values url.Values, key string) (string, bool) {
	items, ok := values[key]
	if !ok {
		return "", true
	}
	if len(items) != 1 {
		return "", false
	}
	return items[0], true
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
func writeTokenError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": "invalid_request"})
}
