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
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
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
	LogoutBrowserSession(context.Context, string, BrowserAuditEvent) (browserauth.BrowserSession, error)
}

// browserSessionResolver is the narrow session-lookup surface the trust
// resolver needs.
type browserSessionResolver interface {
	GetSession(context.Context, string) (browserauth.BrowserSession, error)
}

// browserSessionTrustVerifier adapts the browser session service onto the
// trust resolver's session source.
type browserSessionTrustVerifier struct{ sessions browserSessionResolver }

func (v browserSessionTrustVerifier) VerifyBrowserSession(ctx context.Context, token string) (trust.SessionIdentity, error) {
	session, err := v.sessions.GetSession(ctx, token)
	if errors.Is(err, browserauth.ErrSessionUnavailable) {
		return trust.SessionIdentity{}, errors.Join(trust.ErrSourceUnavailable, err)
	}
	if err != nil {
		return trust.SessionIdentity{}, errors.Join(trust.ErrCredentialRejected, err)
	}
	return trust.SessionIdentity{TenantRef: session.EnterpriseID, PrincipalRef: session.UserID, ExpiresAt: session.IdleExpiresAt}, nil
}

// consoleServiceCredentialVerifier verifies the confidential first-party
// service client (AgentAtlas console). The tenant and client identity come
// from the verified credential, never from request data.
type consoleServiceCredentialVerifier struct{ config browserauth.OIDCConfig }

func (v consoleServiceCredentialVerifier) VerifyServiceCredential(_ context.Context, clientID, secret string) (trust.ServiceIdentity, error) {
	if clientID == "agentatlas" && v.config.AuthenticateConsoleClient(clientID, secret) {
		return trust.ServiceIdentity{TenantRef: v.config.EnterpriseID, ClientRef: clientID, ReleaseRef: trust.UnregisteredReleaseRef}, nil
	}
	return trust.ServiceIdentity{}, trust.ErrCredentialRejected
}

// snapshotIntegrityLogger surfaces sealed-snapshot integrity failures (cycle,
// dangling reference, duplicate, unknown role, over-limit) to the operational
// log, so a corrupt org-policy pipeline is a visible high-risk deny rather
// than a silent baseline deny.
type snapshotIntegrityLogger struct{}

func (snapshotIntegrityLogger) SealedSnapshotIntegrityFailure(_ context.Context, tenantRef, principalRef string, orgVersion int64) {
	log.Printf("sealed org snapshot integrity failure: tenant=%s principal=%s org_version=%d", tenantRef, principalRef, orgVersion)
}

// sealedOrgVersionResolver pins the sealed organization snapshot version of
// a verified principal at ingress.
type sealedOrgVersionResolver struct{ source policy.SnapshotSource }

func (v sealedOrgVersionResolver) ResolveSealedOrgVersion(ctx context.Context, tenantRef, principalRef string) (int64, error) {
	snapshot, err := v.source.LoadAccessSnapshot(ctx, tenantRef, principalRef)
	if err != nil {
		return 0, errors.Join(trust.ErrSourceUnavailable, err)
	}
	return snapshot.OrgVersion, nil
}

// browserTrustAuditSink records trust rejections in the browser audit trail.
// The persisted action names the reason and, when present, the offending
// FIELD (e.g. the forged header's name) — never the attacker-controlled
// value, which the resolver deliberately does not carry.
type browserTrustAuditSink struct{ sink BrowserAuditSink }

func (s browserTrustAuditSink) RecordTrustRejection(ctx context.Context, rejection trust.Rejection) {
	if s.sink == nil {
		return
	}
	action := "trusted_context." + rejection.Reason
	if rejection.Field != "" {
		action += ":" + rejection.Field
	}
	auditCtx, cancel := boundedCleanupContext(ctx)
	defer cancel()
	_ = s.sink.AppendBrowserAudit(auditCtx, BrowserAuditEvent{EnterpriseID: rejection.TenantRef, ActorUserID: rejection.PrincipalRef, Action: action, Decision: "deny"})
}

type BrowserAuthDependencies struct {
	Config                  browserauth.OIDCConfig
	Sessions                BrowserSessionService
	Upstream                UpstreamOIDC
	Identities              ExternalIdentityResolver
	Profiles                BrowserProfileResolver
	Audit                   BrowserAuditSink
	AuditEvidence           AuditEvidenceSink
	TokenIssuer             IDTokenIssuer
	RequestTimeout          time.Duration
	AuthorizeRateLimiter    browserauth.AuthorizeRateLimiter
	AuthorizeSourceResolver AuthorizeSourceResolver
	AuthorizationPolicy     policy.SnapshotSource
	// OrgVersions resolves the sealed org snapshot version at ingress with a
	// single query. When nil, the resolver falls back to reading the version
	// off the full AuthorizationPolicy snapshot (used by in-memory tests).
	OrgVersions  trust.OrgSnapshotResolver
	TicketActors trust.AccessTicketVerifier
	StepGrants   trust.StepGrantVerifier
	// ApprovalTransmission is the GA Task 0E approval transmission plane
	// (optional; the endpoints register when provided). AgentNexus transmits
	// the caller's signed plan unchanged and validates returned evidence —
	// without a configured transmission service there is NO approval surface
	// at all (fail closed; the legacy resolution surface is retired).
	ApprovalTransmission ApprovalTransmissionService
	Grants               grantService
	// Evidence is the semantic evidence runtime behind /v1/runtime/locate and
	// /v1/runtime/read (optional; the endpoints register when provided).
	Evidence EvidenceService
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
	trustResolver           *trust.Resolver
	authorization           *authorizationHandler
	approval                *approvalTransportHandler
	grants                  *grantHandler
	auditEvidence           *auditEvidenceHandler
	evidence                *evidenceHandler
}

func newBrowserAuthHandler(deps BrowserAuthDependencies) (*browserAuthHandler, error) {
	if deps.Sessions == nil || deps.Upstream == nil || deps.Identities == nil || deps.Profiles == nil || deps.Audit == nil || deps.AuthorizeRateLimiter == nil || deps.AuthorizeSourceResolver == nil || deps.AuthorizationPolicy == nil || deps.TicketActors == nil {
		return nil, errors.New("browser auth dependencies incomplete")
	}
	orgVersions := deps.OrgVersions
	if orgVersions == nil {
		orgVersions = sealedOrgVersionResolver{source: deps.AuthorizationPolicy}
	}
	trustResolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef:     deps.Config.EnterpriseID,
		Sessions:      browserSessionTrustVerifier{sessions: deps.Sessions},
		AccessTickets: deps.TicketActors,
		StepGrants:    deps.StepGrants,
		Services:      consoleServiceCredentialVerifier{config: deps.Config},
		OrgSnapshots:  orgVersions,
		Audit:         browserTrustAuditSink{sink: deps.Audit},
		Protected: func(r *http.Request) bool {
			return trustProtectedPath(r.URL.Path)
		},
	})
	if err != nil {
		return nil, err
	}
	authorization, err := newAuthorizationHandler(authorizationDependencies{EnterpriseID: deps.Config.EnterpriseID, Evaluator: policy.NewCapabilityEvaluator(deps.AuthorizationPolicy, policy.WithSnapshotIntegrityObserver(snapshotIntegrityLogger{})), Audit: deps.Audit})
	if err != nil {
		return nil, err
	}
	var approvalRoutes *approvalTransportHandler
	if deps.ApprovalTransmission != nil {
		// No logger is injected through BrowserAuthDependencies yet; nil selects
		// the constructor's explicit slog.Default() fallback through the single
		// handler-logger seam (0D evidence-handler precedent).
		approvalRoutes, err = newApprovalTransportHandler(deps.Config.EnterpriseID, deps.ApprovalTransmission, deps.Audit, nil)
		if err != nil {
			return nil, err
		}
	}
	var grants *grantHandler
	if deps.Grants != nil {
		grants, err = newGrantHandler(deps.Config.EnterpriseID, deps.Grants, deps.Audit)
		if err != nil {
			return nil, err
		}
	}
	var auditEvidence *auditEvidenceHandler
	if deps.AuditEvidence != nil {
		auditEvidence, err = newAuditEvidenceHandler(deps.Config.EnterpriseID, deps.TicketActors, deps.AuditEvidence, deps.Audit)
		if err != nil {
			return nil, err
		}
	}
	var evidenceRuntime *evidenceHandler
	if deps.Evidence != nil {
		// No logger is injected through BrowserAuthDependencies yet; nil
		// selects the constructor's explicit slog.Default() fallback through
		// the single handler-logger seam.
		evidenceRuntime, err = newEvidenceHandler(deps.Config.EnterpriseID, deps.Evidence, deps.Audit, nil)
		if err != nil {
			return nil, err
		}
	}
	issuer := deps.TokenIssuer
	if issuer == nil {
		var err error
		issuer, err = browserauth.NewTokenIssuer(deps.Config, time.Now)
		if err != nil {
			return nil, err
		}
	}
	return &browserAuthHandler{config: deps.Config, sessions: deps.Sessions, upstream: deps.Upstream, identities: deps.Identities, profiles: deps.Profiles, audit: deps.Audit, issuer: issuer, authorizeRateLimiter: deps.AuthorizeRateLimiter, authorizeSourceResolver: deps.AuthorizeSourceResolver, trustResolver: trustResolver, authorization: authorization, approval: approvalRoutes, grants: grants, auditEvidence: auditEvidence, evidence: evidenceRuntime}, nil
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
	h.authorization.register(mux)
	if h.approval != nil {
		h.approval.register(mux)
	}
	if h.grants != nil {
		h.grants.register(mux)
	}
	if h.auditEvidence != nil {
		h.auditEvidence.register(mux)
	}
	if h.evidence != nil {
		h.evidence.register(mux)
	}
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
	responseType, ok := requiredSingle(query, "response_type")
	if !ok || responseType != "code" {
		writeOAuthError(w, http.StatusBadRequest)
		return
	}
	scope, ok := requiredSingle(query, "scope")
	if !ok || !containsExactWord(strings.Fields(scope), "openid") {
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
		if errors.Is(err, ErrInvalidForwardedChain) {
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_forwarded_chain"})
			return
		}
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
	clientID, clientSecret, ok := confidentialBasicCredentials(r.Header)
	if !ok || !h.config.AuthenticateConsoleClient(clientID, clientSecret) {
		writeInvalidClient(w)
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
	if len(form) != 4 {
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
	writeJSON(w, http.StatusOK, map[string]any{"issuer": h.config.PublicIssuerURL, "authorization_endpoint": issuer + "/oauth2/authorize", "token_endpoint": issuer + "/oauth2/token", "jwks_uri": issuer + "/oauth2/jwks", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "id_token_signing_alg_values_supported": h.issuer.Algorithms()})
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
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	logoutCtx, cancel := boundedCleanupContext(r.Context())
	session, err := h.audit.LogoutBrowserSession(logoutCtx, cookie.Value, BrowserAuditEvent{EnterpriseID: h.config.EnterpriseID, Action: "browser_session.logout", Decision: "allow"})
	cancel()
	if errors.Is(err, browserauth.ErrInvalidSession) {
		clearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	if session.EnterpriseID != h.config.EnterpriseID || session.UserID == "" {
		writeOAuthError(w, http.StatusServiceUnavailable)
		return
	}
	clearSessionCookie(w)
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
func containsExactWord(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func confidentialBasicCredentials(header http.Header) (string, string, bool) {
	values := header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Basic ") || strings.Count(values[0], " ") != 1 {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(values[0], "Basic "))
	if err != nil || len(raw) == 0 || len(raw) > 1024 {
		return "", "", false
	}
	separator := strings.IndexByte(string(raw), ':')
	if separator < 1 || separator > 256 || separator == len(raw)-1 {
		return "", "", false
	}
	clientID, secret := string(raw[:separator]), string(raw[separator+1:])
	if !browserauth.ValidConsoleClientID(clientID) || strings.TrimSpace(secret) != secret {
		return "", "", false
	}
	return clientID, secret, true
}

func writeInvalidClient(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="AgentNexus token"`)
	writeTokenError(w, http.StatusUnauthorized, "invalid_client")
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
