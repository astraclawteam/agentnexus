// Package trust derives the ONE immutable, credential-verified principal
// context of every request at HTTP ingress.
//
// Contract (GA Task 0B):
//
//   - Browser sessions, service credentials (confidential client today; JWT
//     and mutual TLS slot in behind ServiceCredentialVerifier), Access
//     Tickets and Step Grants are the ONLY context sources.
//   - Caller JSON and headers can NEVER supply trusted tenant, actor,
//     organization version, trust class, client identity/release, risk
//     authority or approval authority. Requests carrying identity-forging
//     headers are rejected AND audited; body values never win.
//   - The context is resolved exactly once per request, bound by value into
//     the request context, and every accessor returns a copy: mutating a
//     copy can never change the bound context.
//   - AstraClaw/Xiaozhi client origin is carried as trace metadata only. It
//     can only LOWER capability (zero enterprise connector capability, even
//     first-party signed); it never raises trust. The full client trust
//     registry lands with GA Task 0C.
package trust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// Source identifies which verified credential kind produced a Context.
type Source string

const (
	SourceBrowserSession     Source = "browser_session"
	SourceBrowserAccessToken Source = "browser_access_token"
	SourceServiceCredential  Source = "service_credential"
	SourceAccessTicket       Source = "access_ticket"
	SourceStepGrant          Source = "step_grant"
)

// OriginHeader declares the calling Agent product. It is UNVERIFIED trace
// metadata: it is recorded verbatim, never changes the verified identity and
// can only reduce capability (AstraClaw/Xiaozhi lose connector capability).
const OriginHeader = "X-Agent-Origin"

const (
	OriginAstraClaw = "astraclaw"
	OriginXiaozhi   = "xiaozhi"
)

// UnregisteredReleaseRef marks a verified client whose release is not yet
// bound by the Task 0C trust registry.
const UnregisteredReleaseRef = "unregistered"

// UnboundOrgSnapshotRef marks a service credential context that carries no
// member organization snapshot (services have no memberships).
const UnboundOrgSnapshotRef = "orgv_unbound"

// DefaultSessionCookieName is the browser session cookie the resolver reads.
const DefaultSessionCookieName = "nexus_browser_session"

// DefaultBrowserClientRef classifies browser sessions until the Task 0C
// registry binds real client identities.
const DefaultBrowserClientRef = "console"

const (
	maxOpaqueCredentialLength = 4096
	maxOriginLength           = 128
	serviceContextTTL         = 5 * time.Minute
	// maxLoggableClientIDLength bounds the claimed client identifier a rejection
	// log line may echo. decodeBasicCredential accepts a much longer one, and an
	// unbounded echo of caller-controlled bytes is a log-volume lever.
	maxLoggableClientIDLength = 128
)

// Resolution errors. HTTPStatus maps them onto transport statuses.
var (
	// ErrNoTrustedContext is returned by accessors when no context was bound
	// (unprotected path or resolver not installed).
	ErrNoTrustedContext = errors.New("no trusted context bound to request")
	// ErrUnauthenticated marks a protected request without any credential.
	ErrUnauthenticated = errors.New("request carries no verifiable credential")
	// ErrInvalidCredential marks a rejected, revoked, cross-tenant or
	// malformed credential.
	ErrInvalidCredential = errors.New("credential rejected")
	// ErrConflictingCredentials marks a request presenting more than one
	// credential; it is rejected before any verifier runs.
	ErrConflictingCredentials = errors.New("conflicting credentials")
	// ErrCredentialUnavailable marks a verification-infrastructure outage;
	// the request fails closed as retryable.
	ErrCredentialUnavailable = errors.New("credential verification unavailable")
	// ErrForgedIdentity marks a request that tried to supply trusted
	// identity through headers.
	ErrForgedIdentity = errors.New("request supplies trusted identity outside credentials")
)

// Verifier contract errors: source verifiers translate their internal
// failures onto exactly these two sentinels.
var (
	// ErrCredentialRejected reports an invalid, unknown, expired or revoked
	// credential.
	ErrCredentialRejected = errors.New("credential not accepted by verifier")
	// ErrSourceUnavailable reports that the verifier could not answer.
	ErrSourceUnavailable = errors.New("credential source unavailable")
)

// Audit rejection reasons.
const (
	ReasonForgedIdentityHeader   = "forged_identity_header"
	ReasonConflictingCredentials = "conflicting_credentials"
	ReasonConflictingOrigin      = "conflicting_origin"
	ReasonMalformedOrigin        = "malformed_origin"
	ReasonCredentialRejected     = "credential_rejected"
	ReasonCrossTenant            = "cross_tenant_credential"
	ReasonUnsupportedScheme      = "unsupported_authorization_scheme"
	ReasonMalformedCredential    = "malformed_credential"
	ReasonExpiredCredential      = "expired_credential"
	// ReasonSourceNotConfigured marks a credential kind whose verifier is not
	// wired in this deployment. It is distinct from a malformed credential:
	// the caller presented a well-formed credential the runtime cannot verify
	// because the source is absent, not because the value is bad.
	ReasonSourceNotConfigured = "credential_source_not_configured"
)

// Audited field names (never carry attacker-controlled credential values).
const (
	FieldExpiresAt = "expires_at"
)

// SessionIdentity is a verified browser-session identity.
type SessionIdentity struct {
	TenantRef    string
	PrincipalRef string
	// ClientRef is populated for browser access tokens with the configured
	// confidential console client that received the token. Cookie sessions
	// leave it empty and use the deployment's default browser client class.
	ClientRef         string
	ExpiresAt         time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// BrowserSessionVerifier verifies an opaque browser-session token.
type BrowserSessionVerifier interface {
	VerifyBrowserSession(context.Context, string) (SessionIdentity, error)
}

// BrowserAccessTokenVerifier verifies an opaque, revocable browser BFF token.
// It returns the same member identity as the bound browser session while
// keeping the credential source explicit for authorization and audit policy.
type BrowserAccessTokenVerifier interface {
	VerifyBrowserAccessToken(context.Context, string) (SessionIdentity, error)
}

// TicketIdentity is a verified Access Ticket (Case Ticket) identity.
type TicketIdentity struct {
	TenantRef    string
	PrincipalRef string
	TicketRef    string
	ExpiresAt    time.Time
}

// AccessTicketVerifier verifies an opaque Access Ticket token.
type AccessTicketVerifier interface {
	VerifyAccessTicket(context.Context, string) (TicketIdentity, error)
}

// GrantIdentity is a verified Step Grant identity.
type GrantIdentity struct {
	TenantRef    string
	PrincipalRef string
	TicketRef    string
	GrantRef     string
	ExpiresAt    time.Time
}

// StepGrantVerifier verifies an opaque Step Grant token presented as a
// credential.
type StepGrantVerifier interface {
	VerifyStepGrant(context.Context, string) (GrantIdentity, error)
}

// ServiceIdentity is a verified first-party service identity (confidential
// client secret today; service JWT / mutual TLS implementations plug in
// behind the same verifier).
type ServiceIdentity struct {
	TenantRef  string
	ClientRef  string
	ReleaseRef string
}

// ServiceCredentialVerifier verifies confidential service credentials.
type ServiceCredentialVerifier interface {
	VerifyServiceCredential(context.Context, string, string) (ServiceIdentity, error)
}

// OrgSnapshotResolver resolves the current sealed organization snapshot
// version of a verified principal.
type OrgSnapshotResolver interface {
	ResolveSealedOrgVersion(context.Context, string, string) (int64, error)
}

// Rejection is the audited record of a refused trust input.
type Rejection struct {
	TenantRef    string
	PrincipalRef string
	Source       Source
	Reason       string
	Field        string
	Path         string
	Origin       string
	// ClaimedClientID is the client identifier a Basic service credential
	// presented. It is UNVERIFIED — the credential was refused, so nothing about
	// it is established — and it exists for one reason: an operator watching a
	// first-party service fail in a retry loop needs to know WHICH credential is
	// being refused, and the client id is the non-secret half.
	//
	// It is deliberately confined to the operational log. It must never reach
	// the audit trail's actor field, which records verified identity only, and
	// the secret half is never carried here at all.
	ClaimedClientID string
}

// AuditSink records trust rejections. Recording is best-effort: an audit
// outage never converts a rejection into an acceptance.
type AuditSink interface {
	RecordTrustRejection(context.Context, Rejection)
}

// Context is the immutable credential-derived context of one request. It
// contains only value fields so that copies are always safe.
type Context struct {
	// Principal is the frozen vendor-neutral principal context.
	Principal runtime.PrincipalContext
	// Source is the credential kind that produced this context.
	Source Source
	// OrgVersion is the sealed organization snapshot version resolved at
	// ingress (0 for service credentials, which carry no memberships).
	OrgVersion int64
	// CaseTicketRef is the Access Ticket lineage when the credential is a
	// ticket or a grant bound to one.
	CaseTicketRef string
	// Origin is the verbatim declared client origin — trace metadata only.
	Origin string
	// ConnectorCapabilityAllowed reports whether this context may exercise
	// enterprise connector capabilities. AstraClaw/Xiaozhi origins and
	// service credentials never may.
	ConnectorCapabilityAllowed bool
	// BrowserIdleExpiresAt and BrowserAbsoluteExpiresAt are populated only
	// for browser session / BFF-token contexts. They let browser-profile
	// handlers use the identity resolved once at ingress without re-reading
	// the credential store.
	BrowserIdleExpiresAt     time.Time
	BrowserAbsoluteExpiresAt time.Time
}

// BrowserCredential is the already-verified opaque browser credential bound
// to a request. Token is returned only to the browser-session revocation
// handler and must never be logged or persisted.
type BrowserCredential struct {
	Source Source
	Token  string
}

// forgedIdentityHeaders are request headers that would smuggle trusted
// identity outside credentials. Any occurrence is rejected and audited.
var forgedIdentityHeaders = []string{
	"X-Enterprise-Id",
	"X-Actor-User-Id",
	"X-Tenant-Ref",
	"X-Principal-Ref",
	"X-Org-Version",
	"X-Org-Unit-Id",
	"X-Org-Snapshot-Ref",
	"X-Trust-Class",
	"X-Client-Version",
	"X-Client-Release",
	"X-Agent-Client-Ref",
	"X-Agent-Release-Ref",
	"X-Risk-Authority",
	"X-Approval-Authority",
}

// forgedIdentityFields are request-body member names that would smuggle
// trusted identity. Strict body decoders consult this set to audit forgeries
// distinctly from ordinary unknown fields.
var forgedIdentityFields = map[string]struct{}{
	"enterprise_id":      {},
	"actor_user_id":      {},
	"tenant_ref":         {},
	"principal_ref":      {},
	"org_version":        {},
	"org_unit_id":        {},
	"org_snapshot_ref":   {},
	"trust_class":        {},
	"client_version":     {},
	"client_release":     {},
	"agent_client_ref":   {},
	"agent_release_ref":  {},
	"risk_authority":     {},
	"approval_authority": {},
}

// ForgedIdentityField reports whether a request-body member name is a
// trusted-identity name that callers may never supply.
func ForgedIdentityField(name string) bool {
	_, forged := forgedIdentityFields[name]
	return forged
}

// OrgSnapshotRef renders the opaque sealed-snapshot reference of a version.
func OrgSnapshotRef(version int64) string {
	return fmt.Sprintf("orgv_%d", version)
}

// HTTPStatus maps resolution errors onto transport statuses. Unknown errors
// fail closed as 401.
func HTTPStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrCredentialUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrForgedIdentity):
		return http.StatusBadRequest
	default:
		return http.StatusUnauthorized
	}
}

// ResolverConfig wires the credential sources of a deployment. TenantRef and
// at least one source are expected; absent sources reject their credential
// kind.
type ResolverConfig struct {
	// TenantRef is the deployment tenant every credential must belong to.
	TenantRef string
	// SessionCookieName overrides DefaultSessionCookieName.
	SessionCookieName string
	// BrowserClientRef overrides DefaultBrowserClientRef.
	BrowserClientRef    string
	Sessions            BrowserSessionVerifier
	BrowserAccessTokens BrowserAccessTokenVerifier
	AccessTickets       AccessTicketVerifier
	StepGrants          StepGrantVerifier
	Services            ServiceCredentialVerifier
	OrgSnapshots        OrgSnapshotResolver
	Audit               AuditSink
	// Logger receives every authentication rejection. Nil selects
	// slog.Default() explicitly (the handler-logger seam used elsewhere in this
	// service).
	//
	// Rejections used to reach the audit TABLE and nothing else, so a
	// first-party client refused several times a minute forever produced a
	// completely silent gateway log while the caller saw only a status code.
	// The evidence plane already logs its denials with reasons
	// (evidence.locate_denied); ingress now does the same.
	Logger *slog.Logger
	// Protected reports whether a request requires a trusted context. Only
	// protected requests are resolved; forged-identity header screening
	// covers every request.
	Protected func(*http.Request) bool
	Now       func() time.Time
}

// Resolver derives trusted contexts at ingress.
type Resolver struct {
	cfg ResolverConfig
}

// NewResolver validates the configuration.
func NewResolver(cfg ResolverConfig) (*Resolver, error) {
	if !canonical(cfg.TenantRef) {
		return nil, errors.New("trust resolver requires a canonical tenant reference")
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = DefaultSessionCookieName
	}
	if cfg.BrowserClientRef == "" {
		cfg.BrowserClientRef = DefaultBrowserClientRef
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Resolver{cfg: cfg}, nil
}

type contextKey struct{}

// resolution is bound by VALUE: the context is immutable once resolved.
type resolution struct {
	ctx Context
	err error
}

// Middleware screens every request for forged identity headers and resolves
// the trusted context exactly once for protected requests. On a protected
// path with a resolution error the middleware writes the rejection itself and
// NEVER calls the wrapped handler: refusing unauthenticated traffic is a
// structural invariant of the chain, not a convention handlers must remember.
// A forged-header rejection records only the offending header NAME (Field),
// never its attacker-controlled value.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if header, forged := forgedIdentityHeader(req.Header); forged {
			r.audit(req, Rejection{Reason: ReasonForgedIdentityHeader, Field: header, Path: req.URL.Path})
			writeTrustRejection(w, http.StatusBadRequest)
			return
		}
		origin, ok := declaredOrigin(req.Header)
		if !ok {
			reason := ReasonMalformedOrigin
			if len(req.Header.Values(OriginHeader)) > 1 {
				reason = ReasonConflictingOrigin
			}
			r.audit(req, Rejection{Reason: reason, Field: OriginHeader, Path: req.URL.Path})
			writeTrustRejection(w, http.StatusBadRequest)
			return
		}
		if r.cfg.Protected != nil && r.cfg.Protected(req) {
			resolved, err := r.resolve(req, origin)
			if err != nil {
				writeTrustRejection(w, HTTPStatus(err))
				return
			}
			req = req.WithContext(context.WithValue(req.Context(), contextKey{}, resolution{ctx: resolved}))
		}
		next.ServeHTTP(w, req)
	})
}

// ContextFromRequest returns the immutable PrincipalContext resolved at
// ingress for this request. It is the only way handlers obtain trusted
// identity.
func ContextFromRequest(req *http.Request) (runtime.PrincipalContext, error) {
	bound, err := FromRequest(req)
	if err != nil {
		return runtime.PrincipalContext{}, err
	}
	return bound.Principal, nil
}

// FromRequest returns the full immutable trusted context of this request.
func FromRequest(req *http.Request) (Context, error) {
	if req == nil {
		return Context{}, ErrNoTrustedContext
	}
	bound, ok := req.Context().Value(contextKey{}).(resolution)
	if !ok {
		return Context{}, ErrNoTrustedContext
	}
	if bound.err != nil {
		return Context{}, bound.err
	}
	return bound.ctx, nil
}

// ResolveBrowserRequest applies the exact same conflict, syntax, tenant,
// expiry and verifier rules as ingress middleware and returns the verified
// browser credential needed by the session profile/logout endpoints. Those
// endpoints are intentionally outside the generic protected-path middleware
// because they must clear a rejected session cookie and logout needs the
// verified opaque token for revocation.
func (r *Resolver) ResolveBrowserRequest(req *http.Request) (Context, BrowserCredential, error) {
	if r == nil || req == nil {
		return Context{}, BrowserCredential{}, ErrUnauthenticated
	}
	if header, forged := forgedIdentityHeader(req.Header); forged {
		r.audit(req, Rejection{Reason: ReasonForgedIdentityHeader, Field: header, Path: req.URL.Path})
		return Context{}, BrowserCredential{}, ErrForgedIdentity
	}
	origin, ok := declaredOrigin(req.Header)
	if !ok {
		reason := ReasonMalformedOrigin
		if len(req.Header.Values(OriginHeader)) > 1 {
			reason = ReasonConflictingOrigin
		}
		r.audit(req, Rejection{Reason: reason, Field: OriginHeader, Path: req.URL.Path})
		return Context{}, BrowserCredential{}, ErrForgedIdentity
	}
	resolved, err := r.resolve(req, origin)
	if err != nil {
		// Logout is a capability-reducing operation and must be retryable after
		// a previous attempt revoked the session but failed to append audit.
		// Return only a canonical single Bearer envelope; the caller must still
		// validate it against the server-side token binding before mutation.
		if credential, ok := browserCredentialValue(req, r.cfg.SessionCookieName, SourceBrowserAccessToken); ok {
			return Context{}, credential, err
		}
		return Context{}, BrowserCredential{}, err
	}
	credential, ok := browserCredentialValue(req, r.cfg.SessionCookieName, resolved.Source)
	if !ok {
		r.audit(req, Rejection{Source: resolved.Source, Reason: ReasonCredentialRejected, Path: req.URL.Path, Origin: origin})
		return Context{}, BrowserCredential{}, ErrInvalidCredential
	}
	return resolved, credential, nil
}

func browserCredentialValue(req *http.Request, cookieName string, source Source) (BrowserCredential, bool) {
	switch source {
	case SourceBrowserSession:
		cookies := make([]*http.Cookie, 0, 1)
		for _, cookie := range req.Cookies() {
			if cookie.Name == cookieName {
				cookies = append(cookies, cookie)
			}
		}
		if len(cookies) != 1 || !opaqueCredential(cookies[0].Value) {
			return BrowserCredential{}, false
		}
		return BrowserCredential{Source: source, Token: cookies[0].Value}, true
	case SourceBrowserAccessToken:
		values := req.Header.Values("Authorization")
		if len(values) != 1 {
			return BrowserCredential{}, false
		}
		scheme, value, found := strings.Cut(values[0], " ")
		value = strings.TrimSpace(value)
		if !found || !strings.EqualFold(scheme, "Bearer") || !opaqueCredential(value) || strings.ContainsAny(value, " \t") {
			return BrowserCredential{}, false
		}
		return BrowserCredential{Source: source, Token: value}, true
	default:
		return BrowserCredential{}, false
	}
}

func (r *Resolver) resolve(req *http.Request, origin string) (Context, error) {
	var sessionCookies []*http.Cookie
	for _, cookie := range req.Cookies() {
		if cookie.Name == r.cfg.SessionCookieName {
			sessionCookies = append(sessionCookies, cookie)
		}
	}
	authorizations := req.Header.Values("Authorization")
	if len(sessionCookies) > 1 || len(authorizations) > 1 || (len(sessionCookies) == 1 && len(authorizations) > 0) {
		r.audit(req, Rejection{Reason: ReasonConflictingCredentials, Path: req.URL.Path, Origin: origin})
		return Context{}, ErrConflictingCredentials
	}

	switch {
	case len(sessionCookies) == 1:
		return r.resolveSession(req, origin, sessionCookies[0].Value)
	case len(authorizations) == 1:
		return r.resolveAuthorization(req, origin, authorizations[0])
	default:
		// Deliberately NOT recorded. A protected request with no credential is
		// ordinary traffic (probes, unauthenticated clients); recording it would
		// bury the rejections that mean something and hand an unauthenticated
		// caller a log-volume lever. Only a PRESENTED credential that fails is a
		// trust rejection. See TestTrustedContextUnauthenticatedAndUnprotectedPaths.
		return Context{}, ErrUnauthenticated
	}
}

func (r *Resolver) resolveSession(req *http.Request, origin, token string) (Context, error) {
	if r.cfg.Sessions == nil {
		r.audit(req, Rejection{Reason: ReasonSourceNotConfigured, Source: SourceBrowserSession, Path: req.URL.Path, Origin: origin})
		return Context{}, ErrInvalidCredential
	}
	if !opaqueCredential(token) {
		r.audit(req, Rejection{Reason: ReasonMalformedCredential, Source: SourceBrowserSession, Path: req.URL.Path, Origin: origin})
		return Context{}, ErrInvalidCredential
	}
	identity, err := r.cfg.Sessions.VerifyBrowserSession(req.Context(), token)
	if err != nil {
		return Context{}, r.credentialFailure(req, SourceBrowserSession, origin, "", err)
	}
	return r.principalContext(req, principalInput{
		source:                   SourceBrowserSession,
		tenantRef:                identity.TenantRef,
		principalRef:             identity.PrincipalRef,
		clientRef:                r.cfg.BrowserClientRef,
		releaseRef:               UnregisteredReleaseRef,
		expiresAt:                identity.ExpiresAt,
		browserIdleExpiresAt:     identity.IdleExpiresAt,
		browserAbsoluteExpiresAt: identity.AbsoluteExpiresAt,
		expiring:                 true,
		origin:                   origin,
	})
}

// resolveAuthorization dispatches by RFC 7235 auth scheme. Scheme tokens are
// case-insensitive (RFC 7235 §2.1), so they are matched with EqualFold; the
// credential VALUE that follows is always matched exactly.
func (r *Resolver) resolveAuthorization(req *http.Request, origin, header string) (Context, error) {
	scheme, value, found := strings.Cut(header, " ")
	value = strings.TrimSpace(value)
	if !found || value == "" || strings.ContainsAny(value, " \t") {
		r.audit(req, Rejection{Reason: ReasonMalformedCredential, Path: req.URL.Path, Origin: origin})
		return Context{}, ErrInvalidCredential
	}
	switch {
	case strings.EqualFold(scheme, "CaseTicket"):
		if r.cfg.AccessTickets == nil {
			r.audit(req, Rejection{Reason: ReasonSourceNotConfigured, Source: SourceAccessTicket, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		if !opaqueCredential(value) {
			r.audit(req, Rejection{Reason: ReasonMalformedCredential, Source: SourceAccessTicket, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		identity, err := r.cfg.AccessTickets.VerifyAccessTicket(req.Context(), value)
		if err != nil {
			return Context{}, r.credentialFailure(req, SourceAccessTicket, origin, "", err)
		}
		return r.principalContext(req, principalInput{
			source:        SourceAccessTicket,
			tenantRef:     identity.TenantRef,
			principalRef:  identity.PrincipalRef,
			clientRef:     r.cfg.BrowserClientRef,
			releaseRef:    UnregisteredReleaseRef,
			caseTicketRef: identity.TicketRef,
			expiresAt:     identity.ExpiresAt,
			expiring:      true,
			origin:        origin,
		})
	case strings.EqualFold(scheme, "Bearer"):
		if r.cfg.BrowserAccessTokens == nil {
			r.audit(req, Rejection{Reason: ReasonSourceNotConfigured, Source: SourceBrowserAccessToken, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		if !opaqueCredential(value) {
			r.audit(req, Rejection{Reason: ReasonMalformedCredential, Source: SourceBrowserAccessToken, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		identity, err := r.cfg.BrowserAccessTokens.VerifyBrowserAccessToken(req.Context(), value)
		if err != nil {
			return Context{}, r.credentialFailure(req, SourceBrowserAccessToken, origin, "", err)
		}
		clientRef := identity.ClientRef
		if clientRef == "" {
			clientRef = r.cfg.BrowserClientRef
		}
		return r.principalContext(req, principalInput{
			source:                   SourceBrowserAccessToken,
			tenantRef:                identity.TenantRef,
			principalRef:             identity.PrincipalRef,
			clientRef:                clientRef,
			releaseRef:               UnregisteredReleaseRef,
			expiresAt:                identity.ExpiresAt,
			browserIdleExpiresAt:     identity.IdleExpiresAt,
			browserAbsoluteExpiresAt: identity.AbsoluteExpiresAt,
			expiring:                 true,
			origin:                   origin,
		})
	case strings.EqualFold(scheme, "StepGrant"):
		if r.cfg.StepGrants == nil {
			r.audit(req, Rejection{Reason: ReasonSourceNotConfigured, Source: SourceStepGrant, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		if !opaqueCredential(value) {
			r.audit(req, Rejection{Reason: ReasonMalformedCredential, Source: SourceStepGrant, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		identity, err := r.cfg.StepGrants.VerifyStepGrant(req.Context(), value)
		if err != nil {
			return Context{}, r.credentialFailure(req, SourceStepGrant, origin, "", err)
		}
		return r.principalContext(req, principalInput{
			source:        SourceStepGrant,
			tenantRef:     identity.TenantRef,
			principalRef:  identity.PrincipalRef,
			clientRef:     r.cfg.BrowserClientRef,
			releaseRef:    UnregisteredReleaseRef,
			caseTicketRef: identity.TicketRef,
			expiresAt:     identity.ExpiresAt,
			expiring:      true,
			origin:        origin,
		})
	case strings.EqualFold(scheme, "Basic"):
		if r.cfg.Services == nil {
			r.audit(req, Rejection{Reason: ReasonSourceNotConfigured, Source: SourceServiceCredential, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		clientID, secret, ok := decodeBasicCredential(value)
		if !ok {
			r.audit(req, Rejection{Reason: ReasonMalformedCredential, Source: SourceServiceCredential, Path: req.URL.Path, Origin: origin})
			return Context{}, ErrInvalidCredential
		}
		identity, err := r.cfg.Services.VerifyServiceCredential(req.Context(), clientID, secret)
		if err != nil {
			// The claimed client id rides along so the rejection names WHICH
			// first-party credential was refused. This is the case a joint stack
			// hits when the two halves of a service secret were provisioned by
			// different hands: without the id, every rejection looks the same.
			return Context{}, r.credentialFailure(req, SourceServiceCredential, origin, clientID, err)
		}
		return r.principalContext(req, principalInput{
			source:       SourceServiceCredential,
			tenantRef:    identity.TenantRef,
			principalRef: identity.ClientRef,
			clientRef:    identity.ClientRef,
			releaseRef:   identity.ReleaseRef,
			origin:       origin,
		})
	default:
		r.audit(req, Rejection{Reason: ReasonUnsupportedScheme, Field: scheme, Path: req.URL.Path, Origin: origin})
		return Context{}, ErrInvalidCredential
	}
}

type principalInput struct {
	source                   Source
	tenantRef                string
	principalRef             string
	clientRef                string
	releaseRef               string
	caseTicketRef            string
	expiresAt                time.Time
	browserIdleExpiresAt     time.Time
	browserAbsoluteExpiresAt time.Time
	// expiring marks a credential kind that carries its own intrinsic expiry
	// (browser session, Access Ticket, Step Grant). Such a credential must
	// present a real future expiry; a zero or past expiry is rejected, never
	// silently extended. Service credentials are not expiring: they have no
	// intrinsic lifetime and are bound to a fixed derived-context TTL.
	expiring bool
	origin   string
}

func (r *Resolver) principalContext(req *http.Request, input principalInput) (Context, error) {
	if input.tenantRef != r.cfg.TenantRef {
		r.audit(req, Rejection{TenantRef: input.tenantRef, PrincipalRef: input.principalRef, Source: input.source, Reason: ReasonCrossTenant, Path: req.URL.Path, Origin: input.origin})
		return Context{}, ErrInvalidCredential
	}
	if !canonical(input.principalRef) || !canonical(input.clientRef) || !canonical(input.releaseRef) {
		r.audit(req, Rejection{TenantRef: input.tenantRef, PrincipalRef: input.principalRef, Source: input.source, Reason: ReasonMalformedCredential, Path: req.URL.Path, Origin: input.origin})
		return Context{}, ErrInvalidCredential
	}

	orgVersion := int64(0)
	orgSnapshotRef := UnboundOrgSnapshotRef
	if input.source != SourceServiceCredential {
		if r.cfg.OrgSnapshots == nil {
			return Context{}, ErrCredentialUnavailable
		}
		version, err := r.cfg.OrgSnapshots.ResolveSealedOrgVersion(req.Context(), input.tenantRef, input.principalRef)
		if err != nil || version < 1 {
			return Context{}, errJoinUnavailable(err)
		}
		orgVersion = version
		orgSnapshotRef = OrgSnapshotRef(version)
	}

	now := r.cfg.Now().UTC()
	expires := input.expiresAt
	if input.expiring {
		// Fail closed: an expiring credential with a missing or past expiry is
		// rejected outright. Extending it to now+TTL would silently resurrect a
		// dead session/ticket/grant.
		if expires.IsZero() || !expires.After(now) {
			r.audit(req, Rejection{TenantRef: input.tenantRef, PrincipalRef: input.principalRef, Source: input.source, Reason: ReasonCredentialRejected, Field: FieldExpiresAt, Path: req.URL.Path, Origin: input.origin})
			return Context{}, ErrInvalidCredential
		}
	} else {
		// Service credentials have no intrinsic expiry (PrincipalContext.Validate
		// requires ExpiresAt > VerifiedAt); bind the derived context to a fixed
		// TTL. This clamp only ever runs for the non-expiring service source.
		expires = now.Add(serviceContextTTL)
	}
	principal := runtime.PrincipalContext{
		TenantRef:       input.tenantRef,
		PrincipalRef:    input.principalRef,
		AgentClientRef:  input.clientRef,
		AgentReleaseRef: input.releaseRef,
		TrustClass:      runtime.TrustFirstParty,
		OrgSnapshotRef:  orgSnapshotRef,
		VerifiedAt:      now,
		ExpiresAt:       expires,
	}
	if err := principal.Validate(); err != nil {
		return Context{}, errors.Join(ErrCredentialUnavailable, err)
	}
	return Context{
		Principal:                  principal,
		Source:                     input.source,
		OrgVersion:                 orgVersion,
		CaseTicketRef:              input.caseTicketRef,
		Origin:                     input.origin,
		ConnectorCapabilityAllowed: connectorCapabilityAllowed(input.source, input.origin),
		BrowserIdleExpiresAt:       input.browserIdleExpiresAt,
		BrowserAbsoluteExpiresAt:   input.browserAbsoluteExpiresAt,
	}, nil
}

func (r *Resolver) credentialFailure(req *http.Request, source Source, origin, claimedClientID string, err error) error {
	if errors.Is(err, ErrCredentialRejected) {
		r.audit(req, Rejection{Source: source, Reason: ReasonCredentialRejected, Path: req.URL.Path, Origin: origin, ClaimedClientID: claimedClientID})
		return ErrInvalidCredential
	}
	return errJoinUnavailable(err)
}

// audit records one refused trust input on BOTH surfaces: the durable audit
// trail (verified identity only, best-effort) and the operational log (what an
// operator needs to see a client failing in a loop). Neither ever carries a
// credential value — Field is a header NAME, ClaimedClientID is the non-secret
// half of a Basic credential, and the secret is not in Rejection at all.
func (r *Resolver) audit(req *http.Request, rejection Rejection) {
	if rejection.TenantRef == "" {
		rejection.TenantRef = r.cfg.TenantRef
	}
	if r.cfg.Logger != nil {
		attrs := []any{
			slog.String("tenant_ref", rejection.TenantRef),
			slog.String("reason", rejection.Reason),
			slog.String("path", rejection.Path),
			slog.String("credential_source", string(rejection.Source)),
		}
		if rejection.Field != "" {
			attrs = append(attrs, slog.String("field", rejection.Field))
		}
		if rejection.Origin != "" {
			attrs = append(attrs, slog.String("declared_origin", rejection.Origin))
		}
		if rejection.ClaimedClientID != "" {
			attrs = append(attrs, slog.String("claimed_client_id", loggableClientID(rejection.ClaimedClientID)))
		}
		r.cfg.Logger.WarnContext(req.Context(), "trust.credential_rejected", attrs...)
	}
	if r.cfg.Audit == nil {
		return
	}
	// ClaimedClientID stays out of the audit row on purpose: the audit trail
	// records verified identity, and this value was never verified.
	rejection.ClaimedClientID = ""
	r.cfg.Audit.RecordTrustRejection(req.Context(), rejection)
}

// loggableClientID bounds and screens a caller-supplied client identifier
// before it reaches a log line. The value is attacker-controlled, so a
// non-printable or oversized one is reported as unloggable rather than written
// through: a newline in a log record is a forged second record.
func loggableClientID(clientID string) string {
	if len(clientID) > maxLoggableClientIDLength {
		return "<non-canonical>"
	}
	for i := 0; i < len(clientID); i++ {
		if clientID[i] < 0x21 || clientID[i] > 0x7e {
			return "<non-canonical>"
		}
	}
	return clientID
}

func errJoinUnavailable(err error) error {
	if err == nil {
		return ErrCredentialUnavailable
	}
	return errors.Join(ErrCredentialUnavailable, err)
}

// connectorCapabilityAllowed: origin can only lower capability. Service
// credentials never carry connector capability in 0B.
func connectorCapabilityAllowed(source Source, origin string) bool {
	if source == SourceServiceCredential {
		return false
	}
	switch strings.ToLower(origin) {
	case OriginAstraClaw, OriginXiaozhi:
		return false
	}
	return true
}

// forgedIdentityHeader returns the NAME of the first identity-forging header
// present. It deliberately never returns the header value: the value is
// attacker-controlled identity and must never be stored or logged.
func forgedIdentityHeader(header http.Header) (string, bool) {
	for _, name := range forgedIdentityHeaders {
		if len(header.Values(name)) > 0 {
			return name, true
		}
	}
	return "", false
}

func declaredOrigin(header http.Header) (string, bool) {
	values := header.Values(OriginHeader)
	switch len(values) {
	case 0:
		return "", true
	case 1:
		value := values[0]
		if !canonical(value) || len(value) > maxOriginLength {
			return "", false
		}
		return value, true
	default:
		return "", false
	}
}

func decodeBasicCredential(value string) (string, string, bool) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > 1024 {
		return "", "", false
	}
	clientID, secret, found := strings.Cut(string(raw), ":")
	if !found || !canonical(clientID) || secret == "" || strings.TrimSpace(secret) != secret {
		return "", "", false
	}
	return clientID, secret, true
}

func opaqueCredential(value string) bool {
	return canonical(value) && len(value) <= maxOpaqueCredentialLength
}

func canonical(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func writeTrustRejection(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "request_failed"})
}
