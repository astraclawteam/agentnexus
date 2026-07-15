package trust_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const testTenant = "ent-1"

type fakeSessions struct {
	mu          sync.Mutex
	identities  map[string]trust.SessionIdentity
	revoked     map[string]bool
	unavailable bool
	calls       int
}

type fakeAccessTokens struct {
	identities  map[string]trust.SessionIdentity
	unavailable bool
	calls       int
}

func (f *fakeAccessTokens) VerifyBrowserAccessToken(_ context.Context, token string) (trust.SessionIdentity, error) {
	f.calls++
	if f.unavailable {
		return trust.SessionIdentity{}, trust.ErrSourceUnavailable
	}
	identity, ok := f.identities[token]
	if !ok {
		return trust.SessionIdentity{}, trust.ErrCredentialRejected
	}
	return identity, nil
}

func (f *fakeSessions) VerifyBrowserSession(_ context.Context, token string) (trust.SessionIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.unavailable {
		return trust.SessionIdentity{}, trust.ErrSourceUnavailable
	}
	if f.revoked[token] {
		return trust.SessionIdentity{}, trust.ErrCredentialRejected
	}
	identity, ok := f.identities[token]
	if !ok {
		return trust.SessionIdentity{}, trust.ErrCredentialRejected
	}
	return identity, nil
}

type fakeTickets struct {
	identities map[string]trust.TicketIdentity
}

func (f *fakeTickets) VerifyAccessTicket(_ context.Context, token string) (trust.TicketIdentity, error) {
	identity, ok := f.identities[token]
	if !ok {
		return trust.TicketIdentity{}, trust.ErrCredentialRejected
	}
	return identity, nil
}

type fakeGrants struct {
	identities map[string]trust.GrantIdentity
}

func (f *fakeGrants) VerifyStepGrant(_ context.Context, token string) (trust.GrantIdentity, error) {
	identity, ok := f.identities[token]
	if !ok {
		return trust.GrantIdentity{}, trust.ErrCredentialRejected
	}
	return identity, nil
}

type fakeServices struct {
	clientID string
	secret   string
	identity trust.ServiceIdentity
}

func (f *fakeServices) VerifyServiceCredential(_ context.Context, clientID, secret string) (trust.ServiceIdentity, error) {
	if clientID != f.clientID || secret != f.secret {
		return trust.ServiceIdentity{}, trust.ErrCredentialRejected
	}
	return f.identity, nil
}

type fakeSnapshots struct {
	mu      sync.Mutex
	version int64
	err     error
	calls   int
}

func (f *fakeSnapshots) ResolveSealedOrgVersion(_ context.Context, tenantRef, principalRef string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	if tenantRef == "" || principalRef == "" {
		return 0, trust.ErrSourceUnavailable
	}
	return f.version, nil
}

func (f *fakeSnapshots) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type recordingAudit struct {
	mu         sync.Mutex
	rejections []trust.Rejection
}

func (a *recordingAudit) RecordTrustRejection(_ context.Context, rejection trust.Rejection) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rejections = append(a.rejections, rejection)
}

func (a *recordingAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.rejections)
}

func (a *recordingAudit) last() trust.Rejection {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.rejections) == 0 {
		return trust.Rejection{}
	}
	return a.rejections[len(a.rejections)-1]
}

type trustHarness struct {
	resolver     *trust.Resolver
	sessions     *fakeSessions
	accessTokens *fakeAccessTokens
	tickets      *fakeTickets
	grants       *fakeGrants
	services     *fakeServices
	snapshots    *fakeSnapshots
	audit        *recordingAudit
	router       http.Handler
	handled      *int
}

type echoedContext struct {
	Status        int    `json:"status"`
	Tenant        string `json:"tenant"`
	Principal     string `json:"principal"`
	Client        string `json:"client"`
	Release       string `json:"release"`
	TrustClass    string `json:"trust_class"`
	SnapshotRef   string `json:"snapshot_ref"`
	OrgVersion    int64  `json:"org_version"`
	Source        string `json:"source"`
	CaseTicketRef string `json:"case_ticket_ref"`
	Origin        string `json:"origin"`
	Connector     bool   `json:"connector"`
	ValidationOK  bool   `json:"validation_ok"`
	Immutable     bool   `json:"immutable"`
	AccessorErr   string `json:"accessor_err"`
}

func newTrustHarness(t *testing.T) *trustHarness {
	t.Helper()
	h := &trustHarness{
		sessions: &fakeSessions{
			identities: map[string]trust.SessionIdentity{
				"session-token": {TenantRef: testTenant, PrincipalRef: "user-1", ExpiresAt: time.Now().Add(time.Hour)},
				"foreign-token": {TenantRef: "ent-2", PrincipalRef: "user-9", ExpiresAt: time.Now().Add(time.Hour)},
			},
			revoked: map[string]bool{},
		},
		accessTokens: &fakeAccessTokens{identities: map[string]trust.SessionIdentity{
			"access-token": {TenantRef: testTenant, PrincipalRef: "user-1", ClientRef: "agentnexus-admin", ExpiresAt: time.Now().Add(time.Hour)},
		}},
		tickets: &fakeTickets{identities: map[string]trust.TicketIdentity{
			"ticket-token": {TenantRef: testTenant, PrincipalRef: "user-1", TicketRef: "ct-1", ExpiresAt: time.Now().Add(time.Hour)},
		}},
		grants: &fakeGrants{identities: map[string]trust.GrantIdentity{
			"grant-token": {TenantRef: testTenant, PrincipalRef: "user-1", TicketRef: "ct-1", GrantRef: "grant-1", ExpiresAt: time.Now().Add(time.Minute)},
		}},
		services:  &fakeServices{clientID: "agentatlas", secret: "svc-secret", identity: trust.ServiceIdentity{TenantRef: testTenant, ClientRef: "agentatlas", ReleaseRef: trust.UnregisteredReleaseRef}},
		snapshots: &fakeSnapshots{version: 12},
		audit:     &recordingAudit{},
		handled:   new(int),
	}
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef:           testTenant,
		Sessions:            h.sessions,
		BrowserAccessTokens: h.accessTokens,
		AccessTickets:       h.tickets,
		StepGrants:          h.grants,
		Services:            h.services,
		OrgSnapshots:        h.snapshots,
		Audit:               h.audit,
		Protected: func(r *http.Request) bool {
			return r.URL.Path == "/protected"
		},
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*h.handled++
		echo := echoedContext{Status: http.StatusOK}
		principal, accessorErr := trust.ContextFromRequest(r)
		if accessorErr != nil {
			echo.AccessorErr = accessorErr.Error()
			echo.Status = trust.HTTPStatus(accessorErr)
			writeEcho(w, echo)
			return
		}
		first, err := trust.FromRequest(r)
		if err != nil {
			echo.AccessorErr = err.Error()
			echo.Status = trust.HTTPStatus(err)
			writeEcho(w, echo)
			return
		}
		// Mutating the returned copies must never affect the bound context.
		first.Principal.TenantRef = "mutated"
		first.OrgVersion = -1
		principal.PrincipalRef = "mutated"
		second, err := trust.FromRequest(r)
		if err != nil {
			t.Errorf("second FromRequest: %v", err)
		}
		echo.Tenant = second.Principal.TenantRef
		echo.Principal = second.Principal.PrincipalRef
		echo.Client = second.Principal.AgentClientRef
		echo.Release = second.Principal.AgentReleaseRef
		echo.TrustClass = string(second.Principal.TrustClass)
		echo.SnapshotRef = second.Principal.OrgSnapshotRef
		echo.OrgVersion = second.OrgVersion
		echo.Source = string(second.Source)
		echo.CaseTicketRef = second.CaseTicketRef
		echo.Origin = second.Origin
		echo.Connector = second.ConnectorCapabilityAllowed
		echo.ValidationOK = second.Principal.Validate() == nil
		echo.Immutable = second.Principal.TenantRef == testTenant && second.OrgVersion >= 0
		writeEcho(w, echo)
	})
	h.router = resolver.Middleware(handler)
	h.resolver = resolver
	return h
}

func writeEcho(w http.ResponseWriter, echo echoedContext) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(echo.Status)
	_ = json.NewEncoder(w).Encode(echo)
}

func performTrust(t *testing.T, h *trustHarness, mutate func(*http.Request)) (*httptest.ResponseRecorder, echoedContext) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if mutate != nil {
		mutate(req)
	}
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	var echo echoedContext
	_ = json.Unmarshal(rr.Body.Bytes(), &echo)
	return rr, echo
}

func addSessionCookie(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: "nexus_browser_session", Value: "session-token"})
}

func TestTrustedContextResolvesBrowserSessionOnceAndImmutable(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, echo := performTrust(t, h, addSessionCookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if echo.Tenant != testTenant || echo.Principal != "user-1" || echo.Source != string(trust.SourceBrowserSession) {
		t.Fatalf("context=%+v", echo)
	}
	if echo.TrustClass != string(runtime.TrustFirstParty) {
		t.Fatalf("trust class=%q want first_party_trusted", echo.TrustClass)
	}
	if echo.OrgVersion != 12 || echo.SnapshotRef != trust.OrgSnapshotRef(12) {
		t.Fatalf("org version=%d snapshot=%q", echo.OrgVersion, echo.SnapshotRef)
	}
	if !echo.ValidationOK {
		t.Fatal("PrincipalContext must satisfy the frozen runtime validation rules")
	}
	if !echo.Immutable {
		t.Fatal("mutating accessor copies must not change the bound context")
	}
	if h.sessions.calls != 1 {
		t.Fatalf("session verifier calls=%d, want exactly one resolution at ingress", h.sessions.calls)
	}
	if h.snapshots.callCount() != 1 {
		t.Fatalf("snapshot resolutions=%d, want exactly one at ingress", h.snapshots.callCount())
	}
}

func TestTrustedContextResolvesBrowserAccessTokenOnce(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, echo := performTrust(t, h, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer access-token")
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if echo.Tenant != testTenant || echo.Principal != "user-1" || echo.Client != "agentnexus-admin" || echo.Source != string(trust.SourceBrowserAccessToken) || !echo.Connector {
		t.Fatalf("context=%+v", echo)
	}
	if h.accessTokens.calls != 1 || h.snapshots.callCount() != 1 {
		t.Fatalf("access token calls=%d snapshot calls=%d", h.accessTokens.calls, h.snapshots.callCount())
	}
}

func TestResolveBrowserRequestReturnsOnlyTheVerifiedBrowserCredential(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/browser-sessions/me", nil)
	req.Header.Set("Authorization", "bEaReR access-token")
	ctx, credential, err := h.resolver.ResolveBrowserRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Source != trust.SourceBrowserAccessToken || credential.Source != trust.SourceBrowserAccessToken || credential.Token != "access-token" {
		t.Fatalf("context=%+v credential=%+v", ctx, credential)
	}

	conflict := httptest.NewRequest(http.MethodGet, "/v1/browser-sessions/logout", nil)
	conflict.AddCookie(&http.Cookie{Name: "nexus_browser_session", Value: "session-token"})
	conflict.Header.Set("Authorization", "Bearer access-token")
	if _, _, err := h.resolver.ResolveBrowserRequest(conflict); !errors.Is(err, trust.ErrConflictingCredentials) {
		t.Fatalf("conflicting browser credentials error=%v", err)
	}
}

func TestTrustedContextBrowserAccessTokenFailuresFailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		configure func(*trustHarness)
		want      int
	}{
		{name: "unknown", want: http.StatusUnauthorized},
		{name: "source unavailable", configure: func(h *trustHarness) { h.accessTokens.unavailable = true }, want: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrustHarness(t)
			if tc.configure != nil {
				tc.configure(h)
			}
			token := "unknown-token"
			if tc.name == "source unavailable" {
				token = "access-token"
			}
			rr, _ := performTrust(t, h, func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+token) })
			if rr.Code != tc.want || *h.handled != 0 {
				t.Fatalf("status=%d want=%d handled=%d", rr.Code, tc.want, *h.handled)
			}
		})
	}
}

func TestTrustedContextRejectsForgedIdentityHeaders(t *testing.T) {
	t.Parallel()
	headers := []string{
		"X-Enterprise-Id", "X-Actor-User-Id", "X-Tenant-Ref", "X-Principal-Ref",
		"X-Org-Version", "X-Org-Unit-Id", "X-Org-Snapshot-Ref", "X-Trust-Class",
		"X-Client-Version", "X-Client-Release", "X-Agent-Client-Ref",
		"X-Agent-Release-Ref", "X-Risk-Authority", "X-Approval-Authority",
	}
	for _, header := range headers {
		t.Run(header, func(t *testing.T) {
			h := newTrustHarness(t)
			before := h.audit.count()
			rr, _ := performTrust(t, h, func(req *http.Request) {
				addSessionCookie(req)
				req.Header.Set(header, "forged")
			})
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 for forged %s", rr.Code, header)
			}
			if *h.handled != 0 {
				t.Fatal("handler must not run after a forged identity header")
			}
			if h.audit.count() != before+1 {
				t.Fatalf("audit count=%d want one rejection", h.audit.count())
			}
			// The audit must name the offending header (Field) but NEVER record
			// its attacker-controlled value: storing "forged" as identity would
			// let an attacker write arbitrary identity strings into the trail.
			if rejection := h.audit.last(); rejection.Reason != trust.ReasonForgedIdentityHeader || rejection.Field != header || rejection.Origin != "" || rejection.PrincipalRef != "" || strings.Contains(rejection.Field, "forged") {
				t.Fatalf("forged-header audit must record the field name only, not the value: %+v", rejection)
			}
		})
	}
}

func TestTrustedContextForgedHeaderScreeningCoversUnprotectedPaths(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/anything-else", nil)
	req.Header.Set("X-Org-Version", "999")
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || *h.handled != 0 {
		t.Fatalf("status=%d handled=%d", rr.Code, *h.handled)
	}
	if h.audit.count() != 1 {
		t.Fatalf("audit count=%d", h.audit.count())
	}
}

func TestTrustedContextRejectsConflictingCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "two session cookies", mutate: func(req *http.Request) {
			req.AddCookie(&http.Cookie{Name: "nexus_browser_session", Value: "session-token"})
			req.AddCookie(&http.Cookie{Name: "nexus_browser_session", Value: "other"})
		}},
		{name: "session and ticket", mutate: func(req *http.Request) {
			addSessionCookie(req)
			req.Header.Set("Authorization", "CaseTicket ticket-token")
		}},
		{name: "session and bearer", mutate: func(req *http.Request) {
			addSessionCookie(req)
			req.Header.Set("Authorization", "Bearer access-token")
		}},
		{name: "repeated authorization", mutate: func(req *http.Request) {
			req.Header.Add("Authorization", "CaseTicket ticket-token")
			req.Header.Add("Authorization", "CaseTicket other")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newTrustHarness(t)
			rr, _ := performTrust(t, h, test.mutate)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401", rr.Code)
			}
			if h.sessions.calls != 0 {
				t.Fatal("conflicting credentials must be rejected before any verifier runs")
			}
			if h.audit.count() != 1 {
				t.Fatalf("audit count=%d want one rejection", h.audit.count())
			}
		})
	}
}

func TestTrustedContextRevokedCredentialReplayIsRejected(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, _ := performTrust(t, h, addSessionCookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("initial status=%d", rr.Code)
	}
	h.sessions.mu.Lock()
	h.sessions.revoked["session-token"] = true
	h.sessions.mu.Unlock()
	rr, _ = performTrust(t, h, addSessionCookie)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("replayed revoked credential status=%d want 401", rr.Code)
	}
	if h.audit.count() != 1 {
		t.Fatalf("audit count=%d want the replay rejection recorded", h.audit.count())
	}
}

func TestTrustedContextAccessTicketSource(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, echo := performTrust(t, h, func(req *http.Request) {
		req.Header.Set("Authorization", "CaseTicket ticket-token")
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if echo.Source != string(trust.SourceAccessTicket) || echo.CaseTicketRef != "ct-1" || echo.OrgVersion != 12 {
		t.Fatalf("context=%+v", echo)
	}
	if !echo.ValidationOK {
		t.Fatal("ticket-derived PrincipalContext must validate")
	}
}

func TestTrustedContextStepGrantSource(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, echo := performTrust(t, h, func(req *http.Request) {
		req.Header.Set("Authorization", "StepGrant grant-token")
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if echo.Source != string(trust.SourceStepGrant) || echo.CaseTicketRef != "ct-1" || echo.OrgVersion != 12 {
		t.Fatalf("context=%+v", echo)
	}
}

func TestTrustedContextServiceCredentialSource(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, echo := performTrust(t, h, func(req *http.Request) {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agentatlas:svc-secret")))
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if echo.Source != string(trust.SourceServiceCredential) || echo.Client != "agentatlas" || echo.Release != trust.UnregisteredReleaseRef {
		t.Fatalf("context=%+v", echo)
	}
	if echo.OrgVersion != 0 || echo.SnapshotRef != trust.UnboundOrgSnapshotRef {
		t.Fatalf("service credentials must not bind a member org snapshot: %+v", echo)
	}
	if h.snapshots.callCount() != 0 {
		t.Fatal("service credential resolution must not load member snapshots")
	}
	if echo.Connector {
		t.Fatal("service credentials must not receive connector capability")
	}
}

func TestTrustedContextAstraClawOriginIsTraceMetadataOnly(t *testing.T) {
	t.Parallel()
	baseline, baselineEcho := func() (*httptest.ResponseRecorder, echoedContext) {
		h := newTrustHarness(t)
		return performTrust(t, h, addSessionCookie)
	}()
	if baseline.Code != http.StatusOK || !baselineEcho.Connector {
		t.Fatalf("baseline status=%d connector=%v", baseline.Code, baselineEcho.Connector)
	}
	for _, origin := range []string{"astraclaw", "AstraClaw", "xiaozhi"} {
		t.Run(origin, func(t *testing.T) {
			h := newTrustHarness(t)
			rr, echo := performTrust(t, h, func(req *http.Request) {
				addSessionCookie(req)
				req.Header.Set(trust.OriginHeader, origin)
			})
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d: origin is trace metadata and must not break resolution", rr.Code)
			}
			if echo.Origin != origin {
				t.Fatalf("origin=%q want verbatim trace metadata %q", echo.Origin, origin)
			}
			if echo.Connector {
				t.Fatal("AstraClaw/Xiaozhi origins must have zero connector capability")
			}
			if echo.Tenant != baselineEcho.Tenant || echo.TrustClass != baselineEcho.TrustClass || echo.Principal != baselineEcho.Principal {
				t.Fatalf("origin header must never change verified identity: %+v vs %+v", echo, baselineEcho)
			}
		})
	}
	t.Run("other origins keep connector capability", func(t *testing.T) {
		h := newTrustHarness(t)
		rr, echo := performTrust(t, h, func(req *http.Request) {
			addSessionCookie(req)
			req.Header.Set(trust.OriginHeader, "acme-agent")
		})
		if rr.Code != http.StatusOK || !echo.Connector || echo.Origin != "acme-agent" {
			t.Fatalf("status=%d echo=%+v", rr.Code, echo)
		}
	})
	t.Run("repeated origin header is rejected", func(t *testing.T) {
		h := newTrustHarness(t)
		rr, _ := performTrust(t, h, func(req *http.Request) {
			addSessionCookie(req)
			req.Header.Add(trust.OriginHeader, "astraclaw")
			req.Header.Add(trust.OriginHeader, "other")
		})
		if rr.Code != http.StatusBadRequest || h.audit.count() != 1 {
			t.Fatalf("status=%d audit=%d", rr.Code, h.audit.count())
		}
	})
}

func TestTrustedContextUnauthenticatedAndUnprotectedPaths(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, _ := performTrust(t, h, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated protected request status=%d want 401", rr.Code)
	}
	if body := strings.TrimSpace(rr.Body.String()); body != `{"error":"request_failed"}` {
		t.Fatalf("unauthenticated body=%q want the uniform request_failed body", body)
	}
	if *h.handled != 0 {
		t.Fatal("the handler must not run for an unauthenticated protected request")
	}
	// Unauthenticated probes are DELIBERATELY not audited: a request with no
	// credential is normal traffic (health checks, unauthenticated clients),
	// not a trust violation. Only rejected/forged/conflicting credentials are.
	if h.audit.count() != 0 {
		t.Fatalf("unauthenticated probe must not be audited, got %d events", h.audit.count())
	}

	req := httptest.NewRequest(http.MethodGet, "/open", nil)
	rr = httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	var openEcho echoedContext
	_ = json.Unmarshal(rr.Body.Bytes(), &openEcho)
	if openEcho.AccessorErr == "" || !strings.Contains(openEcho.AccessorErr, trust.ErrNoTrustedContext.Error()) {
		t.Fatalf("unprotected path must expose no trusted context: %+v", openEcho)
	}
}

func TestTrustedContextExpiringCredentialWithPastExpiryIsRejected(t *testing.T) {
	t.Parallel()
	past := time.Now().Add(-30 * time.Minute)
	for _, tc := range []struct {
		name  string
		setup func(*trustHarness)
		probe func(*http.Request)
	}{
		{
			name: "browser session expired 30m ago",
			setup: func(h *trustHarness) {
				h.sessions.mu.Lock()
				h.sessions.identities["session-token"] = trust.SessionIdentity{TenantRef: testTenant, PrincipalRef: "user-1", ExpiresAt: past}
				h.sessions.mu.Unlock()
			},
			probe: addSessionCookie,
		},
		{
			name: "access ticket expired",
			setup: func(h *trustHarness) {
				h.tickets.identities["ticket-token"] = trust.TicketIdentity{TenantRef: testTenant, PrincipalRef: "user-1", TicketRef: "ct-1", ExpiresAt: past}
			},
			probe: func(req *http.Request) { req.Header.Set("Authorization", "CaseTicket ticket-token") },
		},
		{
			name: "step grant expired",
			setup: func(h *trustHarness) {
				h.grants.identities["grant-token"] = trust.GrantIdentity{TenantRef: testTenant, PrincipalRef: "user-1", TicketRef: "ct-1", GrantRef: "grant-1", ExpiresAt: past}
			},
			probe: func(req *http.Request) { req.Header.Set("Authorization", "StepGrant grant-token") },
		},
		{
			name: "session with zero expiry is not silently extended",
			setup: func(h *trustHarness) {
				h.sessions.mu.Lock()
				h.sessions.identities["session-token"] = trust.SessionIdentity{TenantRef: testTenant, PrincipalRef: "user-1"}
				h.sessions.mu.Unlock()
			},
			probe: addSessionCookie,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrustHarness(t)
			tc.setup(h)
			rr, echo := performTrust(t, h, tc.probe)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401: an expired credential must never be clamped to a fresh context", rr.Code)
			}
			if echo.Tenant != "" || *h.handled != 0 {
				t.Fatalf("a fresh context was minted for an expired credential: echo=%+v handled=%d", echo, *h.handled)
			}
			if h.audit.count() != 1 || h.audit.last().Reason != trust.ReasonCredentialRejected || h.audit.last().Field != trust.FieldExpiresAt {
				t.Fatalf("expired credential must be audited as a rejection naming expires_at: %+v", h.audit.last())
			}
		})
	}
}

func TestTrustedContextServiceCredentialNoIntrinsicExpiryIsClampedNotRejected(t *testing.T) {
	t.Parallel()
	// The service credential (no intrinsic expiry) is the ONE case the
	// now+TTL clamp legitimately applies to; it must still resolve.
	h := newTrustHarness(t)
	rr, echo := performTrust(t, h, func(req *http.Request) {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agentatlas:svc-secret")))
	})
	if rr.Code != http.StatusOK || echo.Source != string(trust.SourceServiceCredential) {
		t.Fatalf("service credential must resolve via the fixed-TTL clamp: status=%d echo=%+v", rr.Code, echo)
	}
}

func TestTrustedContextCrossTenantCredentialIsRejected(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, _ := performTrust(t, h, func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "nexus_browser_session", Value: "foreign-token"})
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
	if h.audit.count() != 1 || h.audit.last().Reason != trust.ReasonCrossTenant {
		t.Fatalf("audit=%+v", h.audit.last())
	}
}

func TestTrustedContextSnapshotOutageFailsClosed(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	h.snapshots.mu.Lock()
	h.snapshots.err = trust.ErrSourceUnavailable
	h.snapshots.mu.Unlock()
	rr, _ := performTrust(t, h, addSessionCookie)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 when the sealed snapshot cannot be resolved", rr.Code)
	}
}

// newUnconfiguredResolver builds a resolver with NO credential sources wired,
// to prove an unconfigured source is audited distinctly from a malformed one.
func newUnconfiguredResolver(t *testing.T, audit *recordingAudit) http.Handler {
	t.Helper()
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef:    testTenant,
		OrgSnapshots: &fakeSnapshots{version: 12},
		Audit:        audit,
		Protected:    func(r *http.Request) bool { return r.URL.Path == "/protected" },
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	handled := 0
	return resolver.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handled++ }))
}

func TestTrustedContextUnconfiguredSourceIsAuditedDistinctly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		probe func(*http.Request)
	}{
		{name: "session source absent", probe: addSessionCookie},
		{name: "ticket source absent", probe: func(req *http.Request) { req.Header.Set("Authorization", "CaseTicket ticket-token") }},
		{name: "step grant source absent", probe: func(req *http.Request) { req.Header.Set("Authorization", "StepGrant grant-token") }},
		{name: "service source absent", probe: func(req *http.Request) {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agentatlas:svc-secret")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &recordingAudit{}
			router := newUnconfiguredResolver(t, audit)
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			tc.probe(req)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401", rr.Code)
			}
			if audit.count() != 1 || audit.last().Reason != trust.ReasonSourceNotConfigured {
				t.Fatalf("unconfigured source must audit credential_source_not_configured, not malformed: %+v", audit.last())
			}
		})
	}
}

func TestTrustedContextSchemeTokenIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	// RFC 7235 auth scheme tokens are case-insensitive; the credential VALUE
	// is not. A lowercased scheme must still resolve.
	h := newTrustHarness(t)
	rr, echo := performTrust(t, h, func(req *http.Request) {
		req.Header.Set("Authorization", "caseticket ticket-token")
	})
	if rr.Code != http.StatusOK || echo.Source != string(trust.SourceAccessTicket) {
		t.Fatalf("case-insensitive scheme must resolve: status=%d echo=%+v", rr.Code, echo)
	}
}

func TestTrustedContextMalformedAuthorizationCredentialsRejected(t *testing.T) {
	t.Parallel()
	oversizedToken := strings.Repeat("a", 5000)
	oversizedBasic := base64.StdEncoding.EncodeToString([]byte("agentatlas:" + strings.Repeat("s", 2000)))
	for _, tc := range []struct {
		name   string
		header string
	}{
		{name: "empty credential after scheme", header: "CaseTicket "},
		{name: "internal whitespace in token", header: "CaseTicket a b"},
		{name: "oversized opaque token", header: "CaseTicket " + oversizedToken},
		{name: "basic bad base64", header: "Basic !!!not-base64!!!"},
		{name: "basic missing colon", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("agentatlas-no-colon"))},
		{name: "basic decoded over 1024 bytes", header: "Basic " + oversizedBasic},
		{name: "basic empty secret", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("agentatlas:"))},
		{name: "unknown bearer token", header: "Bearer forged-jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrustHarness(t)
			rr, echo := performTrust(t, h, func(req *http.Request) {
				req.Header.Set("Authorization", tc.header)
			})
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401 for %q", rr.Code, tc.header)
			}
			if echo.Tenant != "" || *h.handled != 0 {
				t.Fatalf("a malformed credential must not resolve a context: echo=%+v", echo)
			}
		})
	}
}

func TestTrustedContextMalformedOriginRejected(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		origin string
	}{
		{name: "leading whitespace", origin: " astraclaw"},
		{name: "trailing whitespace", origin: "astraclaw "},
		{name: "oversized origin", origin: strings.Repeat("x", 200)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTrustHarness(t)
			rr, _ := performTrust(t, h, func(req *http.Request) {
				addSessionCookie(req)
				req.Header.Set(trust.OriginHeader, tc.origin)
			})
			if rr.Code != http.StatusBadRequest || *h.handled != 0 {
				t.Fatalf("status=%d handled=%d: a malformed origin must be rejected before resolution", rr.Code, *h.handled)
			}
			if h.audit.count() != 1 || h.audit.last().Reason != trust.ReasonMalformedOrigin {
				t.Fatalf("malformed origin audit=%+v", h.audit.last())
			}
		})
	}
}

func TestTrustedContextUnknownAuthorizationSchemeIsRejected(t *testing.T) {
	t.Parallel()
	h := newTrustHarness(t)
	rr, _ := performTrust(t, h, func(req *http.Request) {
		req.Header.Set("Authorization", "Digest forged")
	})
	if rr.Code != http.StatusUnauthorized || h.audit.count() != 1 {
		t.Fatalf("status=%d audit=%d", rr.Code, h.audit.count())
	}
}

func TestTrustedContextMiddlewareShortCircuitsBeforeForgetfulHandler(t *testing.T) {
	t.Parallel()
	// A handler that FORGETS to call FromRequest must still be unable to serve
	// unauthenticated traffic on a protected path: refusing it is a structural
	// invariant of the middleware, not a convention the handler must uphold.
	served := false
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef:    testTenant,
		Sessions:     &fakeSessions{identities: map[string]trust.SessionIdentity{}, revoked: map[string]bool{}},
		OrgSnapshots: &fakeSnapshots{version: 12},
		Audit:        &recordingAudit{},
		Protected:    func(r *http.Request) bool { return r.URL.Path == "/protected" },
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	forgetful := resolver.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	forgetful.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 from the middleware", rr.Code)
	}
	if served {
		t.Fatal("the forgetful handler ran on an unauthenticated protected request")
	}
	if body := strings.TrimSpace(rr.Body.String()); body != `{"error":"request_failed"}` {
		t.Fatalf("middleware body=%q want the uniform request_failed body", body)
	}
}

func TestTrustedContextResolverRequiresTenant(t *testing.T) {
	t.Parallel()
	if _, err := trust.NewResolver(trust.ResolverConfig{}); err == nil {
		t.Fatal("resolver without a tenant must be refused")
	}
	if _, err := trust.NewResolver(trust.ResolverConfig{TenantRef: " padded "}); err == nil {
		t.Fatal("non-canonical tenant must be refused")
	}
}

func TestTrustedContextHTTPStatusMapping(t *testing.T) {
	t.Parallel()
	cases := map[error]int{
		nil:                             http.StatusOK,
		trust.ErrUnauthenticated:        http.StatusUnauthorized,
		trust.ErrInvalidCredential:      http.StatusUnauthorized,
		trust.ErrConflictingCredentials: http.StatusUnauthorized,
		trust.ErrNoTrustedContext:       http.StatusUnauthorized,
		trust.ErrCredentialUnavailable:  http.StatusServiceUnavailable,
		trust.ErrForgedIdentity:         http.StatusBadRequest,
		errors.New("unknown"):           http.StatusUnauthorized,
	}
	for err, want := range cases {
		if got := trust.HTTPStatus(err); got != want {
			t.Fatalf("HTTPStatus(%v)=%d want %d", err, got, want)
		}
	}
}
