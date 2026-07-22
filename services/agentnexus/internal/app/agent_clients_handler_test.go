package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/agenttrust"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const agentClientsTenant = "ent-agentclients"

const testReleaseDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type agentClientsHarness struct {
	server   http.Handler
	registry *agenttrust.Service
	signing  map[string]any
}

// newAgentClientsHarness wires the handler behind the REAL trust middleware and
// the REAL registry service over an in-memory store. The tenant must come from
// the verified credential, so the test is deliberately unable to fake a context.
func newAgentClientsHarness(t *testing.T) *agentClientsHarness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	registry := agenttrust.NewService(agenttrust.NewMemoryStore())
	handler, err := newAgentClientsHandler(agentClientsTenant, registry, nil, nil)
	if err != nil {
		t.Fatalf("new agent clients handler: %v", err)
	}
	mux := http.NewServeMux()
	handler.register(mux)
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef: agentClientsTenant,
		Services:  fakeServiceCredentials{tenantRef: agentClientsTenant, clientRef: "agentatlas"},
		Sessions:  agentClientsSessions{},
		// A browser session resolves fully (including its sealed org snapshot) so
		// the refusal below is the handler's service-credential rule, not an
		// incidental failure to resolve the context.
		OrgSnapshots: agentClientsSessions{},
		Protected:    func(r *http.Request) bool { return agentClientsProtectedPath(r.URL.Path) },
	})
	if err != nil {
		t.Fatalf("new trust resolver: %v", err)
	}
	return &agentClientsHarness{
		server:   resolver.Middleware(mux),
		registry: registry,
		signing: map[string]any{
			"key_id":     "release-key-1",
			"algorithm":  "ed25519",
			"public_key": base64.StdEncoding.EncodeToString(public),
			"private":    private,
		},
	}
}

// agentClientsSessions lets the suite present a browser session so the
// service-credential-only rule is provable rather than assumed.
type agentClientsSessions struct{}

func (agentClientsSessions) VerifyBrowserSession(_ context.Context, token string) (trust.SessionIdentity, error) {
	if token != "browser-session-token" {
		return trust.SessionIdentity{}, trust.ErrCredentialRejected
	}
	return trust.SessionIdentity{TenantRef: agentClientsTenant, PrincipalRef: "user-1", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (agentClientsSessions) ResolveSealedOrgVersion(_ context.Context, _, _ string) (int64, error) {
	return 1, nil
}

func (h *agentClientsHarness) signingKey() map[string]any {
	return map[string]any{"key_id": h.signing["key_id"], "algorithm": h.signing["algorithm"], "public_key": h.signing["public_key"]}
}

// manifestSignature signs the release-manifest digest STRING, which is the
// preimage VerifyBuildManifestSignature defines.
func (h *agentClientsHarness) manifestSignature(digest string) map[string]any {
	signature := ed25519.Sign(h.signing["private"].(ed25519.PrivateKey), []byte(digest))
	return map[string]any{
		"algorithm": "ed25519",
		"key_id":    h.signing["key_id"],
		"value":     base64.StdEncoding.EncodeToString(signature),
	}
}

type agentClientsAuth int

const (
	authService agentClientsAuth = iota
	authNone
	authBrowserSession
)

func (h *agentClientsHarness) post(t *testing.T, path string, body map[string]any, auth agentClientsAuth) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	switch auth {
	case authService:
		req.SetBasicAuth("agentatlas", "s3cr3t")
	case authBrowserSession:
		req.AddCookie(&http.Cookie{Name: trust.DefaultSessionCookieName, Value: "browser-session-token"})
	}
	recorder := httptest.NewRecorder()
	h.server.ServeHTTP(recorder, req)
	return recorder
}

func (h *agentClientsHarness) registerClient(t *testing.T) string {
	t.Helper()
	recorder := h.post(t, "/v1/agent-clients", map[string]any{
		"request_id": "req-1", "publisher": "AstraClaw", "product": "agentatlas",
	}, authService)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		AgentClientRef string `json:"agent_client_ref"`
		Publisher      string `json:"publisher"`
		Product        string `json:"product"`
		Registered     bool   `json:"registered"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if !strings.HasPrefix(response.AgentClientRef, "agc_") || !response.Registered ||
		response.Publisher != "AstraClaw" || response.Product != "agentatlas" {
		t.Fatalf("register response does not match the published schema: %+v", response)
	}
	return response.AgentClientRef
}

func (h *agentClientsHarness) certifyBody() map[string]any {
	return map[string]any{
		"request_id":              "req-2",
		"trust_class":             "first_party_trusted",
		"version_range":           map[string]any{"min_inclusive": "1.0.0", "max_exclusive": "2.0.0"},
		"signing_key":             h.signingKey(),
		"release_manifest_digest": testReleaseDigest,
		"manifest_signature":      h.manifestSignature(testReleaseDigest),
		"capability_ceiling":      []string{"knowledge.suggest"},
		"ttl_seconds":             3600,
	}
}

// The defect this whole surface exists to end: three PUBLISHED operations that
// answered Go's bare 404 because no route matched. A 404 here means the
// regression is back, whatever the rest of the suite says.
func TestAgentClientOperationsAreRouted(t *testing.T) {
	h := newAgentClientsHarness(t)
	clientRef := h.registerClient(t)
	for _, path := range []string{
		"/v1/agent-clients",
		"/v1/agent-clients/" + clientRef + "/certifications",
		"/v1/agent-clients/" + clientRef + "/certifications/cert_x/revocations",
	} {
		recorder := h.post(t, path, map[string]any{"request_id": "req-probe"}, authService)
		if recorder.Code == http.StatusNotFound && !strings.Contains(path, "cert_x") {
			t.Fatalf("%s is published but no route matched (status 404)", path)
		}
		if body := recorder.Body.String(); strings.Contains(body, "page not found") {
			t.Fatalf("%s answered Go's bare not-found text rather than the JSON envelope: %s", path, body)
		}
	}
	// Every one of them must also be behind the ingress trust resolver; a
	// registered route that no middleware protects would authenticate nothing.
	for _, path := range []string{
		"/v1/agent-clients",
		"/v1/agent-clients/" + clientRef + "/certifications",
		"/v1/agent-clients/" + clientRef + "/certifications/cert_x/revocations",
	} {
		if !trustProtectedPath(path) {
			t.Fatalf("%s is not in the ingress-protected path set", path)
		}
	}
	// ...and the subtree match must not swallow unrelated paths.
	if trustProtectedPath("/v1/agent-clients-report") {
		t.Fatal("the protected-path match is a bare prefix; an unrelated path must keep answering 404")
	}
}

func TestAgentClientRegisterCertifyRevokeRoundTrip(t *testing.T) {
	h := newAgentClientsHarness(t)
	clientRef := h.registerClient(t)

	recorder := h.post(t, "/v1/agent-clients/"+clientRef+"/certifications", h.certifyBody(), authService)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("certify status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var certification struct {
		CertificationRef  string   `json:"certification_ref"`
		TrustClass        string   `json:"trust_class"`
		Revision          int64    `json:"revision"`
		Status            string   `json:"status"`
		CapabilityCeiling []string `json:"capability_ceiling"`
		ExpiresAt         string   `json:"expires_at"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &certification); err != nil {
		t.Fatalf("decode certify response: %v", err)
	}
	if !strings.HasPrefix(certification.CertificationRef, "cert_") || certification.TrustClass != "first_party_trusted" ||
		certification.Revision != 1 || certification.Status != "active" || certification.ExpiresAt == "" ||
		len(certification.CapabilityCeiling) != 1 || certification.CapabilityCeiling[0] != "knowledge.suggest" {
		t.Fatalf("certify response does not match the published schema: %+v", certification)
	}

	recorder = h.post(t, "/v1/agent-clients/"+clientRef+"/certifications/"+certification.CertificationRef+"/revocations",
		map[string]any{"request_id": "req-3", "reason": "signing key compromised"}, authService)
	if recorder.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var revocation struct {
		CertificationRef string `json:"certification_ref"`
		Status           string `json:"status"`
		RevokedAt        string `json:"revoked_at"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &revocation); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if revocation.CertificationRef != certification.CertificationRef || revocation.Status != "revoked" || revocation.RevokedAt == "" {
		t.Fatalf("revoke response does not match the published schema: %+v", revocation)
	}
}

func TestAgentClientOperationsRequireAFirstPartyServiceCredential(t *testing.T) {
	h := newAgentClientsHarness(t)
	body := map[string]any{"request_id": "req-1", "publisher": "AstraClaw", "product": "agentatlas"}
	for _, tc := range []struct {
		name string
		auth agentClientsAuth
	}{
		{"no credential", authNone},
		// Certifying a client is an act of the certifying AUTHORITY. A browser
		// session is a perfectly valid credential elsewhere in this gateway and
		// must still be refused here.
		{"browser session", authBrowserSession},
	} {
		recorder := h.post(t, "/v1/agent-clients", body, tc.auth)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status=%d want 401", tc.name, recorder.Code)
		}
	}
}

func TestAgentClientCertifyRejectsAnUnverifiableManifestSignature(t *testing.T) {
	h := newAgentClientsHarness(t)
	clientRef := h.registerClient(t)

	for _, tc := range []struct {
		name  string
		mutet func(map[string]any)
	}{
		{"signature over a different digest", func(body map[string]any) {
			body["manifest_signature"] = h.manifestSignature("sha256:" + strings.Repeat("a", 64))
		}},
		{"signature by an unrelated key", func(body map[string]any) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			signature := ed25519.Sign(other, []byte(testReleaseDigest))
			body["manifest_signature"] = map[string]any{
				"algorithm": "ed25519", "key_id": h.signing["key_id"],
				"value": base64.StdEncoding.EncodeToString(signature),
			}
		}},
		{"signature naming a key the certification does not bind", func(body map[string]any) {
			signature := h.manifestSignature(testReleaseDigest)
			signature["key_id"] = "some-other-key"
			body["manifest_signature"] = signature
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := h.certifyBody()
			tc.mutet(body)
			recorder := h.post(t, "/v1/agent-clients/"+clientRef+"/certifications", body, authService)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 body=%s", recorder.Code, recorder.Body.String())
			}
			// A rejected signature must leave NO certification behind: the
			// registry stores SignedBuildManifest as an attested fact, so a
			// revision written here would be an unearned attestation forever.
			if _, err := h.registry.ResolveClient(context.Background(), agentClientsTenant, clientRef); err != nil {
				t.Fatalf("resolve client: %v", err)
			}
			assessment, err := h.registry.Assess(context.Background(), agentClientsTenant, agenttrust.AssessRequest{
				Release: agenttrust.Release{
					Publisher: "AstraClaw", Product: "agentatlas", Version: "1.2.0",
					SigningKeyID: "release-key-1", ReleaseManifestDigest: testReleaseDigest,
				},
				Capability: "knowledge.suggest",
			})
			if err != nil {
				t.Fatalf("assess: %v", err)
			}
			if assessment.TrustClass != "untrusted" {
				t.Fatalf("a rejected signature left a usable certification: %+v", assessment)
			}
		})
	}
}

func TestAgentClientRequestsRejectUndeclaredMembers(t *testing.T) {
	h := newAgentClientsHarness(t)
	clientRef := h.registerClient(t)

	for _, tc := range []struct {
		name string
		path string
		body map[string]any
	}{
		{"unknown top-level member", "/v1/agent-clients",
			map[string]any{"request_id": "req-1", "publisher": "p", "product": "q", "unexpected": true}},
		// Trusted identity in a body is never a typo: the tenant is derived from
		// the verified credential and a body value never wins.
		{"forged tenant in the body", "/v1/agent-clients",
			map[string]any{"request_id": "req-1", "publisher": "p", "product": "q", "tenant_ref": "ent-someone-else"}},
		{"missing required member", "/v1/agent-clients",
			map[string]any{"request_id": "req-1", "publisher": "p"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if recorder := h.post(t, tc.path, tc.body, authService); recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}

	// The contract declares additionalProperties: false on the NESTED objects
	// too, so an unknown member of signing_key must be refused rather than
	// quietly dropped by a permissive decoder.
	body := h.certifyBody()
	key := h.signingKey()
	key["unexpected"] = "value"
	body["signing_key"] = key
	if recorder := h.post(t, "/v1/agent-clients/"+clientRef+"/certifications", body, authService); recorder.Code != http.StatusBadRequest {
		t.Fatalf("nested unknown member status=%d want 400 body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAgentClientCertifyRejectsAnUnknownClientHandle(t *testing.T) {
	h := newAgentClientsHarness(t)
	recorder := h.post(t, "/v1/agent-clients/agc_doesnotexist000000/certifications", h.certifyBody(), authService)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", recorder.Code, recorder.Body.String())
	}
}

// A certification is addressed UNDER a client. Revoking one client's revision
// through another client's path would make the URL's lineage decorative.
func TestAgentClientRevokeRejectsACertificationOfAnotherClient(t *testing.T) {
	h := newAgentClientsHarness(t)
	firstRef := h.registerClient(t)
	recorder := h.post(t, "/v1/agent-clients/"+firstRef+"/certifications", h.certifyBody(), authService)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("certify status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var certification struct {
		CertificationRef string `json:"certification_ref"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &certification); err != nil {
		t.Fatalf("decode certify response: %v", err)
	}

	other := h.post(t, "/v1/agent-clients", map[string]any{
		"request_id": "req-9", "publisher": "OtherPublisher", "product": "other-product",
	}, authService)
	var otherClient struct {
		AgentClientRef string `json:"agent_client_ref"`
	}
	if err := json.Unmarshal(other.Body.Bytes(), &otherClient); err != nil {
		t.Fatalf("decode second register response: %v", err)
	}

	recorder = h.post(t, "/v1/agent-clients/"+otherClient.AgentClientRef+"/certifications/"+certification.CertificationRef+"/revocations",
		map[string]any{"request_id": "req-10", "reason": "not mine to revoke"}, authService)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("cross-client revocation status=%d want 404 body=%s", recorder.Code, recorder.Body.String())
	}
}
