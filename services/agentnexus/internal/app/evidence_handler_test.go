package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// Canaries: internal connector topology and sensitive business content. The
// connector canary may NEVER appear in anything the gateway emits; the content
// canary may appear ONLY inside an allowed read's data envelope.
const (
	gatewayConnectorCanary = "connector-instance-GW-SECRET-77/api/v1/docs"
	gatewayContentCanary   = "GW-CANARY-SENSITIVE-DOC-BODY-42aa"
	gatewayDataClass       = "kb.articles"
	gatewayPurpose         = "case-investigation"
)

// gatewayEvidenceAudit adapts the evidence authorization-lineage port for the
// handler tests.
type gatewayEvidenceAudit struct {
	mu     sync.Mutex
	events []evidence.AuditEvent
	n      int
}

func (g *gatewayEvidenceAudit) AppendEvidenceAudit(_ context.Context, event evidence.AuditEvent) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	g.events = append(g.events, event)
	return fmt.Sprintf("audit_gw_%08d", g.n), nil
}

func (g *gatewayEvidenceAudit) payload(t *testing.T) string {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	raw, err := json.Marshal(g.events)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// newGatewayEvidenceService builds a real evidence service over in-memory
// state, seeded so the ent-1/user-1 harness principal (org version 12, suggest
// membership on root) may locate and read the gateway data class.
func newGatewayEvidenceService(t *testing.T, source policy.SnapshotSource, records []evidence.Record) (*evidence.Service, *gatewayEvidenceAudit) {
	t.Helper()
	audit := &gatewayEvidenceAudit{}
	contentSource := evidence.NewMemoryContentSource()
	svc := evidence.NewService(
		evidence.NewMemoryStore(),
		evidence.NewMemoryObjectStore(),
		evidence.StaticKeyProvider{Material: evidence.KeyMaterial{Ref: "test-key-gateway", Key: bytes.Repeat([]byte{0x24}, 32)}},
		contentSource,
		policy.NewCapabilityEvaluator(source),
		audit,
	)
	if _, err := svc.RegisterSourceBinding(context.Background(), evidence.SourceBinding{
		TenantRef:         "ent-1",
		DataClass:         gatewayDataClass,
		SourceRef:         gatewayConnectorCanary,
		SourceVersion:     5,
		AccessCapability:  "knowledge.suggest",
		SourceCapability:  "connector.docs.read",
		ResourceType:      "knowledge",
		ResourceID:        "kb-space",
		CachedReadAllowed: true,
	}); err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	if records == nil {
		records = []evidence.Record{
			{"title": "Doc A", "body": gatewayContentCanary},
			{"title": "Doc B", "body": "plain"},
		}
	}
	contentSource.Seed(gatewayConnectorCanary, records)
	return svc, audit
}

// newEvidenceTestRouter mirrors the production chain: mux + evidence handler +
// trust resolver middleware + request deadline (the authorization_test.go
// convention).
func newEvidenceTestRouter(t *testing.T, sessions browserSessionResolver, service EvidenceService, audit BrowserAuditSink) http.Handler {
	t.Helper()
	handler, err := newEvidenceHandler("ent-1", service, audit)
	if err != nil {
		t.Fatal(err)
	}
	mux := newGatewayAPIMux("gateway-api", "test")
	handler.register(mux)
	resolver := newTestTrustResolver(t, sessions, nil, authorizationPolicySource(), audit)
	return browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second)
}

func evidenceLocateBody(dataClass, purpose string, maxResults int) string {
	constraints := ""
	if maxResults > 0 {
		constraints = fmt.Sprintf(`,"constraints":{"max_results":%d}`, maxResults)
	}
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{"request_id":"req-locate-1","trace_id":"trace-1","data_needs":[{"need_id":"n1","data_class":"%s","purpose":"%s"%s}],"purpose":"%s","expires_at":"%s"}`,
		dataClass, purpose, constraints, purpose, expires)
}

func evidenceReadBody(businessContextRef, evidenceRef, purpose string, maxResults int) string {
	constraints := ""
	if maxResults > 0 {
		constraints = fmt.Sprintf(`,"constraints":{"max_results":%d}`, maxResults)
	}
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{"request_id":"req-read-1","business_context_ref":"%s","evidence_ref":"%s","purpose":"%s"%s,"expires_at":"%s"}`,
		businessContextRef, evidenceRef, purpose, constraints, expires)
}

func postEvidence(t *testing.T, router http.Handler, path, body string, decorate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if decorate != nil {
		decorate(req)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func decodeEvidenceJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", rr.Body.String(), err)
	}
	return payload
}

func TestEvidenceRuntimePathsAreTrustProtected(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/v1/runtime/locate", "/v1/runtime/read"} {
		if !trustProtectedPath(path) {
			t.Errorf("%s must be a trust-protected runtime path", path)
		}
	}

	svc, _ := newGatewayEvidenceService(t, authorizationPolicySource(), nil)
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	// Unauthenticated requests never reach the handler.
	for _, path := range []string{"/v1/runtime/locate", "/v1/runtime/read"} {
		rr := postEvidence(t, router, path, evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s without credentials: status=%d want=401 body=%s", path, rr.Code, rr.Body.String())
		}
	}
}

func TestSemanticReadFlowsThroughGatewayWithCacheHonesty(t *testing.T) {
	t.Parallel()
	svc, evidenceAudit := newGatewayEvidenceService(t, authorizationPolicySource(), nil)
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	located := postEvidence(t, router, "/v1/runtime/locate", evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if located.Code != http.StatusOK {
		t.Fatalf("locate status=%d body=%s", located.Code, located.Body.String())
	}
	if located.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("locate must be no-store: %v", located.Header())
	}
	locatePayload := decodeEvidenceJSON(t, located)
	businessContextRef, _ := locatePayload["business_context_ref"].(string)
	handles, _ := locatePayload["evidence"].([]any)
	if !strings.HasPrefix(businessContextRef, "wc_") || len(handles) != 1 {
		t.Fatalf("locate payload = %s", located.Body.String())
	}
	handle, _ := handles[0].(map[string]any)
	evidenceRef, _ := handle["evidence_ref"].(string)
	if !strings.HasPrefix(evidenceRef, "evd_") {
		t.Fatalf("evidence_ref = %q, want opaque evd_ handle", evidenceRef)
	}

	read := postEvidence(t, router, "/v1/runtime/read", evidenceReadBody(businessContextRef, evidenceRef, gatewayPurpose, 0), addAuthorizationSession)
	if read.Code != http.StatusOK {
		t.Fatalf("read status=%d body=%s", read.Code, read.Body.String())
	}
	payload := decodeEvidenceJSON(t, read)
	if payload["decision"] != "allow" {
		t.Fatalf("read decision = %v body=%s", payload["decision"], read.Body.String())
	}

	// Cache honesty is schema-visible: source version, as-of time and the
	// explicit served-from-cache marker ride ON the response, never as prose.
	if version, ok := payload["source_version"].(float64); !ok || int64(version) != 5 {
		t.Fatalf("source_version = %v, want 5", payload["source_version"])
	}
	if served, ok := payload["served_from_cache"].(bool); !ok || !served {
		t.Fatalf("served_from_cache = %v, want explicit true", payload["served_from_cache"])
	}
	asOf, _ := payload["as_of"].(string)
	if _, err := time.Parse(time.RFC3339, asOf); err != nil {
		t.Fatalf("as_of = %q is not an RFC3339 timestamp: %v", asOf, err)
	}
	data, _ := payload["data"].(map[string]any)
	records, _ := data["records"].([]any)
	if len(records) != 2 {
		t.Fatalf("read data = %s", read.Body.String())
	}
	if !strings.Contains(read.Body.String(), gatewayContentCanary) {
		t.Fatal("allowed read must deliver the business content to the caller")
	}

	// The public plane never carries connector topology.
	for _, body := range []string{located.Body.String(), read.Body.String()} {
		if strings.Contains(body, gatewayConnectorCanary) {
			t.Fatalf("gateway response leaks connector topology: %s", body)
		}
	}
	if lineage := evidenceAudit.payload(t); strings.Contains(lineage, gatewayContentCanary) || strings.Contains(lineage, gatewayConnectorCanary) {
		t.Fatalf("audit lineage leaks sensitive data: %s", lineage)
	}
}

func TestSemanticReadPaginatesThroughContinuationHandles(t *testing.T) {
	t.Parallel()
	svc, _ := newGatewayEvidenceService(t, authorizationPolicySource(), []evidence.Record{
		{"seq": "r1"}, {"seq": "r2"}, {"seq": "r3"},
	})
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	located := postEvidence(t, router, "/v1/runtime/locate", evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if located.Code != http.StatusOK {
		t.Fatalf("locate status=%d body=%s", located.Code, located.Body.String())
	}
	locatePayload := decodeEvidenceJSON(t, located)
	businessContextRef, _ := locatePayload["business_context_ref"].(string)
	handles, _ := locatePayload["evidence"].([]any)
	handle, _ := handles[0].(map[string]any)
	ref, _ := handle["evidence_ref"].(string)

	// Page 1: bounded, explicit continuation marker.
	first := decodeEvidenceJSON(t, postEvidence(t, router, "/v1/runtime/read", evidenceReadBody(businessContextRef, ref, gatewayPurpose, 2), addAuthorizationSession))
	continuation, _ := first["continuation_ref"].(string)
	if first["decision"] != "allow" || !strings.HasPrefix(continuation, "evd_") {
		t.Fatalf("bounded first page must carry an explicit continuation handle: %+v", first)
	}
	firstData, _ := first["data"].(map[string]any)
	firstRecords, _ := firstData["records"].([]any)
	if len(firstRecords) != 2 {
		t.Fatalf("first page records = %d, want 2", len(firstRecords))
	}

	// Page 2: the continuation drains the remainder and terminates.
	second := decodeEvidenceJSON(t, postEvidence(t, router, "/v1/runtime/read", evidenceReadBody(businessContextRef, continuation, gatewayPurpose, 2), addAuthorizationSession))
	if second["decision"] != "allow" {
		t.Fatalf("continuation read = %+v", second)
	}
	if _, hasMore := second["continuation_ref"]; hasMore {
		t.Fatalf("final page must not carry a continuation marker: %+v", second)
	}
	secondData, _ := second["data"].(map[string]any)
	secondRecords, _ := secondData["records"].([]any)
	if len(secondRecords) != 1 {
		t.Fatalf("second page records = %d, want the 1 remaining record (never silent truncation)", len(secondRecords))
	}
}

func TestEvidenceGatewayRejectsForgedIdentityAndConnectorFields(t *testing.T) {
	t.Parallel()
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	needs := `[{"need_id":"n1","data_class":"kb.articles","purpose":"p"}]`
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "locate forged enterprise", path: "/v1/runtime/locate", body: `{"request_id":"r","data_needs":` + needs + `,"purpose":"p","expires_at":"` + expires + `","enterprise_id":"attacker"}`},
		{name: "locate forged actor", path: "/v1/runtime/locate", body: `{"request_id":"r","data_needs":` + needs + `,"purpose":"p","expires_at":"` + expires + `","actor_user_id":"victim"}`},
		{name: "locate connector selector", path: "/v1/runtime/locate", body: `{"request_id":"r","data_needs":` + needs + `,"purpose":"p","expires_at":"` + expires + `","connector_instance_id":"conn-7"}`},
		{name: "locate nested connector selector", path: "/v1/runtime/locate", body: `{"request_id":"r","data_needs":[{"need_id":"n1","data_class":"kb.articles","purpose":"p","connector_instance_id":"conn-7"}],"purpose":"p","expires_at":"` + expires + `"}`},
		{name: "locate caller org version", path: "/v1/runtime/locate", body: `{"request_id":"r","data_needs":` + needs + `,"purpose":"p","expires_at":"` + expires + `","org_version":12}`},
		{name: "locate legacy action input", path: "/v1/runtime/locate", body: `{"action":"read","input":{"q":1}}`},
		{name: "locate unknown member", path: "/v1/runtime/locate", body: `{"request_id":"r","data_needs":` + needs + `,"purpose":"p","expires_at":"` + expires + `","surprise":true}`},
		{name: "read forged enterprise", path: "/v1/runtime/read", body: `{"request_id":"r","business_context_ref":"wc_0000000000000001","evidence_ref":"evd_0000000000000001","purpose":"p","expires_at":"` + expires + `","enterprise_id":"attacker"}`},
		{name: "read connector selector", path: "/v1/runtime/read", body: `{"request_id":"r","business_context_ref":"wc_0000000000000001","evidence_ref":"evd_0000000000000001","purpose":"p","expires_at":"` + expires + `","connector_instance_id":"conn-7"}`},
		{name: "read non-opaque evidence ref", path: "/v1/runtime/read", body: `{"request_id":"r","business_context_ref":"wc_0000000000000001","evidence_ref":"postgres://db/table","purpose":"p","expires_at":"` + expires + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc, _ := newGatewayEvidenceService(t, authorizationPolicySource(), nil)
			audit := &recordingTrustAudit{}
			router := newEvidenceTestRouter(t, validSessionStub(), svc, audit)
			rr := postEvidence(t, router, test.path, test.body, addAuthorizationSession)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want=400 body=%s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "conn-7") || strings.Contains(rr.Body.String(), "postgres://") {
				t.Fatalf("rejection echoes caller-supplied topology: %s", rr.Body.String())
			}
		})
	}

	// Wrong media type fails before any decode.
	svc, _ := newGatewayEvidenceService(t, authorizationPolicySource(), nil)
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})
	req := httptest.NewRequest(http.MethodPost, "/v1/runtime/locate", strings.NewReader(evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0)))
	req.Header.Set("Content-Type", "text/plain")
	addAuthorizationSession(req)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong media type status=%d want=415", rr.Code)
	}
}

// TestEvidenceGatewayBoundsRequestBodySize proves the request size bound: an
// over-limit body is rejected with the same fixed 400 envelope the other
// runtime handlers use for oversized input (authorization/audit-evidence
// convention; the payload is never echoed).
func TestEvidenceGatewayBoundsRequestBodySize(t *testing.T) {
	t.Parallel()
	svc, _ := newGatewayEvidenceService(t, authorizationPolicySource(), nil)
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})
	oversized := `{"request_id":"` + strings.Repeat("x", maxEvidenceRequestBytes) + `"}`
	for _, path := range []string{"/v1/runtime/locate", "/v1/runtime/read"} {
		rr := postEvidence(t, router, path, oversized, addAuthorizationSession)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s oversized body status=%d want=400 body=%s", path, rr.Code, rr.Body.String())
		}
		var payload map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil || payload["error"] != "invalid_request" {
			t.Fatalf("%s oversized body envelope=%s", path, rr.Body.String())
		}
	}
}

func TestEvidenceGatewayDenialsAreOpaqueAndFailClosed(t *testing.T) {
	t.Parallel()
	svc, _ := newGatewayEvidenceService(t, authorizationPolicySource(), nil)
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	// AstraClaw origin: the trusted context carries no connector capability,
	// so the connector-backed data class is denied with a generic envelope.
	astraLocate := postEvidence(t, router, "/v1/runtime/locate", evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), func(req *http.Request) {
		addAuthorizationSession(req)
		req.Header.Set("X-Agent-Origin", "astraclaw")
	})
	if astraLocate.Code != http.StatusForbidden {
		t.Fatalf("AstraClaw connector-backed locate status=%d want=403 body=%s", astraLocate.Code, astraLocate.Body.String())
	}
	if body := astraLocate.Body.String(); strings.Contains(body, gatewayConnectorCanary) || strings.Contains(body, "connector") {
		t.Fatalf("denial envelope must stay opaque: %s", body)
	}

	// A revoked handle reads as a typed deny decision, never stale data.
	located := postEvidence(t, router, "/v1/runtime/locate", evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if located.Code != http.StatusOK {
		t.Fatalf("locate status=%d body=%s", located.Code, located.Body.String())
	}
	locatePayload := decodeEvidenceJSON(t, located)
	businessContextRef, _ := locatePayload["business_context_ref"].(string)
	handles, _ := locatePayload["evidence"].([]any)
	handle, _ := handles[0].(map[string]any)
	ref, _ := handle["evidence_ref"].(string)
	if err := svc.RevokeAuthorization(context.Background(), "ent-1", ref, "operator revoked"); err != nil {
		t.Fatalf("RevokeAuthorization: %v", err)
	}
	read := postEvidence(t, router, "/v1/runtime/read", evidenceReadBody(businessContextRef, ref, gatewayPurpose, 0), addAuthorizationSession)
	if read.Code != http.StatusOK {
		t.Fatalf("revoked read status=%d body=%s", read.Code, read.Body.String())
	}
	payload := decodeEvidenceJSON(t, read)
	if payload["decision"] != "deny" {
		t.Fatalf("revoked read decision = %v", payload["decision"])
	}
	if _, leaked := payload["data"]; leaked {
		t.Fatalf("revoked read must not carry data: %s", read.Body.String())
	}
	if strings.Contains(read.Body.String(), gatewayContentCanary) {
		t.Fatalf("revoked read leaks content: %s", read.Body.String())
	}
}

// TestEvidenceGatewayWiringRegistersRuntimeEndpoints proves the PRODUCTION
// router (NewGatewayAPIRouterWithDependencies via the browser harness) wires
// the evidence endpoints behind the ingress trust guard.
func TestEvidenceGatewayWiringRegistersRuntimeEndpoints(t *testing.T) {
	t.Parallel()
	h := newBrowserHarness(t)
	token, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}

	// Unauthenticated: guarded, registered (never a silent 404).
	unauth := postEvidence(t, h.router, "/v1/runtime/locate", evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), nil)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated locate through production router status=%d want=401 body=%s", unauth.Code, unauth.Body.String())
	}

	// Authenticated: the full locate -> read flow works end to end.
	located := postEvidence(t, h.router, "/v1/runtime/locate", evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: token})
	})
	if located.Code != http.StatusOK {
		t.Fatalf("locate through production router status=%d body=%s", located.Code, located.Body.String())
	}
	locatePayload := decodeEvidenceJSON(t, located)
	businessContextRef, _ := locatePayload["business_context_ref"].(string)
	handles, _ := locatePayload["evidence"].([]any)
	if len(handles) != 1 {
		t.Fatalf("locate payload = %s", located.Body.String())
	}
	handle, _ := handles[0].(map[string]any)
	ref, _ := handle["evidence_ref"].(string)
	read := postEvidence(t, h.router, "/v1/runtime/read", evidenceReadBody(businessContextRef, ref, gatewayPurpose, 0), func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: token})
	})
	if read.Code != http.StatusOK {
		t.Fatalf("read through production router status=%d body=%s", read.Code, read.Body.String())
	}
	payload := decodeEvidenceJSON(t, read)
	if payload["decision"] != "allow" || payload["served_from_cache"] != true {
		t.Fatalf("production read = %s", read.Body.String())
	}
	if strings.Contains(located.Body.String(), gatewayConnectorCanary) || strings.Contains(read.Body.String(), gatewayConnectorCanary) {
		t.Fatal("production plane leaks connector topology")
	}
}
