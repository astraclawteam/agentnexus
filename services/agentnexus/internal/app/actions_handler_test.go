package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const (
	actWorkCase = "wc_actionhandler0001"
	actPlanRef  = "apl_actionhandler0001"
)

func newActionsRouter(t *testing.T, sessions browserSessionResolver, service ActionsService) http.Handler {
	t.Helper()
	audit := &recordingTrustAudit{}
	mux := newGatewayAPIMux("gateway-api", "test")
	if service != nil {
		handler, err := newActionsHandler("ent-1", service, audit, nil)
		if err != nil {
			t.Fatal(err)
		}
		handler.register(mux)
	}
	cfg := trust.ResolverConfig{
		TenantRef:    "ent-1",
		OrgSnapshots: sealedOrgVersionResolver{source: approvalTransportVersionSource{}},
		Audit:        browserTrustAuditSink{sink: audit},
		Protected:    func(r *http.Request) bool { return trustProtectedPath(r.URL.Path) },
	}
	if sessions != nil {
		cfg.Sessions = browserSessionTrustVerifier{sessions: sessions}
	}
	resolver, err := trust.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return browserRequestDeadline(resolver.Middleware(browserResponseHeaders(mux)), time.Second)
}

func actionRequestBody(t *testing.T, withCompensation bool) (string, string) {
	t.Helper()
	params, hash, err := runtime.BuildParameters(map[string]any{"amount": 100})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	body := map[string]any{
		"request_id":           "req-act-1",
		"business_context_ref": actWorkCase,
		"capability":           "erp.purchase_order.approve",
		"parameters":           json.RawMessage(params),
		"parameter_hash":       hash,
		"purpose":              "approve purchase order 42",
		"risk_decision": map[string]any{
			"decision_id":          "dec-1",
			"authority":            "agentatlas-risk",
			"risk_level":           "medium",
			"capability":           "erp.purchase_order.approve",
			"parameter_hash":       hash,
			"business_context_ref": actWorkCase,
			"issued_at":            now.Add(-time.Minute).Format(time.RFC3339),
			"expires_at":           now.Add(time.Hour).Format(time.RFC3339),
			"signature":            map[string]any{"algorithm": "ed25519", "key_id": "k1", "value": "c2ln"},
		},
		"idempotency_key":         "idem-actionhandler01",
		"expires_at":              now.Add(30 * time.Minute).Format(time.RFC3339),
		"expected_receipt_schema": "erp.receipt.v1",
	}
	if withCompensation {
		body["compensation_ref"] = "erp.purchase_order.void"
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload), hash
}

func directActionsPrincipal() runtime.PrincipalContext {
	now := time.Now().UTC()
	return runtime.PrincipalContext{
		TenantRef: "ent-1", PrincipalRef: "user-1", AgentClientRef: "agc_x", AgentReleaseRef: "rel",
		TrustClass: runtime.TrustFirstParty, OrgSnapshotRef: "org", VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func TestActionsPathsAreTrustProtected(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/v1/runtime/act",
		"/v1/runtime/actions/act_x/receipts",
		"/v1/runtime/actions/act_x/compensations",
		"/v1/runtime/receipts/rcp_x",
	} {
		if !trustProtectedPath(path) {
			t.Errorf("%s must be trust-protected", path)
		}
	}
}

func TestActionsRequestAndReceiptFlowThroughGateway(t *testing.T) {
	t.Parallel()
	store := actions.NewMemoryStore()
	// GA Task 0G: completion fails closed without a verifier, so wire a real
	// signed-receipt verifier and sign the connector receipt below.
	connectorPub, connectorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	connectorKeys := sdkaudit.NewKeySet(sdkaudit.SigningKey{KeyID: "connector-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: connectorPub, Status: sdkaudit.KeyActive})
	service, err := actions.NewService(store, actions.NewMemoryAuditSink(), actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(connectorKeys)))
	if err != nil {
		t.Fatal(err)
	}
	router := newActionsRouter(t, transportSession("ent-1"), service)

	body, hash := actionRequestBody(t, true)
	requested := transportRequest(t, router, http.MethodPost, "/v1/runtime/act", body, withTransportSessionCookie)
	if requested.Code != http.StatusOK {
		t.Fatalf("request status=%d body=%s", requested.Code, requested.Body.String())
	}
	var action struct {
		ActionRef     string `json:"action_ref"`
		Status        string `json:"status"`
		ParameterHash string `json:"parameter_hash"`
	}
	if err := json.Unmarshal(requested.Body.Bytes(), &action); err != nil {
		t.Fatal(err)
	}
	if action.Status != "requested" || action.ParameterHash != hash {
		t.Fatalf("action = %+v", action)
	}

	// Advance the action to executing through the internal transitions (grant and
	// dispatch are server-driven, not part of the Agent-facing HTTP surface).
	ctx := context.Background()
	principal := directActionsPrincipal()
	if _, err := service.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := service.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if _, err := service.MarkExecuting(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}

	result, _, _ := runtime.BuildParameters(map[string]any{"po_id": "po-1"})
	resultHash := runtime.HashParameters(result)
	receipt := runtime.ActionReceipt{
		ReceiptRef: "rcp_actionhandler0001", ActionRef: action.ActionRef, Status: runtime.StatusSucceeded,
		Capability: "erp.purchase_order.approve", ParameterHash: hash, ReceiptSchema: "erp.receipt.v1",
		Result: result, ResultHash: resultHash, IssuedAt: time.Now().UTC(),
	}
	canonical, err := actions.CanonicalActionReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = &runtime.Signature{Algorithm: runtime.SignatureAlgorithmEd25519, KeyID: "connector-1", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(connectorPriv, canonical))}
	ingestReq, err := json.Marshal(struct {
		RequestID string                `json:"request_id"`
		ResultID  string                `json:"result_id"`
		Receipt   runtime.ActionReceipt `json:"receipt"`
	}{"req-ingest-1", "connector-1", receipt})
	if err != nil {
		t.Fatal(err)
	}
	receiptBody := string(ingestReq)
	ingested := transportRequest(t, router, http.MethodPost, "/v1/runtime/actions/"+action.ActionRef+"/receipts", receiptBody, withTransportSessionCookie)
	if ingested.Code != http.StatusOK || !strings.Contains(ingested.Body.String(), `"succeeded"`) {
		t.Fatalf("ingest status=%d body=%s", ingested.Code, ingested.Body.String())
	}
	// Redelivered result (same result_id) is idempotent.
	redelivered := transportRequest(t, router, http.MethodPost, "/v1/runtime/actions/"+action.ActionRef+"/receipts", receiptBody, withTransportSessionCookie)
	if redelivered.Code != http.StatusOK || !strings.Contains(redelivered.Body.String(), `"succeeded"`) {
		t.Fatalf("redelivered ingest status=%d body=%s", redelivered.Code, redelivered.Body.String())
	}

	fetch := transportRequest(t, router, http.MethodGet, "/v1/runtime/receipts/rcp_actionhandler0001", "", withTransportSessionCookie)
	if fetch.Code != http.StatusOK || !strings.Contains(fetch.Body.String(), action.ActionRef) {
		t.Fatalf("receipt fetch status=%d body=%s", fetch.Code, fetch.Body.String())
	}

	compensate := transportRequest(t, router, http.MethodPost, "/v1/runtime/actions/"+action.ActionRef+"/compensations", `{"request_id":"req-comp-1"}`, withTransportSessionCookie)
	if compensate.Code != http.StatusOK {
		t.Fatalf("compensate status=%d body=%s", compensate.Code, compensate.Body.String())
	}
	var compensation struct {
		ActionRef  string `json:"action_ref"`
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal(compensate.Body.Bytes(), &compensation); err != nil {
		t.Fatal(err)
	}
	if compensation.ActionRef == action.ActionRef || compensation.Capability != "erp.purchase_order.void" {
		t.Fatalf("compensation = %+v, want a new action of the declared compensation capability", compensation)
	}
}

func TestActionsGatewayRejectsForgedIdentityAndCrossTenant(t *testing.T) {
	t.Parallel()
	store := actions.NewMemoryStore()
	service, err := actions.NewService(store, actions.NewMemoryAuditSink())
	if err != nil {
		t.Fatal(err)
	}
	router := newActionsRouter(t, transportSession("ent-1"), service)
	body, _ := actionRequestBody(t, false)

	forged := strings.Replace(body, `"request_id"`, `"enterprise_id":"ent-forged","request_id"`, 1)
	if rr := transportRequest(t, router, http.MethodPost, "/v1/runtime/act", forged, withTransportSessionCookie); rr.Code != http.StatusBadRequest {
		t.Fatalf("forged identity status=%d body=%s", rr.Code, rr.Body.String())
	}
	unknown := strings.Replace(body, `"request_id"`, `"reviewer":"x","request_id"`, 1)
	if rr := transportRequest(t, router, http.MethodPost, "/v1/runtime/act", unknown, withTransportSessionCookie); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown member status=%d body=%s", rr.Code, rr.Body.String())
	}
	cross := transportRequest(t, router, http.MethodPost, "/v1/runtime/act", body, func(req *http.Request) {})
	if cross.Code == http.StatusOK {
		t.Fatalf("unauthenticated request unexpectedly succeeded: %d", cross.Code)
	}
}

func TestActionsGatewayUnwiredLeavesSurfaceUnregistered(t *testing.T) {
	t.Parallel()
	router := newActionsRouter(t, transportSession("ent-1"), nil)
	body, _ := actionRequestBody(t, false)
	if rr := transportRequest(t, router, http.MethodPost, "/v1/runtime/act", body, withTransportSessionCookie); rr.Code != http.StatusNotFound {
		t.Fatalf("unwired action surface status=%d, want 404", rr.Code)
	}
}
