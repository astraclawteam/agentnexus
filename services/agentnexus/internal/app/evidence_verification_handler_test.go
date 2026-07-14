package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// GA Task 0D amendment: gateway coverage of verification-purpose reads. The
// declared binding rides the strict-decoded request; observation authority,
// source version, observed-at and freshness stay server-derived; an allowed
// verification read emits the signed observation_receipt and ordinary reads
// keep their exact prior response shape.
const (
	gatewayVerifyActionRef = "act_0123456789abcdef"
	gatewayVerifyPost      = "post-doc-refreshed"
	gatewayVerifyNeed      = "verify-doc-refreshed"
)

func gatewayVerifyParameterHash() string {
	return runtime.HashParameters([]byte(`{"doc":"D-77"}`))
}

// newGatewayVerificationService builds the evidence service with a REAL
// ed25519 observation signer and an authority-declared registry binding.
func newGatewayVerificationService(t *testing.T, source policy.SnapshotSource) (*evidence.Service, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := evidence.NewEd25519ObservationSigner("obs-key-gateway", priv)
	if err != nil {
		t.Fatalf("NewEd25519ObservationSigner: %v", err)
	}
	contentSource := evidence.NewMemoryContentSource()
	svc := evidence.NewService(
		evidence.NewMemoryStore(),
		evidence.NewMemoryObjectStore(),
		evidence.StaticKeyProvider{Material: evidence.KeyMaterial{Ref: "test-key-gateway", Key: bytes.Repeat([]byte{0x24}, 32)}},
		contentSource,
		policy.NewCapabilityEvaluator(source),
		&gatewayEvidenceAudit{},
		evidence.WithObservationSigner(signer),
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
		AuthorityTier:     evidence.AuthorityTierAuthoritativeReplica,
		FreshnessBound:    10 * time.Minute,
	}); err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	contentSource.Seed(gatewayConnectorCanary, []evidence.Record{
		{"title": "Doc A", "review_state": "refreshed"},
	})
	return svc, pub
}

func verificationBindingJSON() string {
	return fmt.Sprintf(`{"action_ref":"%s","parameter_hash":"%s","postcondition_id":"%s","verification_need_id":"%s","data_class":"%s"}`,
		gatewayVerifyActionRef, gatewayVerifyParameterHash(), gatewayVerifyPost, gatewayVerifyNeed, gatewayDataClass)
}

func verificationReadBody(businessContextRef, evidenceRef string) string {
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{"request_id":"req-verify-1","business_context_ref":"%s","evidence_ref":"%s","purpose":"postcondition_verification","verification_binding":%s,"expires_at":"%s"}`,
		businessContextRef, evidenceRef, verificationBindingJSON(), expires)
}

// locateForVerification stages the gateway data class under the frozen
// verification purpose and returns (business_context_ref, evidence_ref).
func locateForVerification(t *testing.T, router http.Handler) (string, string) {
	t.Helper()
	located := postEvidence(t, router, "/v1/runtime/locate",
		evidenceLocateBody(gatewayDataClass, "postcondition_verification", 0), addAuthorizationSession)
	if located.Code != http.StatusOK {
		t.Fatalf("locate status=%d body=%s", located.Code, located.Body.String())
	}
	payload := decodeEvidenceJSON(t, located)
	businessContextRef, _ := payload["business_context_ref"].(string)
	handles, _ := payload["evidence"].([]any)
	if len(handles) != 1 {
		t.Fatalf("locate payload = %s", located.Body.String())
	}
	handle, _ := handles[0].(map[string]any)
	evidenceRef, _ := handle["evidence_ref"].(string)
	return businessContextRef, evidenceRef
}

func TestVerificationReadFlowsThroughGatewaySigned(t *testing.T) {
	t.Parallel()
	svc, pub := newGatewayVerificationService(t, authorizationPolicySource())
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	businessContextRef, evidenceRef := locateForVerification(t, router)
	read := postEvidence(t, router, "/v1/runtime/read", verificationReadBody(businessContextRef, evidenceRef), addAuthorizationSession)
	if read.Code != http.StatusOK {
		t.Fatalf("verification read status=%d body=%s", read.Code, read.Body.String())
	}
	payload := decodeEvidenceJSON(t, read)
	if payload["decision"] != "allow" {
		t.Fatalf("decision = %v body=%s", payload["decision"], read.Body.String())
	}
	receiptPayload, ok := payload["observation_receipt"].(map[string]any)
	if !ok {
		t.Fatalf("allowed verification read must emit observation_receipt: %s", read.Body.String())
	}

	// The emitted receipt is the frozen public type: decode through the SDK
	// shape, validate canonically and verify the REAL signature.
	raw, err := json.Marshal(receiptPayload)
	if err != nil {
		t.Fatal(err)
	}
	var receipt runtime.ObservationReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatalf("observation_receipt does not decode as runtime.ObservationReceipt: %v", err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("emitted observation receipt must pass Validate, got %v", err)
	}
	if !strings.HasPrefix(receipt.ObservationRef, "obs_") {
		t.Errorf("observation_ref = %q, want opaque obs_ handle", receipt.ObservationRef)
	}
	if receipt.ActionRef != gatewayVerifyActionRef || receipt.ParameterHash != gatewayVerifyParameterHash() {
		t.Errorf("receipt action binding = %q %q, want the declared originals", receipt.ActionRef, receipt.ParameterHash)
	}
	if receipt.PostconditionID != gatewayVerifyPost || receipt.VerificationNeedID != gatewayVerifyNeed {
		t.Errorf("receipt need binding = %q %q, want the declared pair", receipt.PostconditionID, receipt.VerificationNeedID)
	}
	if receipt.Source != gatewayDataClass || receipt.SourceVersion != 5 {
		t.Errorf("receipt source binding = %q v%d, want %q v5", receipt.Source, receipt.SourceVersion, gatewayDataClass)
	}
	if receipt.Authority != "authoritative_replica" {
		t.Errorf("receipt authority = %q, want the registry-derived tier", receipt.Authority)
	}
	if receipt.EvidenceRef != evidenceRef {
		t.Errorf("receipt evidence_ref = %q, want the read handle %q", receipt.EvidenceRef, evidenceRef)
	}
	canonical, err := evidence.CanonicalObservationReceipt(receipt)
	if err != nil {
		t.Fatalf("CanonicalObservationReceipt: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(receipt.Signature.Value)
	if err != nil {
		t.Fatalf("signature value is not base64: %v", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("gateway-emitted receipt signature must verify over the canonical bytes")
	}

	// Cache honesty rides the same response: the receipt's observed-at is
	// the staged as_of instant, never the response instant.
	asOf, _ := payload["as_of"].(string)
	stagedAt, err := time.Parse(time.RFC3339Nano, asOf)
	if err != nil {
		t.Fatalf("as_of = %q: %v", asOf, err)
	}
	if !receipt.ObservedAt.Equal(stagedAt) {
		t.Errorf("observed_at = %v, want the staged as_of %v", receipt.ObservedAt, stagedAt)
	}

	// No topology, ever.
	if strings.Contains(read.Body.String(), gatewayConnectorCanary) {
		t.Fatalf("gateway response leaks connector topology: %s", read.Body.String())
	}

	// Ordinary reads keep the exact prior response shape: no
	// observation_receipt key at all.
	ordinaryLocate := postEvidence(t, router, "/v1/runtime/locate", evidenceLocateBody(gatewayDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if ordinaryLocate.Code != http.StatusOK {
		t.Fatalf("ordinary locate status=%d body=%s", ordinaryLocate.Code, ordinaryLocate.Body.String())
	}
	ordinaryPayload := decodeEvidenceJSON(t, ordinaryLocate)
	ordinaryContext, _ := ordinaryPayload["business_context_ref"].(string)
	ordinaryHandles, _ := ordinaryPayload["evidence"].([]any)
	ordinaryHandle, _ := ordinaryHandles[0].(map[string]any)
	ordinaryRef, _ := ordinaryHandle["evidence_ref"].(string)
	ordinaryRead := postEvidence(t, router, "/v1/runtime/read", evidenceReadBody(ordinaryContext, ordinaryRef, gatewayPurpose, 0), addAuthorizationSession)
	if ordinaryRead.Code != http.StatusOK {
		t.Fatalf("ordinary read status=%d body=%s", ordinaryRead.Code, ordinaryRead.Body.String())
	}
	if _, exists := decodeEvidenceJSON(t, ordinaryRead)["observation_receipt"]; exists {
		t.Fatalf("ordinary reads must not carry observation_receipt: %s", ordinaryRead.Body.String())
	}
}

func TestVerificationReadGatewayRejectsForgedObservationMetadata(t *testing.T) {
	t.Parallel()
	svc, _ := newGatewayVerificationService(t, authorizationPolicySource())
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})
	businessContextRef, evidenceRef := locateForVerification(t, router)

	canonical := verificationReadBody(businessContextRef, evidenceRef)
	cases := map[string]string{
		"authority inside the binding": strings.Replace(canonical,
			`"action_ref":"`+gatewayVerifyActionRef+`"`,
			`"action_ref":"`+gatewayVerifyActionRef+`","authority":"system_of_record"`, 1),
		"observed_at inside the binding": strings.Replace(canonical,
			`"action_ref":"`+gatewayVerifyActionRef+`"`,
			`"action_ref":"`+gatewayVerifyActionRef+`","observed_at":"2026-07-14T00:00:00Z"`, 1),
		"fresh_until on the envelope": strings.Replace(canonical,
			`"request_id":"req-verify-1"`,
			`"request_id":"req-verify-1","fresh_until":"2027-01-01T00:00:00Z"`, 1),
		"source_version on the envelope": strings.Replace(canonical,
			`"request_id":"req-verify-1"`,
			`"request_id":"req-verify-1","source_version":99`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if body == canonical {
				t.Fatal("forged fixture did not apply")
			}
			rr := postEvidence(t, router, "/v1/runtime/read", body, addAuthorizationSession)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("forged observation metadata: status=%d body=%s, want 400", rr.Code, rr.Body.String())
			}
			if payload := decodeEvidenceJSON(t, rr); payload["error"] != "invalid_request" {
				t.Fatalf("forged observation metadata envelope = %s, want fixed invalid_request", rr.Body.String())
			}
		})
	}

	t.Run("detached verification purpose", func(t *testing.T) {
		rr := postEvidence(t, router, "/v1/runtime/read",
			evidenceReadBody(businessContextRef, evidenceRef, "postcondition_verification", 0), addAuthorizationSession)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("verification purpose without a binding: status=%d body=%s, want 400", rr.Code, rr.Body.String())
		}
	})
	t.Run("detached binding", func(t *testing.T) {
		body := strings.Replace(canonical, `"purpose":"postcondition_verification"`, `"purpose":"`+gatewayPurpose+`"`, 1)
		rr := postEvidence(t, router, "/v1/runtime/read", body, addAuthorizationSession)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("binding without the verification purpose: status=%d body=%s, want 400", rr.Code, rr.Body.String())
		}
	})
}
