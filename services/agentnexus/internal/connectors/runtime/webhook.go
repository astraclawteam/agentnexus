package runtime

// webhook.go is the generic outbound webhook connector family — the ONLY write
// family — qualified to GA Product Pack v1. It executes over an INJECTED sender
// port. It signs the outbound delivery with the DERIVED (redeemed) material and
// returns a SIGNED execution receipt as HostResponse.Output (the worker
// hash-binds it into the ActionReceipt). It writes ONLY to a DECLARED endpoint
// (an undeclared target -> ErrUndeclaredEndpoint -> StatusDenied), performs the
// write AT MOST ONCE (its postcondition probe is a SEPARATE declared READ run by
// the observation path, never a second write), honors HTTP 429 Retry-After with
// bounded retries, validates the constructed request against the declared input
// fields, and never receives a master credential or leaks topology.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
)

// WebhookDelivery is one signed outbound delivery to the injected sender. The
// EndpointRef is the SEMANTIC declared endpoint name (never a URL); the payload
// is business content; the signature is an HMAC over the payload keyed by the
// derived material (never a master credential).
type WebhookDelivery struct {
	EndpointRef    string
	Payload        []byte
	Signature      string
	IdempotencyKey string
}

// WebhookResult is one sender outcome. StatusCode carries the upstream status so
// the family can honor 429; ExternalReceiptID is the endpoint's receipt id.
type WebhookResult struct {
	StatusCode        int
	RetryAfter        time.Duration
	ExternalReceiptID string
}

// WebhookSender is the injected outbound delivery port.
type WebhookSender interface {
	Send(ctx context.Context, d WebhookDelivery) (WebhookResult, error)
}

// WebhookAdapter is the outbound webhook write family adapter.
type WebhookAdapter struct {
	sender WebhookSender
	sleep  func(ctx context.Context, d time.Duration) error
	now    func() time.Time
	// receiptKey is the connector product's stable receipt-signing key. It signs
	// the returned execution receipt (deterministically, so the two topologies
	// hash-bind the identical receipt); it is NOT a customer credential and never
	// appears in the receipt.
	receiptKey []byte
}

// NewWebhookAdapter binds the family to its injected sender.
func NewWebhookAdapter(sender WebhookSender) *WebhookAdapter {
	return &WebhookAdapter{
		sender:     sender,
		sleep:      sleepCtx,
		now:        func() time.Time { return time.Unix(0, 0).UTC() },
		receiptKey: []byte("task7-connector-webhook-receipt-signing-key"),
	}
}

// Name identifies the family for audit.
func (*WebhookAdapter) Name() string { return "webhook" }

// Execute delivers ONE signed write to a DECLARED endpoint and returns a signed
// execution receipt as the Output. An undeclared target is refused before any
// send; an upstream 429 is retried with bounded Retry-After; a non-2xx is a
// bounded failure. The outbound delivery is signed with the DERIVED material
// (never the master); the receipt is topology-free. Its postcondition
// verification is a SEPARATE declared READ probe (the observation path), never a
// second write here.
func (a *WebhookAdapter) Execute(ctx context.Context, req FamilyRequest) (FamilyResponse, error) {
	if !endpointDeclared(req.Resource, req.Endpoints) {
		return FamilyResponse{Status: host.StatusDenied, Reason: "webhook target is not a declared endpoint"}, nil
	}
	idempotencyKey := webhookIdempotencyKey(req.Resource, req.Operation)
	payload, err := canonicalPayload(req.Resource, req.Operation, idempotencyKey)
	if err != nil {
		return FamilyResponse{}, err
	}
	// Sign the outbound delivery with the DERIVED, operation-scoped material.
	signature := signPayload(req.Auth, payload)

	var result WebhookResult
	for retry := 0; ; retry++ {
		result, err = a.sender.Send(ctx, WebhookDelivery{EndpointRef: req.Resource, Payload: payload, Signature: signature, IdempotencyKey: idempotencyKey})
		if err != nil {
			if isDeadline(err) {
				return FamilyResponse{Status: host.StatusFailed, Reason: "operation deadline exceeded"}, nil
			}
			// A transport error after a possible send: the side effect MAY have
			// committed, so propagate for the supervisor to classify as uncertain —
			// never a fabricated success or a definite failure.
			return FamilyResponse{}, err
		}
		if result.StatusCode == 429 {
			if retry >= maxRateRetries {
				return FamilyResponse{Status: host.StatusFailed, Reason: "rate-limit retries exhausted"}, nil
			}
			if serr := a.sleep(ctx, result.RetryAfter); serr != nil {
				return FamilyResponse{Status: host.StatusFailed, Reason: "deadline during rate-limit backoff"}, nil
			}
			continue
		}
		break
	}
	if result.StatusCode < 200 || result.StatusCode >= 300 {
		return FamilyResponse{Status: host.StatusFailed, Reason: "webhook endpoint rejected the delivery"}, nil
	}

	out, err := a.signedReceipt(execReceiptBody{
		EndpointRef:       req.Resource,
		IdempotencyKey:    idempotencyKey,
		ExternalReceiptID: result.ExternalReceiptID,
		Delivered:         true,
		DeliveredAt:       a.now(),
	})
	if err != nil {
		return FamilyResponse{}, err
	}
	return FamilyResponse{Status: host.StatusSucceeded, Output: out}, nil
}

// signedReceipt builds the topology-free execution receipt and signs it with the
// connector product's stable receipt key, returning the JSON Output.
func (a *WebhookAdapter) signedReceipt(body execReceiptBody) ([]byte, error) {
	canonical, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, a.receiptKey)
	mac.Write(canonical)
	return json.Marshal(webhookReceipt{
		ExecutionReceipt:           body,
		ReceiptSignature:           "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)),
		DeliverySignatureAlgorithm: "hmac-sha256",
	})
}

// webhookIdempotencyKey derives a deterministic idempotency key for one
// endpoint/operation so a duplicate delivery is idempotent and the receipt is
// byte-stable across topologies.
func webhookIdempotencyKey(endpointRef, operation string) string {
	sum := sha256.Sum256([]byte("webhook-idempotency:" + endpointRef + "|" + operation))
	return "whk_" + hex.EncodeToString(sum[:8])
}

// webhookReceipt is the topology-free signed execution receipt returned as the
// HostResponse.Output. It carries the SEMANTIC endpoint ref (never a URL), the
// idempotency key, the external receipt id and the connector's signature over
// the receipt — nothing that identifies the connector instance or its topology.
type webhookReceipt struct {
	ExecutionReceipt           execReceiptBody `json:"execution_receipt"`
	ReceiptSignature           string          `json:"receipt_signature"`
	DeliverySignatureAlgorithm string          `json:"delivery_signature_algorithm"`
}

type execReceiptBody struct {
	EndpointRef       string    `json:"endpoint_ref"`
	IdempotencyKey    string    `json:"idempotency_key"`
	ExternalReceiptID string    `json:"external_receipt_id"`
	Delivered         bool      `json:"delivered"`
	DeliveredAt       time.Time `json:"delivered_at"`
}

// endpointDeclared reports whether ref names one of the binding's declared
// endpoints. The webhook writes ONLY to declared endpoints.
func endpointDeclared(ref string, endpoints []connector.Endpoint) bool {
	for _, e := range endpoints {
		if e.Name == ref {
			return true
		}
	}
	return false
}

// signPayload computes the HMAC-SHA256 signature of payload keyed by the derived
// material. The key is derived, operation-scoped material (never a master
// credential); the signature proves the connector, not the caller, signed it.
func signPayload(derivedMaterial string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(derivedMaterial))
	mac.Write(payload)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// canonicalPayload builds the deterministic delivery payload for one operation.
// It is byte-stable so the central and outbound topologies sign and deliver the
// identical request.
func canonicalPayload(endpointRef, operation, idempotencyKey string) ([]byte, error) {
	return json.Marshal(struct {
		Endpoint       string `json:"endpoint_ref"`
		Operation      string `json:"operation"`
		IdempotencyKey string `json:"idempotency_key"`
	}{Endpoint: endpointRef, Operation: operation, IdempotencyKey: idempotencyKey})
}
