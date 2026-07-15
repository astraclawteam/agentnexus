package actions

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// receiptTimePrecision matches the audit canonical precision (microseconds): a
// receipt's issued_at survives a JSON/DB round-trip losslessly at this
// precision, so signer and verifier agree on the pre-image bytes.
const receiptTimePrecision = time.Microsecond

// CanonicalActionReceipt returns the deterministic signing pre-image of an
// ActionReceipt: the encoding/json serialization with the signature slot
// CLEARED and issued_at normalized to UTC microseconds. A connector signs these
// bytes; the SignedReceiptVerifier rebuilds and verifies them. The result stays
// hash-bound (result_hash), so the payload never needs to be embedded to be
// covered.
func CanonicalActionReceipt(receipt runtime.ActionReceipt) ([]byte, error) {
	receipt.Signature = nil
	receipt.IssuedAt = receipt.IssuedAt.UTC().Truncate(receiptTimePrecision)
	return json.Marshal(receipt)
}

// SignedReceiptVerifier is the real GA Task 0G ReceiptVerifier: it verifies the
// ActionReceipt's ed25519 signature against the registered connector signing
// keys. It ADDS the signature check on top of the service's local structural
// checks and NEVER weakens them. An unsigned receipt, a foreign algorithm, an
// unknown or revoked key, or a signature that does not verify all fail closed —
// "only a verified signed ActionReceipt completes an Action".
type SignedReceiptVerifier struct {
	keys sdkaudit.KeyResolver
}

// NewSignedReceiptVerifier builds the verifier over a connector-key resolver.
func NewSignedReceiptVerifier(keys sdkaudit.KeyResolver) *SignedReceiptVerifier {
	return &SignedReceiptVerifier{keys: keys}
}

// VerifyReceipt implements ReceiptVerifier.
func (v *SignedReceiptVerifier) VerifyReceipt(_ context.Context, _ string, receipt runtime.ActionReceipt) error {
	if v == nil || v.keys == nil {
		return errors.New("receipt verifier is not configured with a connector key resolver")
	}
	if receipt.Signature == nil {
		return errors.New("action receipt is unsigned; only a verified signed receipt completes an action")
	}
	signature := *receipt.Signature
	if err := signature.Validate(); err != nil {
		return err
	}
	if signature.Algorithm != runtime.SignatureAlgorithmEd25519 {
		return errors.New("action receipt signature algorithm is not ed25519")
	}
	key, ok := v.keys.ResolveKey(signature.KeyID)
	if !ok {
		return errors.New("action receipt signing key is unknown")
	}
	if key.Status == sdkaudit.KeyRevoked {
		return errors.New("action receipt signing key is revoked")
	}
	if key.Algorithm != runtime.SignatureAlgorithmEd25519 || len(key.PublicKey) != ed25519.PublicKeySize {
		return errors.New("registered connector key is not a valid ed25519 public key")
	}
	canonical, err := CanonicalActionReceipt(receipt)
	if err != nil {
		return err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil {
		return errors.New("action receipt signature is not base64")
	}
	if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), canonical, sigBytes) {
		return errors.New("action receipt signature does not verify against the registered connector key")
	}
	return nil
}
