package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

// SignEd25519 is the reference ed25519 signer over the canonical audit
// pre-image. It fills EventHash and Signature (leaving every other field,
// including SignedAt, exactly as the caller set it) and returns the signed
// event. Both the event_hash and the signature bind the SAME canonical bytes.
//
// It is the pure counterpart of the open-core Ed25519AuditSigner (which speaks
// the narrow runtime.Signature port and a KMS-ready seam); this helper lets the
// offline export path and the conformance test suites build signed evidence
// without importing the runtime service.
func SignEd25519(e Event, keyID string, key ed25519.PrivateKey) (Event, error) {
	if keyID == "" {
		return Event{}, errors.New("audit signer requires a key id")
	}
	if len(key) != ed25519.PrivateKeySize {
		return Event{}, errors.New("audit signer requires exactly ed25519.PrivateKeySize bytes of key material")
	}
	canonical, err := Canonical(e)
	if err != nil {
		return Event{}, err
	}
	hash, err := EventHash(e)
	if err != nil {
		return Event{}, err
	}
	e.EventHash = hash
	e.Signature = Signature{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)),
	}
	return e, nil
}
