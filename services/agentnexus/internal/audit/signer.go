package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// ErrUnavailable marks a signing outage: no signer wired, broken key material or
// a signer failure. High-risk audit appends fail CLOSED on it — an integrity
// outage never silently produces an unsigned high-risk audit record.
var ErrUnavailable = errors.New("audit signer unavailable")

// AuditSigner is the narrow signing port of the audit plane: it signs the
// canonical event pre-image and nothing else. This IS the Secret Provider / KMS
// seam — a narrow port with a real local stdlib implementation below; a KMS
// wires behind it later without touching a caller. Production wiring is
// nil-guarded: with no signer wired, a high-risk audit append fails CLOSED and
// a nil port never weakens a local check nor silently passes a rejection.
type AuditSigner interface {
	Sign(ctx context.Context, canonical []byte) (runtime.Signature, error)
}

// Ed25519AuditSigner is the real local AuditSigner: stdlib ed25519 over the
// canonical event bytes. It is real cryptography - signatures verify against the
// public key - but its in-memory key handling is NOT the production shape; a
// deployment adapts its KMS behind AuditSigner. Broken key material is rejected
// at construction, never at signing time.
type Ed25519AuditSigner struct {
	keyID string
	key   ed25519.PrivateKey
}

// NewEd25519AuditSigner builds the local signer; a missing key id or malformed
// key material is rejected up front.
func NewEd25519AuditSigner(keyID string, key ed25519.PrivateKey) (*Ed25519AuditSigner, error) {
	if keyID == "" {
		return nil, errors.New("audit signer requires a key id")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("audit signer requires exactly ed25519.PrivateKeySize bytes of key material")
	}
	return &Ed25519AuditSigner{keyID: keyID, key: key}, nil
}

// KeyID returns the signer's key id (used to register the public half).
func (s *Ed25519AuditSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// PublicKey returns the signer's ed25519 public key (registered so the verifier
// can resolve signatures).
func (s *Ed25519AuditSigner) PublicKey() ed25519.PublicKey {
	if s == nil || len(s.key) != ed25519.PrivateKeySize {
		return nil
	}
	return s.key.Public().(ed25519.PublicKey)
}

// Sign signs the canonical event pre-image with ed25519.
func (s *Ed25519AuditSigner) Sign(_ context.Context, canonical []byte) (runtime.Signature, error) {
	if s == nil || s.keyID == "" || len(s.key) != ed25519.PrivateKeySize {
		return runtime.Signature{}, ErrUnavailable
	}
	return runtime.Signature{
		Algorithm: runtime.SignatureAlgorithmEd25519,
		KeyID:     s.keyID,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, canonical)),
	}, nil
}

// SignEvent canonicalizes the event, signs it through the port and returns the
// event with its signature (and recomputed event_hash) set.
//
// Signer-error-logging seam (deferred from the 0D amendment to 0G): the 0D
// observation path returned a naked "signing failed" that hid the cause. HERE
// the underlying signer error is LOGGED for diagnostics (refs and the coded
// cause only — never key material, which the ed25519 signer never places in an
// error) while the call still fails CLOSED with ErrUnavailable wrapping the
// cause, so operators can tell a KMS outage from a key-config error.
func SignEvent(ctx context.Context, signer AuditSigner, logger *slog.Logger, event Event) (Event, error) {
	if signer == nil {
		return Event{}, errors.Join(ErrUnavailable, errors.New("audit signer is not wired; high-risk audit append fails closed"))
	}
	canonical, err := CanonicalAuditEvent(event)
	if err != nil {
		return Event{}, errors.Join(ErrUnavailable, err)
	}
	signature, err := signer.Sign(ctx, canonical)
	if err != nil {
		if logger != nil {
			logger.Error("audit signing failed",
				slog.String("audit_id", event.ID),
				slog.String("tenant_ref", event.EnterpriseID),
				slog.Uint64("tenant_seq", event.TenantSeq),
				slog.String("cause", err.Error()))
		}
		// Preserve the cause for diagnostics AND fail closed.
		return Event{}, errors.Join(ErrUnavailable, err)
	}
	if err := signature.Validate(); err != nil {
		return Event{}, errors.Join(ErrUnavailable, err)
	}
	event.Signature = signature
	event.EventHash = ComputeHash(event)
	return event, nil
}
