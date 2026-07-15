package audit

import (
	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
)

// Re-exported shared verification types and sentinels so callers verify durable
// chains without importing the sdk module directly. The verification LOGIC lives
// in sdk/go/audit (the single source of truth); this package only maps the
// durable Event onto it.
type (
	// SigningKey is a registered ed25519 signing key and its lifecycle status.
	SigningKey = sdkaudit.SigningKey
	// KeyResolver resolves a key id to its registered signing key.
	KeyResolver = sdkaudit.KeyResolver
	// KeySet is an in-memory KeyResolver.
	KeySet = sdkaudit.KeySet
)

// SignatureAlgorithmEd25519 is the only frozen v1 signature algorithm.
const SignatureAlgorithmEd25519 = sdkaudit.SignatureAlgorithmEd25519

// Shared verification error sentinels (errors.Is-matchable).
var (
	ErrUnsigned         = sdkaudit.ErrUnsigned
	ErrRevokedKey       = sdkaudit.ErrRevokedKey
	ErrUnknownKey       = sdkaudit.ErrUnknownKey
	ErrBadSignature     = sdkaudit.ErrBadSignature
	ErrHashMismatch     = sdkaudit.ErrHashMismatch
	ErrChainBroken      = sdkaudit.ErrChainBroken
	ErrSequence         = sdkaudit.ErrSequence
	ErrTenantSplice     = sdkaudit.ErrTenantSplice
	ErrRawPayload       = sdkaudit.ErrRawPayload
	ErrOutcomeAssertion = sdkaudit.ErrOutcomeAssertion
)

// NewKeySet builds an in-memory key resolver from registered signing keys.
func NewKeySet(keys ...SigningKey) KeySet { return sdkaudit.NewKeySet(keys...) }

// Verify verifies a FULL signed per-tenant durable chain (events in sequence
// order) against the registered keys. It detects, over the chain: field
// mutation, event deletion/insertion, reordering, tenant-chain splice, forged
// timestamp, revoked signing key, duplicate sequence, a raw sensitive payload,
// execution/observation receipt substitution, a detached postcondition binding
// and any event asserting a business Outcome; and it rejects the existing
// UNSIGNED SHA-256 chain (an absent signature fails closed). It fails on the
// FIRST tamper with a typed sentinel.
func Verify(events []Event, keys KeyResolver) error {
	sdkEvents := make([]sdkaudit.Event, len(events))
	for i, e := range events {
		sdkEvents[i] = toSDK(e)
	}
	return sdkaudit.VerifyChain(sdkEvents, keys)
}
