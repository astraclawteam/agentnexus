package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// BundleVersion is the format version of the offline verification package.
const BundleVersion = "agentnexus-audit-bundle/v1"

// BatchRoot is the signed WORM/SIEM manifest of one exported chain segment: the
// batch Merkle root over the event hashes, the covered sequence window, the
// event count and the signer-asserted timestamp (SignedAt), all bound by one ed25519
// signature. It is the tamper-evident attestation an offline auditor checks
// without any live service.
type BatchRoot struct {
	TenantRef  string    `json:"tenant_ref"`
	FirstSeq   uint64    `json:"first_seq"`
	LastSeq    uint64    `json:"last_seq"`
	EventCount int       `json:"event_count"`
	RootHash   string    `json:"root_hash"`
	SignedAt   time.Time `json:"signed_at"`
	Signature  Signature `json:"signature"`
}

// canonicalBatch returns the deterministic signing pre-image of a BatchRoot
// (signature slot zeroed, timestamp UTC).
func canonicalBatch(b BatchRoot) ([]byte, error) {
	b.Signature = Signature{}
	b.SignedAt = b.SignedAt.UTC().Truncate(canonicalTimePrecision)
	return json.Marshal(b)
}

// Bundle is the portable offline verification package (WORM/SIEM export): the
// ordered per-tenant events, the signing public keys with their revocation
// state, the signed batch Merkle root with its signer-asserted timestamp, and a
// per-event Merkle inclusion witness. Its bytes are deterministic.
type Bundle struct {
	Version   string          `json:"version"`
	TenantRef string          `json:"tenant_ref"`
	Events    []Event         `json:"events"`
	Keys      []SigningKey    `json:"keys"`
	Batch     BatchRoot       `json:"batch"`
	Witnesses []MerkleWitness `json:"witnesses"`
}

// eventHashes returns the ordered event_hash leaves of the events.
func eventHashes(events []Event) []string {
	hashes := make([]string, len(events))
	for i, e := range events {
		hashes[i] = e.EventHash
	}
	return hashes
}

// BatchSigner signs the canonical batch-root pre-image and returns the detached
// signature. It is the narrow seam a KMS-backed audit key wires behind (the
// open-core AuditSigner port adapts onto it); Ed25519Signer is the local
// reference implementation.
type BatchSigner func(canonical []byte) (Signature, error)

// Ed25519Signer is the local reference BatchSigner over a raw ed25519 key.
func Ed25519Signer(keyID string, key ed25519.PrivateKey) BatchSigner {
	return func(canonical []byte) (Signature, error) {
		if keyID == "" || len(key) != ed25519.PrivateKeySize {
			return Signature{}, fmt.Errorf("%w: ed25519 batch signer needs a key id and key", ErrMalformed)
		}
		return Signature{
			Algorithm: SignatureAlgorithmEd25519,
			KeyID:     keyID,
			Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)),
		}, nil
	}
}

// BuildBundle assembles and signs an offline verification package for the given
// chain. The events must be a valid signed chain (built by the runtime append
// path). The batch root is signed by sign, whose key's public half must appear
// in keys so an offline verifier can check it.
func BuildBundle(tenant string, events []Event, keys []SigningKey, sign BatchSigner) (Bundle, error) {
	if tenant == "" || len(events) == 0 {
		return Bundle{}, fmt.Errorf("%w: bundle needs a tenant and at least one event", ErrMalformed)
	}
	if sign == nil {
		return Bundle{}, fmt.Errorf("%w: bundle needs a batch signer", ErrMalformed)
	}
	hashes := eventHashes(events)
	root, err := MerkleRoot(hashes)
	if err != nil {
		return Bundle{}, err
	}
	witnesses := make([]MerkleWitness, len(events))
	for i := range events {
		witness, err := MerkleProof(hashes, i)
		if err != nil {
			return Bundle{}, err
		}
		witnesses[i] = witness
	}
	batch := BatchRoot{
		TenantRef:  tenant,
		FirstSeq:   events[0].TenantSeq,
		LastSeq:    events[len(events)-1].TenantSeq,
		EventCount: len(events),
		RootHash:   root,
		SignedAt:   events[len(events)-1].SignedAt.UTC(),
	}
	canonical, err := canonicalBatch(batch)
	if err != nil {
		return Bundle{}, err
	}
	signature, err := sign(canonical)
	if err != nil {
		return Bundle{}, err
	}
	if signature.zero() || signature.Algorithm != SignatureAlgorithmEd25519 {
		return Bundle{}, fmt.Errorf("%w: batch signer returned an invalid signature", ErrMalformed)
	}
	batch.Signature = signature
	return Bundle{
		Version:   BundleVersion,
		TenantRef: tenant,
		Events:    events,
		Keys:      keys,
		Batch:     batch,
		Witnesses: witnesses,
	}, nil
}

// MarshalBundle serializes a bundle to deterministic, human-inspectable bytes.
func MarshalBundle(b Bundle) ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// UnmarshalBundle parses bundle bytes.
func UnmarshalBundle(raw []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return b, nil
}

// anchoredResolver resolves signing keys ONLY from the caller-supplied trust
// anchor (the pinned public keys), overlaying revocation asserted by the
// bundle. The bundle's own key list can therefore assert that a trusted key was
// revoked, but can NEVER introduce a new trusted key: an unanchored key id does
// not resolve, and a signature made by any key other than the anchored one
// fails ed25519 verification against the anchored public-key bytes.
type anchoredResolver struct {
	trusted KeyResolver
	revoked map[string]bool
}

func (r anchoredResolver) ResolveKey(keyID string) (SigningKey, bool) {
	key, ok := r.trusted.ResolveKey(keyID)
	if !ok {
		return SigningKey{}, false
	}
	if r.revoked[keyID] {
		key.Status = KeyRevoked
	}
	return key, true
}

// VerifyBundle verifies an offline verification package end to end with stdlib
// crypto only, AGAINST A CALLER-SUPPLIED TRUST ANCHOR: the pinned signing keys,
// the full signed chain (VerifyChain: sequence, tenant, hash chain, per-event
// signatures, revoked-key detection, raw-payload and business-Outcome
// rejection), the batch Merkle root over the event hashes, every inclusion
// witness, the WORM manifest window and the batch-root signature (including its
// signer-asserted timestamp). Any failure is a tamper.
//
// AUTHENTICITY: the trust anchor is REQUIRED and is the ONLY trust root. The
// bundle's embedded Keys supply REVOCATION metadata only; they can never be the
// trust root, so a fully fabricated bundle self-signed by an attacker's own key
// is rejected as ErrUnknownKey/ErrUntrustedKey. Bundle self-consistency is not
// authenticity.
func VerifyBundle(b Bundle, trusted KeyResolver) error {
	if trusted == nil {
		return fmt.Errorf("%w: a trusted signing-key anchor is required; bundle self-trust is refused", ErrMalformed)
	}
	if b.Version != BundleVersion {
		return fmt.Errorf("%w: unexpected bundle version %q", ErrMalformed, b.Version)
	}
	if len(b.Events) == 0 {
		return fmt.Errorf("%w: bundle has no events", ErrMalformed)
	}
	// Bundle keys carry REVOCATION metadata only. Each must be well-formed, and
	// where it names an anchored key id its public-key bytes MUST match the
	// anchor (a mismatch is a key-substitution forgery).
	revoked := map[string]bool{}
	for _, key := range b.Keys {
		if err := verifyKeyMaterial(key); err != nil {
			return fmt.Errorf("%w: signing key %s", err, key.KeyID)
		}
		anchor, ok := trusted.ResolveKey(key.KeyID)
		if ok && !bytes.Equal(anchor.PublicKey, key.PublicKey) {
			return fmt.Errorf("%w: bundle key %s public-key bytes differ from the anchor", ErrUntrustedKey, key.KeyID)
		}
		if key.Status == KeyRevoked {
			revoked[key.KeyID] = true
		}
	}
	effective := anchoredResolver{trusted: trusted, revoked: revoked}
	// Full signed-chain verification against the anchor (single source of truth,
	// shared with the live runtime verifier).
	if err := VerifyChain(b.Events, effective); err != nil {
		return err
	}
	if b.TenantRef != b.Events[0].TenantRef {
		return fmt.Errorf("%w: bundle tenant %q does not match events", ErrTenantSplice, b.TenantRef)
	}
	// Batch Merkle root over the event hashes.
	hashes := eventHashes(b.Events)
	root, err := MerkleRoot(hashes)
	if err != nil {
		return err
	}
	if root != b.Batch.RootHash {
		return fmt.Errorf("%w: batch root does not cover the events", ErrHashMismatch)
	}
	// Every inclusion witness must verify against the root.
	if len(b.Witnesses) != len(b.Events) {
		return fmt.Errorf("%w: witness count does not match events", ErrMalformed)
	}
	for i, witness := range b.Witnesses {
		if !VerifyMerkleProof(hashes[i], root, witness) {
			return fmt.Errorf("%w: witness %d does not prove inclusion", ErrChainBroken, i)
		}
	}
	// WORM manifest window.
	if b.Batch.TenantRef != b.TenantRef ||
		b.Batch.FirstSeq != b.Events[0].TenantSeq ||
		b.Batch.LastSeq != b.Events[len(b.Events)-1].TenantSeq ||
		b.Batch.EventCount != len(b.Events) {
		return fmt.Errorf("%w: batch manifest window does not match the events", ErrSequence)
	}
	// Batch-root signature (with its signer-asserted timestamp), against the
	// anchored resolver - the single batch-root verification path.
	return VerifyBatchRoot(b.Batch, effective)
}

// CanonicalBatchRoot returns the deterministic signing pre-image of a batch-root
// checkpoint (signature slot zeroed, timestamp UTC at microsecond precision).
func CanonicalBatchRoot(b BatchRoot) ([]byte, error) { return canonicalBatch(b) }

// VerifyBatchRoot verifies a batch-root checkpoint's ed25519 signature against a
// caller-supplied trust anchor: an unsigned root, a foreign algorithm, an
// unknown or revoked key, or a signature that does not verify is rejected. It is
// the shared authenticity gate for a persisted checkpoint - the LIVE truncation
// helper verifies a checkpoint through HERE before trusting its covered
// sequence, so a DB role that inserts a forged checkpoint cannot mask truncation.
func VerifyBatchRoot(b BatchRoot, trusted KeyResolver) error {
	if trusted == nil {
		return fmt.Errorf("%w: batch root needs a trust anchor", ErrMalformed)
	}
	if b.Signature.zero() {
		return fmt.Errorf("%w: batch root is unsigned", ErrUnsigned)
	}
	if b.Signature.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("%w: batch root", ErrBadAlgorithm)
	}
	key, ok := trusted.ResolveKey(b.Signature.KeyID)
	if !ok {
		return fmt.Errorf("%w: batch signing key not in the trusted anchor", ErrUnknownKey)
	}
	if key.Status == KeyRevoked {
		return fmt.Errorf("%w: batch signing key", ErrRevokedKey)
	}
	if err := verifyKeyMaterial(key); err != nil {
		return err
	}
	canonical, err := canonicalBatch(b)
	if err != nil {
		return err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b.Signature.Value)
	if err != nil {
		return fmt.Errorf("%w: batch signature is not base64", ErrBadSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), canonical, sigBytes) {
		return fmt.Errorf("%w: batch root signature", ErrBadSignature)
	}
	return nil
}
