// observation.go is the GA Task 0D amendment surface (plan revision dc81e80;
// deferral recorded in the task-0d handoff): verification-purpose reads bind
// the original Action and the declared PostconditionSpec/VerificationNeed
// pair server-side and mint a signed runtime.ObservationReceipt.
//
// Authority boundary (frozen by contract v1.3.0, GA Task 0A amendment): an
// ObservationReceipt proves what an authorized source reported at a bounded
// time. AgentNexus NEVER interprets business/domain success, never asserts an
// Outcome and never touches the calling Agent platform's result graph - the
// minting path below never inspects observation CONTENT, only server-side
// binding facts (registry authority tier, sealed source version, staging
// instant, freshness bound, content hash).
package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// Frozen observation authority tiers of the internal semantic registry: the
// vocabulary under which a bound source reports observations. The literals
// mirror the connector probe source-authority ladder frozen by the GA Task 2
// amendment (sdk/go/connector SourceAuthority) BY VALUE - deliberately copied
// as frozen literals, not imported: the evidence plane must not depend on the
// connector SDK module, and both vocabularies are contract-frozen so drift is
// a contract change, never a refactor.
//
// The tier is INTERNAL registry state (never part of the public contract
// request surface) and is emitted verbatim as ObservationReceipt.authority:
// the receipt states the declared authority honestly - including "derived" -
// and leaves any acceptance policy over tiers to the caller and to the GA
// Task 8 certification plane. Refusing non-authoritative tiers here would
// itself be a policy judgment the evidence plane does not own.
const (
	AuthorityTierSystemOfRecord       = "system_of_record"
	AuthorityTierAuthoritativeReplica = "authoritative_replica"
	AuthorityTierDerived              = "derived"
)

// validAuthorityTier reports whether tier is one of the frozen literals.
func validAuthorityTier(tier string) bool {
	switch tier {
	case AuthorityTierSystemOfRecord, AuthorityTierAuthoritativeReplica, AuthorityTierDerived:
		return true
	}
	return false
}

// ObservationSigner is the narrow signing port of the observation plane: it
// signs the canonical receipt pre-image and nothing else. GA Task 0G brings
// KMS-backed keys, rotation and the audit chain; this port stays the seam.
// Production wiring is nil-guarded: with no signer wired, verification-purpose
// reads fail CLOSED (ordinary reads are unaffected).
type ObservationSigner interface {
	Sign(ctx context.Context, canonical []byte) (runtime.Signature, error)
}

// ActionBindingVerifier is the GA Task 0F seam: when wired, it
// AUTHORITATIVELY checks the declared verification binding against the stored
// Action (action_ref existence, parameter-hash equality, declared
// postcondition/need membership - Actions and their state machine land in
// Task 0F). Until then the port stays nil and the service performs only the
// local self-consistency checks (canonical block, purpose coupling,
// data-class match against the resolved read); a nil port never weakens those
// checks and never substitutes a silent pass for a wired rejection.
type ActionBindingVerifier interface {
	VerifyActionBinding(ctx context.Context, tenantRef string, binding runtime.VerificationBinding) error
}

// Ed25519ObservationSigner is the real local ObservationSigner used by unit
// tests and local harnesses: stdlib ed25519 over the canonical receipt bytes.
// It is real cryptography - signatures verify against the public key - but
// its key handling (in-memory private key) is NOT the production shape; a
// deployment adapts its KMS behind ObservationSigner (GA Task 0G).
type Ed25519ObservationSigner struct {
	keyID string
	key   ed25519.PrivateKey
}

// NewEd25519ObservationSigner builds the local signer; broken key material is
// rejected at construction, never at signing time.
func NewEd25519ObservationSigner(keyID string, key ed25519.PrivateKey) (*Ed25519ObservationSigner, error) {
	if keyID == "" {
		return nil, errors.New("observation signer requires a key id")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("observation signer requires exactly ed25519.PrivateKeySize bytes of key material")
	}
	return &Ed25519ObservationSigner{keyID: keyID, key: key}, nil
}

// Sign signs the canonical receipt pre-image with ed25519.
func (s *Ed25519ObservationSigner) Sign(_ context.Context, canonical []byte) (runtime.Signature, error) {
	if s == nil || s.keyID == "" || len(s.key) != ed25519.PrivateKeySize {
		return runtime.Signature{}, ErrUnavailable
	}
	return runtime.Signature{
		Algorithm: runtime.SignatureAlgorithmEd25519,
		KeyID:     s.keyID,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, canonical)),
	}, nil
}

// CanonicalObservationReceipt returns the deterministic signing pre-image of
// an ObservationReceipt: the encoding/json serialization of the receipt with
// its signature slot ZEROED and both time bounds normalized to UTC.
//
// Canonicalization convention (documented, mirrors the staged-content
// convention of this package): deterministic bytes come from encoding/json
// over a fixed Go struct - field order is the frozen contract declaration
// order, no omitempty on any receipt field, time.Time marshals as RFC 3339
// UTC. A verifier rebuilds the exact pre-image from the transported receipt
// by zeroing the signature and re-marshaling, because the receipt JSON
// round-trips losslessly through the SDK type.
func CanonicalObservationReceipt(receipt runtime.ObservationReceipt) ([]byte, error) {
	receipt.Signature = runtime.Signature{}
	receipt.ObservedAt = receipt.ObservedAt.UTC()
	receipt.FreshUntil = receipt.FreshUntil.UTC()
	return json.Marshal(receipt)
}

// mintObservationReceipt builds, canonicalizes and signs the ObservationReceipt
// of one ALLOWED verification-purpose read. Every binding is server-side
// truth: the handle (sealed source version, staging instant, content hash,
// evidence ref), the registry binding (authority tier, freshness bound) and
// the read's mandatory audit lineage reference. The caller-declared block
// contributes only the Action/postcondition/need identity it was validated
// for. The observation hash is the staged normalized content digest
// (sha256 over the encoding/json record-array bytes - the same digest the
// handle binds as ContentHash), so the receipt attests the FULL bounded
// observation behind evidence_ref, independent of per-read field projection
// or pagination windows.
func (s *Service) mintObservationReceipt(ctx context.Context, observationRef string, declared runtime.VerificationBinding, handle Handle, binding SourceBinding, auditRef string) (runtime.ObservationReceipt, error) {
	observedAt := handle.StagedAt.UTC()
	receipt := runtime.ObservationReceipt{
		ObservationRef:     observationRef,
		ActionRef:          declared.ActionRef,
		ParameterHash:      declared.ParameterHash,
		PostconditionID:    declared.PostconditionID,
		VerificationNeedID: declared.VerificationNeedID,
		// Source is the business-semantic identity of the observed source:
		// the data class - never the private SourceRef topology.
		Source:          handle.DataClass,
		SourceVersion:   handle.SourceVersion,
		Authority:       binding.AuthorityTier,
		ObservedAt:      observedAt,
		FreshUntil:      observedAt.Add(binding.FreshnessBound),
		ObservationHash: "sha256:" + handle.ContentHash,
		EvidenceRef:     handle.EvidenceRef,
		AuditRefID:      auditRef,
	}
	canonical, err := CanonicalObservationReceipt(receipt)
	if err != nil {
		return runtime.ObservationReceipt{}, errors.Join(ErrUnavailable, err)
	}
	signature, err := s.signer.Sign(ctx, canonical)
	if err != nil {
		return runtime.ObservationReceipt{}, errors.Join(ErrUnavailable, errors.New("observation signing failed"))
	}
	receipt.Signature = signature
	// Integrity backstop: a receipt that does not satisfy the frozen public
	// contract is a bug, and the read fails closed rather than emitting it.
	if err := receipt.Validate(); err != nil {
		return runtime.ObservationReceipt{}, errors.Join(ErrUnavailable, err)
	}
	return receipt, nil
}

// maxDataClassBytes mirrors the public data_class length bound (OpenAPI
// maxLength 256; SDK counts bytes).
const maxDataClassBytes = 256

// validateVerificationBinding applies the service-side canonicality rules on
// top of the SDK block validation (defense in depth: the gateway decodes
// through the SDK, but the service is also called directly). Fields are
// checked in the frozen contract declaration order so the FIRST reported
// error is deterministic (the package's ordered field-check idiom; a map
// here would randomize which failure a caller sees when several fields are
// invalid).
func validateVerificationBinding(binding runtime.VerificationBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	checks := []struct {
		field string
		value string
		limit int
	}{
		{"postcondition_id", binding.PostconditionID, maxNeedIDBytes},
		{"verification_need_id", binding.VerificationNeedID, maxNeedIDBytes},
		{"data_class", binding.DataClass, maxDataClassBytes},
	}
	for _, check := range checks {
		if !canonical(check.value) || hasControlBytes(check.value) || len(check.value) > check.limit {
			return errors.New(check.field + " is not canonical")
		}
	}
	return nil
}
