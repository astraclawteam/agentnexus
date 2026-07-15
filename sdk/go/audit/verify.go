package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// VerifyChain verifies one per-tenant audit chain end to end against the
// registered keys. The events must be the FULL chain for one tenant in sequence
// order. It fails closed on the FIRST tamper it finds and returns a typed
// sentinel (errors.Is-matchable) naming the tamper class.
//
// The checks, in order, jointly detect: an unsigned/legacy event, a foreign
// algorithm, a spliced foreign-tenant event, a sequence gap/duplicate/reorder
// (deletion, insertion, reordering), a raw sensitive payload, a smuggled
// business-Outcome assertion, a broken prev_hash linkage, a forged event_hash,
// an unknown or revoked signing key, and any field mutation / forged timestamp /
// receipt-or-observation substitution / detached postcondition binding (all of
// which invalidate the ed25519 signature over the canonical pre-image).
func VerifyChain(events []Event, keys KeyResolver) error {
	if keys == nil {
		return fmt.Errorf("%w: no key resolver", ErrMalformed)
	}
	if len(events) == 0 {
		return nil
	}
	tenant := events[0].TenantRef
	if tenant == "" {
		return fmt.Errorf("%w: empty tenant ref", ErrMalformed)
	}
	prevHash := ""
	for i := range events {
		e := events[i]
		if err := verifyEvent(e, uint64(i+1), tenant, prevHash, keys); err != nil {
			return fmt.Errorf("audit event %s (seq %d): %w", e.ID, e.TenantSeq, err)
		}
		prevHash = e.EventHash
	}
	return nil
}

// verifyEvent applies the ordered per-event checks. wantSeq is the expected
// strict sequence value (1-based position), tenant is the chain tenant and
// prevHash is the previous event's event_hash.
func verifyEvent(e Event, wantSeq uint64, tenant, prevHash string, keys KeyResolver) error {
	// 1. Signed authority: the legacy unsigned SHA-256 chain never passes.
	if e.Signature.zero() {
		return ErrUnsigned
	}
	if e.Signature.Algorithm != SignatureAlgorithmEd25519 {
		return ErrBadAlgorithm
	}
	// 2. Single-tenant chain: a foreign-tenant event is a splice.
	if e.TenantRef != tenant {
		return ErrTenantSplice
	}
	// 3. Strict monotonic sequence from 1 (catches deletion, insertion,
	// reordering, duplicate sequence).
	if e.TenantSeq != wantSeq {
		return ErrSequence
	}
	// 4. No raw sensitive payload: hash slots are sha256 refs or empty, opaque
	// references are bounded, and no field carries control/NUL bytes.
	if err := checkNoRawPayload(e); err != nil {
		return err
	}
	// 5. No smuggled business Outcome (mirrors the 0A public-contract ban).
	if assertsOutcome(e) {
		return ErrOutcomeAssertion
	}
	// 6. Hash-chain linkage: prev_hash binds the previous event's event_hash.
	if e.PrevHash != prevHash {
		return ErrChainBroken
	}
	// 7. Event hash integrity: event_hash equals the recomputed canonical hash.
	recomputed, err := EventHash(e)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if recomputed != e.EventHash {
		return ErrHashMismatch
	}
	// 8. Key resolution: the signing key must be registered and not revoked.
	key, ok := keys.ResolveKey(e.Signature.KeyID)
	if !ok {
		return ErrUnknownKey
	}
	if key.Status == KeyRevoked {
		return ErrRevokedKey
	}
	if err := verifyKeyMaterial(key); err != nil {
		return err
	}
	// 9. Signature: ed25519 over the canonical pre-image. Any field mutation,
	// forged timestamp or substituted binding reaches this check and fails it.
	canonical, err := Canonical(e)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(e.Signature.Value)
	if err != nil {
		return fmt.Errorf("%w: signature is not base64", ErrBadSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), canonical, sigBytes) {
		return ErrBadSignature
	}
	return nil
}

// checkNoRawPayload enforces that an audit event binds hashes and opaque
// references only. A hash slot must be empty or a sha256:<64 hex> reference; a
// reference field must be bounded; no field may carry control/NUL bytes.
func checkNoRawPayload(e Event) error {
	for _, hashField := range []string{e.InputHash, e.OutputHash, e.ParameterHash} {
		if hashField != "" && !sha256RefRe.MatchString(hashField) {
			return ErrRawPayload
		}
	}
	for _, ref := range []string{
		e.ID, e.TenantRef, e.CaseTicketID, e.StepGrantID, e.ActorUserID,
		e.ConnectorInstanceID, e.ResourceType, e.ResourceID, e.Action, e.Decision,
		e.EvidencePointer, e.StatusFrom, e.Capability, e.GrantRef, e.ApprovalEvidenceRef,
		e.ReceiptRef, e.RiskAuthority, e.AgentClientRef, e.AgentReleaseRef, e.OrgSnapshotRef, e.PrevHash,
	} {
		if len(ref) > maxReferenceBytes {
			return ErrRawPayload
		}
		if hasControlBytes(ref) {
			return ErrRawPayload
		}
	}
	return nil
}
