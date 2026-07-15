// Package audit is the shared, dependency-free verification core of the
// AgentNexus signed audit evidence chain (GA Task 0G). It is the SINGLE source
// of truth for how one audit event is canonicalized, hashed and signed, how a
// per-tenant chain is verified, and how an offline WORM/SIEM verification
// package is built and re-verified. Both the open-core runtime (which appends
// and self-verifies live chains) and the standalone enterprise offline verifier
// consume THIS module, so the two can never diverge on a crypto detail.
//
// Authority boundary (frozen by contract v1.3.0, GA Task 0A amendment): the
// audit plane records what happened - the verified principal, the exact
// operation, the action transition, the receipt reference and the hash-chain
// linkage. It NEVER records or asserts a business Outcome. VerifyChain rejects
// any event whose fields assert an outcome/goal/result-graph, mirroring the 0A
// public-contract name ban - an audit ledger that could smuggle an Outcome
// assertion would breach the same authority boundary the public surface freezes.
//
// The module has zero external dependencies: stdlib crypto only. A KMS wires in
// LATER behind the narrow signer port defined in the open-core runtime; nothing
// in this module builds key-management machinery.
package audit

import (
	"crypto/ed25519"
	"errors"
	"regexp"
	"strings"
	"time"
)

// SignatureAlgorithmEd25519 is the only signature algorithm frozen for contract
// v1 (mirrors sdk/go/runtime SignatureAlgorithmEd25519 by value).
const SignatureAlgorithmEd25519 = "ed25519"

// Signature is a detached signature by a named key over the canonical audit
// pre-image. The JSON tags are byte-identical to sdk/go/runtime Signature so a
// runtime.Signature and this type canonicalize to the same bytes; the open-core
// signer port returns runtime.Signature and maps it onto this shape.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	// Value carries the base64 (StdEncoding) signature bytes.
	Value string `json:"value"`
}

// zero reports whether the signature slot is empty. An empty signature is the
// legacy UNSIGNED chain: VerifyChain rejects it.
func (s Signature) zero() bool { return s == Signature{} }

// Event is one link of the signed, per-tenant audit chain. Its fields mirror
// the durable audit_events row (the internal ledger) EXACTLY, plus the GA Task
// 0G signing columns (TenantSeq, SignedAt, Signature). Canonicalization covers
// every field except the two slots it zeroes (Signature and EventHash), so a
// mutation of ANY other field breaks both the hash and the signature.
//
// The JSON tags freeze the canonical field order and carry NO omitempty: field
// presence is stable, so the pre-image bytes are deterministic across encoders.
type Event struct {
	ID                  string `json:"id"`
	TenantRef           string `json:"tenant_ref"`
	TenantSeq           uint64 `json:"tenant_seq"`
	CaseTicketID        string `json:"case_ticket_id"`
	StepGrantID         string `json:"step_grant_id"`
	ActorUserID         string `json:"actor_user_id"`
	ConnectorInstanceID string `json:"connector_instance_id"`
	ResourceType        string `json:"resource_type"`
	ResourceID          string `json:"resource_id"`
	Action              string `json:"action"`
	Decision            string `json:"decision"`
	InputHash           string `json:"input_hash"`
	OutputHash          string `json:"output_hash"`
	EvidencePointer     string `json:"evidence_pointer"`
	// GA Task 0G first-class binding refs (recoverable, individually signed).
	// The action-transition sub-chain populates these from the Action record and
	// the verified principal so every binding is inspectable and independently
	// tamper-evident - not folded non-recoverably into a single input hash.
	StatusFrom          string    `json:"status_from"`
	Capability          string    `json:"capability"`
	ParameterHash       string    `json:"parameter_hash"`
	GrantRef            string    `json:"grant_ref"`
	ApprovalEvidenceRef string    `json:"approval_evidence_ref"`
	ReceiptRef          string    `json:"receipt_ref"`
	RiskAuthority       string    `json:"risk_authority"`
	AgentClientRef      string    `json:"agent_client_ref"`
	AgentReleaseRef     string    `json:"agent_release_ref"`
	OrgSnapshotRef      string    `json:"org_snapshot_ref"`
	PrevHash            string    `json:"prev_hash"`
	SignedAt            time.Time `json:"signed_at"`
	Signature           Signature `json:"signature"`
	EventHash           string    `json:"event_hash"`
}

// Verification sentinels. Callers (and the offline CLI) match these with
// errors.Is to distinguish tamper classes; every one fails the chain closed.
var (
	// ErrUnsigned marks an event whose signature slot is empty: the legacy
	// unsigned SHA-256 chain never satisfies the signed verifier.
	ErrUnsigned = errors.New("audit event is unsigned")
	// ErrBadAlgorithm marks a signature that is not the frozen ed25519 algorithm.
	ErrBadAlgorithm = errors.New("audit signature algorithm is not ed25519")
	// ErrUnknownKey marks a signature by a key the verifier cannot resolve.
	ErrUnknownKey = errors.New("audit signing key is unknown")
	// ErrUntrustedKey marks a bundle key that is absent from the caller-supplied
	// trust anchor, or present under a key id with DIFFERENT public-key bytes: a
	// bundle can never be its own trust root. Bundle self-consistency is NOT
	// authenticity - only a signature by a key pinned in the trust anchor is.
	ErrUntrustedKey = errors.New("audit signing key is not in the trusted anchor")
	// ErrRevokedKey marks a signature by a key whose registered status is revoked.
	ErrRevokedKey = errors.New("audit signing key is revoked")
	// ErrBadSignature marks a signature that does not verify against the resolved
	// key over the canonical pre-image (field mutation, forged timestamp,
	// receipt/observation substitution, detached postcondition binding).
	ErrBadSignature = errors.New("audit signature does not verify")
	// ErrHashMismatch marks an event_hash that does not equal the recomputed hash
	// of the canonical pre-image.
	ErrHashMismatch = errors.New("audit event_hash does not match the canonical pre-image")
	// ErrChainBroken marks a prev_hash that does not link to the previous event's
	// event_hash (deletion, insertion, reordering).
	ErrChainBroken = errors.New("audit chain prev_hash linkage is broken")
	// ErrSequence marks a per-tenant sequence that is not the strict monotonic
	// 1,2,3,... with no gaps and no duplicates.
	ErrSequence = errors.New("audit per-tenant sequence is not strictly monotonic from 1")
	// ErrTenantSplice marks an event whose tenant_ref differs from the chain's
	// tenant: events from another tenant may never be spliced into a chain.
	ErrTenantSplice = errors.New("audit chain contains an event from another tenant")
	// ErrRawPayload marks an event carrying a raw (non-hash, non-reference)
	// sensitive payload: audit records bind hashes and opaque pointers only.
	ErrRawPayload = errors.New("audit event carries a raw sensitive payload")
	// ErrOutcomeAssertion marks an event whose fields assert a business Outcome,
	// goal or result-graph: the audit plane records facts, never Outcomes.
	ErrOutcomeAssertion = errors.New("audit event asserts a business outcome")
	// ErrMalformed marks a structurally invalid event or chain input.
	ErrMalformed = errors.New("audit input is malformed")
)

// KeyStatus is the registered lifecycle of a signing key.
type KeyStatus string

const (
	// KeyActive is a key whose signatures are accepted.
	KeyActive KeyStatus = "active"
	// KeyRevoked is a key whose signatures are rejected (ErrRevokedKey) even
	// though they verify cryptographically: a revoked key can sign no new truth.
	KeyRevoked KeyStatus = "revoked"
)

// SigningKey is a registered ed25519 public key and its lifecycle status. The
// public key bytes are the 32-byte ed25519 public key; a revoked key is kept in
// the set so the verifier can distinguish "revoked" from "unknown".
type SigningKey struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
	Status    KeyStatus `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	RevokedAt time.Time `json:"revoked_at"`
}

// KeyResolver resolves a key id to its registered signing key. It is the ONLY
// authority on which keys are valid versus revoked; VerifyChain never trusts a
// signature whose key it cannot resolve.
type KeyResolver interface {
	ResolveKey(keyID string) (SigningKey, bool)
}

// KeySet is an in-memory KeyResolver over a fixed set of registered keys.
type KeySet map[string]SigningKey

// ResolveKey implements KeyResolver.
func (s KeySet) ResolveKey(keyID string) (SigningKey, bool) {
	key, ok := s[keyID]
	return key, ok
}

// NewKeySet builds a KeySet from keys, indexed by key id.
func NewKeySet(keys ...SigningKey) KeySet {
	set := make(KeySet, len(keys))
	for _, key := range keys {
		set[key.KeyID] = key
	}
	return set
}

// sha256RefRe is the canonical sha256:<64 hex> reference shape. A signed audit
// event's hash-bound fields must be empty or this exact shape; anything else is
// a raw payload smuggled into a hash slot.
var sha256RefRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// maxReferenceBytes bounds an opaque reference field (evidence_pointer,
// resource_id, ...). A field longer than this is not a reference; it is inline
// content, and the verifier rejects it as a raw payload.
const maxReferenceBytes = 512

// hasControlBytes reports whether s contains a NUL or other C0 control byte
// (except the ordinary structural whitespace tab/newline/carriage-return). A
// control byte in an audit field is either corruption or a smuggling attempt.
func hasControlBytes(s string) bool {
	for _, r := range s {
		if r == 0 {
			return true
		}
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return true
		}
		if r == 0x7f {
			return true
		}
	}
	return false
}

// outcomeTokens are the banned business-Outcome / goal / result-graph
// substrings, extending the GA Task 0A public-contract forbiddenPublicFieldName
// ban with common synonyms. This lint is DEFENSE IN DEPTH: the PRIMARY control
// is that the audit plane only ever emits a small, constrained INTERNAL
// vocabulary (action.requested/granted/.../completed and technical status
// values), which structurally cannot carry an Outcome. The lint additionally
// rejects any event whose fields nonetheless contain an Outcome assertion; it is
// a backstop, not a complete tamper-class guarantee against an adversary free to
// choose arbitrary text.
var outcomeTokens = []string{
	"outcome", "goal_achieved", "goal_reached", "goal_met", "goal_complete",
	"objective_met", "objective_achieved", "business_result", "result_graph",
}

// assertsOutcome reports whether any field of the event asserts a business
// Outcome. It scans every author- or binding-controlled opaque field (not just a
// few), plus the standalone result-graph token family, so a synonym in an
// unexpected field is still caught. Hash slots are shape-checked elsewhere.
func assertsOutcome(e Event) bool {
	for _, field := range []string{
		e.Action, e.Decision, e.ResourceType, e.ResourceID, e.EvidencePointer,
		e.Capability, e.StatusFrom, e.RiskAuthority, e.CaseTicketID, e.StepGrantID,
		e.GrantRef, e.ApprovalEvidenceRef, e.ReceiptRef, e.AgentClientRef,
		e.AgentReleaseRef, e.OrgSnapshotRef, e.ID,
	} {
		lower := strings.ToLower(field)
		for _, token := range outcomeTokens {
			if strings.Contains(lower, token) {
				return true
			}
		}
		if graphToken(lower) {
			return true
		}
	}
	return false
}

// graphToken reports whether lower contains a standalone result-graph token
// ("graph", "*_graph", "graph_*") without catching unrelated words.
func graphToken(lower string) bool {
	for _, part := range strings.FieldsFunc(lower, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_'
	}) {
		if part == "graph" || strings.HasPrefix(part, "graph_") || strings.HasSuffix(part, "_graph") {
			return true
		}
	}
	return false
}

// verifyKeyMaterial checks a registered key is a usable ed25519 public key.
func verifyKeyMaterial(key SigningKey) error {
	if key.Algorithm != SignatureAlgorithmEd25519 {
		return ErrBadAlgorithm
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return ErrMalformed
	}
	return nil
}
