package connector

import (
	"regexp"
	"strings"
)

// verification.go declares the GA Task 2 amendment surface (plan revision
// dc81e80, consuming public contract v1.3.0 vocabulary): the technical-safety
// floor, per-write idempotency declarations, available precondition and
// authoritative postcondition probes, and execution/observation receipt schema
// declarations.
//
// Authority boundary (frozen): a connector Product Pack declares HOW its
// technical execution and bounded observations are made and schema'd. It NEVER
// declares, computes or carries a business Outcome, goal_achieved or
// graph-provider semantics -- ActionReceipt attests technical execution only,
// ObservationReceipt proves a bounded authoritative observation, and only the
// calling Agent's deterministic domain runtime turns observed facts into an
// Outcome. A postcondition probe therefore declares exactly the observation
// metadata that lets the platform mint ObservationReceipts per the v1.3.0
// public contract: the source authority tier, the source-version semantics,
// the freshness/staleness bound and a canonical observation schema.

// ProbeIDPattern is the frozen probe identifier form: one lowercase segment,
// unique within its declaring capability (probes are addressed as
// (capability, probe_id) by the execution plane).
const ProbeIDPattern = `^[a-z][a-z0-9_]*$`

var probeIDRe = regexp.MustCompile(ProbeIDPattern)

// SourceAuthority is the frozen source-authority tier vocabulary for a
// postcondition probe: under which authority the probed source reports. The
// certification plane (GA Task 8) accepts only authoritative tiers for
// production observation minting; the SDK freezes the ladder.
type SourceAuthority string

const (
	// SourceAuthoritySystemOfRecord marks the probed source as the system of
	// record for the observed business fact.
	SourceAuthoritySystemOfRecord SourceAuthority = "system_of_record"
	// SourceAuthorityAuthoritativeReplica marks a replica the customer has
	// designated authoritative for reads of the observed fact.
	SourceAuthorityAuthoritativeReplica SourceAuthority = "authoritative_replica"
	// SourceAuthorityDerived marks a computed or cached projection. It is a
	// valid declaration but never an authoritative one.
	SourceAuthorityDerived SourceAuthority = "derived"
)

// Valid reports whether a is one of the frozen source-authority tiers.
func (a SourceAuthority) Valid() bool {
	return a == SourceAuthoritySystemOfRecord || a == SourceAuthorityAuthoritativeReplica || a == SourceAuthorityDerived
}

// Authoritative reports whether the tier may back an authoritative
// post-action observation (system_of_record or authoritative_replica).
// A derived source never counts as authoritative.
func (a SourceAuthority) Authoritative() bool {
	return a == SourceAuthoritySystemOfRecord || a == SourceAuthorityAuthoritativeReplica
}

// SourceVersionSemantics is the frozen vocabulary for HOW the probed source
// expresses the sealed content version an observation reflects; the platform
// seals it into the ObservationReceipt source_version.
type SourceVersionSemantics string

const (
	// SourceVersionMonotonicCounter: the source exposes a monotonically
	// increasing version or change sequence.
	SourceVersionMonotonicCounter SourceVersionSemantics = "monotonic_counter"
	// SourceVersionContentDigest: the source version is a digest over the
	// observed content.
	SourceVersionContentDigest SourceVersionSemantics = "content_digest"
	// SourceVersionLastModified: the source exposes a last-modified timestamp
	// as its version signal.
	SourceVersionLastModified SourceVersionSemantics = "last_modified_timestamp"
)

// Valid reports whether s is one of the frozen source-version semantics.
func (s SourceVersionSemantics) Valid() bool {
	return s == SourceVersionMonotonicCounter || s == SourceVersionContentDigest || s == SourceVersionLastModified
}

// DuplicateSemantics is the frozen vocabulary for what a duplicate write
// (same idempotency key) does at the external system.
type DuplicateSemantics string

const (
	// DuplicateReturnPriorResult: the duplicate replays the original result.
	DuplicateReturnPriorResult DuplicateSemantics = "return_prior_result"
	// DuplicateReject: the duplicate is rejected as already executed.
	DuplicateReject DuplicateSemantics = "reject"
	// DuplicateNoOp: the duplicate is accepted and does nothing.
	DuplicateNoOp DuplicateSemantics = "no_op"
)

// Valid reports whether d is one of the frozen duplicate semantics.
func (d DuplicateSemantics) Valid() bool {
	return d == DuplicateReturnPriorResult || d == DuplicateReject || d == DuplicateNoOp
}

// TechnicalSafetyFloor is the pack-level blast-radius ceiling applied when a
// capability is exercised under a third-party or uncertified decision context
// (Global Constraints: "Third-party Agents require a certified Policy Decision
// Provider and the stricter technical-safety floor"). It is part of the
// product contract and required on every Product Pack. It deliberately does
// NOT duplicate the pack's default envelope (limits), egress classes (network)
// or runtime requirements: the floor is the STRICTER bound layered on top.
type TechnicalSafetyFloor struct {
	// EffectCeiling is the maximum effect reachable under the floor: "read"
	// means third-party/uncertified decisions can never reach a write
	// capability of this pack.
	EffectCeiling Effect `json:"effect_ceiling"`
	// MaxWritesPerMinute bounds the write rate under the floor. 0 means no
	// additional write-rate bound; when both this and the pack envelope's
	// max_requests_per_minute are declared, the floor must not be looser.
	MaxWritesPerMinute int `json:"max_writes_per_minute,omitempty"`
	// MaxPayloadBytes bounds a single request payload under the floor.
	MaxPayloadBytes int `json:"max_payload_bytes,omitempty"`
	// RequireApprovalForWrites requires a transmitted approval plan to be
	// present before any write executes under the floor. AgentNexus enforces
	// presence as an execution constraint; it never chooses approvers.
	RequireApprovalForWrites bool `json:"require_approval_for_writes"`
}

// IdempotencyDeclaration declares, per write capability, how duplicate
// submissions are kept safe: the key derivation scheme, the uniqueness scope
// of the key, and the frozen duplicate-replay semantics at the external
// system. Every write capability must declare one -- the contract never
// permits an at-least-once mutation with undeclared duplicate behavior.
// KeyScheme and Scope are lowercase machine names (the same frozen form as
// probe ids, ProbeIDPattern), never free prose.
type IdempotencyDeclaration struct {
	KeyScheme   string             `json:"key_scheme"`
	Scope       string             `json:"scope"`
	OnDuplicate DuplicateSemantics `json:"on_duplicate"`
}

// PreconditionProbe declares an available pre-execution observation: a
// declared read capability that checks state BEFORE the action executes.
// Declaring one makes it available; the execution plane invokes only declared
// probes.
type PreconditionProbe struct {
	ProbeID     string `json:"probe_id"`
	Capability  string `json:"capability"`
	Description string `json:"description,omitempty"`
}

// PostconditionProbe declares an available authoritative post-execution
// observation of a write capability: WHICH declared read capability performs
// the bounded observation and the observation metadata the platform needs to
// mint a signed ObservationReceipt (contract v1.3.0) -- source authority
// tier, source-version semantics, freshness bound and the canonical
// observation schema. A probe missing any of those is invalid.
type PostconditionProbe struct {
	ProbeID string `json:"probe_id"`
	// Capability names the declared READ capability that performs the probe.
	Capability string `json:"capability"`
	// SourceAuthority is the frozen tier under which the probed source reports.
	SourceAuthority SourceAuthority `json:"source_authority"`
	// SourceVersionSemantics declares how the probed source expresses the
	// sealed content version an observation reflects.
	SourceVersionSemantics SourceVersionSemantics `json:"source_version_semantics"`
	// FreshnessBoundSeconds bounds observation staleness: an observation
	// minted from this probe may be treated as fresh for at most this many
	// seconds after observed-at. Must be positive -- an observation proves a
	// bounded time window.
	FreshnessBoundSeconds int `json:"freshness_bound_seconds"`
	// ObservationSchema is the canonical, digest-referenced schema of the
	// normalized observation content (same reference form as Input/Output).
	ObservationSchema IOSchema `json:"observation_schema"`
	Description       string   `json:"description,omitempty"`
}

// assertsBusinessOutcomeName reports whether a pack-declared machine name
// claims business-outcome or graph-provider authority. The matcher mirrors the
// frozen public runtime-contract semantics (sdk/go/runtime parity gates, GA
// Task 0A amendment) by value: forbidden if the name contains "outcome" or
// "goal_achieved", or if any dotted segment is a graph-provider form (exact
// "graph", prefix "graph_", suffix "_graph"). Applied to declared machine
// names only (capability names, probe ids, schema refs, kinds, strategies,
// key schemes/scopes, field names, egress classes, product keys) -- human
// prose (titles, descriptions, notes) stays free.
func assertsBusinessOutcomeName(name string) bool {
	if strings.Contains(name, "outcome") || strings.Contains(name, "goal_achieved") {
		return true
	}
	for _, segment := range strings.Split(name, ".") {
		if segment == "graph" || strings.HasPrefix(segment, "graph_") || strings.HasSuffix(segment, "_graph") {
			return true
		}
	}
	return false
}
