package connector

import "regexp"

// CapabilityPattern is the frozen business-semantic capability vocabulary. It is
// mirrored byte-for-byte from the public Agent runtime contract
// (sdk/go/runtime, GA Task 0A). A Product Pack declares the SAME semantic
// capabilities the Agent uses; connector topology (instance ids, endpoints,
// table/API paths, credentials) is never a capability. The service parity test
// (internal/connectors/manifest/parity_test.go) proves this constant never
// diverges from the runtime regex and that no second vocabulary exists.
const CapabilityPattern = `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`

// Sha256RefPattern is the canonical digest reference format, mirrored from the
// runtime contract. Every content, SBOM, provenance and schema digest a Product
// Pack references uses this exact shape.
const Sha256RefPattern = `^sha256:[0-9a-f]{64}$`

// SchemaRefPattern constrains an IO schema reference to a semantic, versioned
// artifact id (same namespacing as a capability, e.g.
// schema.erp.purchase_order.approve.input). A raw connection string or API path
// (postgres://, https://host/path, /api/v2/...) can never match, so customer
// topology cannot masquerade as an IO schema reference.
const SchemaRefPattern = CapabilityPattern

var (
	capabilityRe = regexp.MustCompile(CapabilityPattern)
	sha256RefRe  = regexp.MustCompile(Sha256RefPattern)
	schemaRefRe  = regexp.MustCompile(SchemaRefPattern)
)

// Effect declares whether a capability observes (read) or changes (write) a
// system of record. Every write capability must declare its side effects and a
// reconciliation strategy.
type Effect string

const (
	EffectRead  Effect = "read"
	EffectWrite Effect = "write"
)

// Valid reports whether e is one of the frozen effect kinds.
func (e Effect) Valid() bool { return e == EffectRead || e == EffectWrite }

// IsWrite reports whether the capability changes a system of record.
func (e Effect) IsWrite() bool { return e == EffectWrite }

// IOSchema references a versioned, customer-agnostic input or output data
// schema by semantic id plus content digest. The schema body itself is a
// separate signed artifact; a Product Pack never inlines customer-shaped data.
type IOSchema struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// FieldClassification declares the sensitivity of a business (semantic) field.
// It names a field in the capability's IO schema, never a customer column.
type FieldClassification struct {
	Field          string `json:"field"`
	Classification string `json:"classification"`
	Redacted       bool   `json:"redacted,omitempty"`
}

// FieldPolicy is the customer-agnostic field-handling policy: which semantic
// fields are sensitive and how they are treated by default.
type FieldPolicy struct {
	Classifications []FieldClassification `json:"classifications,omitempty"`
	DefaultRedacted bool                  `json:"default_redacted,omitempty"`
}

// SideEffect declares an externally observable consequence of a write
// capability. A write capability must declare at least one.
type SideEffect struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Reversible  bool   `json:"reversible"`
}

// Reconciliation declares how a write is verified and, if necessary,
// compensated after a result-unknown or failure. Every write capability must
// declare one — the contract never permits a fire-and-forget mutation.
type Reconciliation struct {
	Strategy               string `json:"strategy"`
	VerifyCapability       string `json:"verify_capability"`
	CompensationCapability string `json:"compensation_capability,omitempty"`
}

// Capability is a semantic, resellable operation the connector exposes. Its
// name is drawn from the frozen Agent capability vocabulary; its IO is
// referenced by digest; a write declares side effects and reconciliation.
type Capability struct {
	Name           string          `json:"name"`
	Title          string          `json:"title"`
	Description    string          `json:"description,omitempty"`
	Effect         Effect          `json:"effect"`
	Input          IOSchema        `json:"input"`
	Output         IOSchema        `json:"output"`
	FieldPolicy    *FieldPolicy    `json:"field_policy,omitempty"`
	SideEffects    []SideEffect    `json:"side_effects,omitempty"`
	Reconciliation *Reconciliation `json:"reconciliation,omitempty"`
}

// ValidateCapabilityName reports whether name is a frozen business-semantic
// capability (for example erp.purchase_order.approve). It reuses the exact
// runtime regex so the Product Pack and Agent contract share one vocabulary.
func ValidateCapabilityName(name string) error {
	if name == "" {
		return fieldErrorf("capability", "is required")
	}
	if len(name) > 256 {
		return fieldErrorf("capability", "must be at most 256 bytes")
	}
	if !capabilityRe.MatchString(name) {
		return fieldErrorf("capability", "%q is not a namespaced business-semantic capability (for example erp.purchase_order.approve)", name)
	}
	return nil
}
