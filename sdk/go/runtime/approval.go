package runtime

import (
	"strings"
	"time"
)

// SignatureAlgorithmEd25519 is the only signature algorithm frozen for
// contract v1.
const SignatureAlgorithmEd25519 = "ed25519"

// Signature is a detached signature by a named key of a trusted authority.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	// Value carries the base64-encoded signature bytes.
	Value string `json:"value"`
}

// Validate applies the canonical Signature rules. A zero signature is
// rejected: unsigned authority claims never enter the runtime.
func (s Signature) Validate() error {
	if s == (Signature{}) {
		return fieldErrorf("signature", "is required; unsigned authority claims are rejected")
	}
	if s.Algorithm == "" {
		return fieldErrorf("algorithm", "is required")
	}
	if s.Algorithm != SignatureAlgorithmEd25519 {
		return fieldErrorf("algorithm", "%q is not a frozen v1 signature algorithm", s.Algorithm)
	}
	if s.KeyID == "" {
		return fieldErrorf("key_id", "is required")
	}
	if s.Value == "" {
		return fieldErrorf("value", "is required")
	}
	return nil
}

// RiskLevel is the frozen risk classification vocabulary.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// Valid reports whether the risk level is one of the frozen levels.
func (l RiskLevel) Valid() bool {
	switch l {
	case RiskLow, RiskMedium, RiskHigh:
		return true
	}
	return false
}

// RiskDecision is the signed risk verdict of the calling risk authority
// (a first-party Agent platform or a certified provider). AgentNexus
// verifies and transmits it; it never authors one. The decision binds the
// exact operation: capability, parameter hash and business context.
type RiskDecision struct {
	DecisionID         string    `json:"decision_id"`
	Authority          string    `json:"authority"`
	RiskLevel          RiskLevel `json:"risk_level"`
	Reasons            []string  `json:"reasons,omitempty"`
	Capability         string    `json:"capability"`
	ParameterHash      string    `json:"parameter_hash"`
	BusinessContextRef string    `json:"business_context_ref"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Signature          Signature `json:"signature"`
}

// Validate applies the canonical RiskDecision rules; an unsigned or unbound
// decision is rejected.
func (d RiskDecision) Validate() error {
	if err := requireNonEmpty("decision_id", d.DecisionID); err != nil {
		return err
	}
	if err := requireNonEmpty("authority", d.Authority); err != nil {
		return err
	}
	if !d.RiskLevel.Valid() {
		return fieldErrorf("risk_level", "%q is not a frozen risk level", d.RiskLevel)
	}
	if err := validateCapability(d.Capability); err != nil {
		return err
	}
	if d.ParameterHash == "" {
		return fieldErrorf("parameter_hash", "is required; a risk decision binds the exact operation")
	}
	if err := ValidateSHA256Ref(d.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if d.BusinessContextRef == "" {
		return fieldErrorf("business_context_ref", "is required")
	}
	if err := ValidateHandle(d.BusinessContextRef, HandleWorkCase); err != nil {
		return fieldErrorf("business_context_ref", "%v", err)
	}
	if d.IssuedAt.IsZero() {
		return fieldErrorf("issued_at", "is required")
	}
	if d.ExpiresAt.IsZero() {
		return fieldErrorf("expires_at", "is required")
	}
	if !d.ExpiresAt.After(d.IssuedAt) {
		return fieldErrorf("expires_at", "must be after issued_at")
	}
	return d.Signature.Validate()
}

// ApprovalPlanRef references an approval plan authored by the approval
// authority and bound by digest. AgentNexus transmits plans; it never
// authors them.
type ApprovalPlanRef struct {
	PlanRef   string `json:"plan_ref"`
	PlanHash  string `json:"plan_hash"`
	Authority string `json:"authority"`
}

// Validate applies the canonical ApprovalPlanRef rules.
func (p ApprovalPlanRef) Validate() error {
	if err := ValidateHandle(p.PlanRef, HandleApprovalPlan); err != nil {
		return fieldErrorf("plan_ref", "%v", err)
	}
	if p.PlanHash == "" {
		return fieldErrorf("plan_hash", "is required")
	}
	if err := ValidateSHA256Ref(p.PlanHash); err != nil {
		return fieldErrorf("plan_hash", "%v", err)
	}
	if err := requireNonEmpty("authority", p.Authority); err != nil {
		return err
	}
	if strings.EqualFold(p.Authority, "agentnexus") {
		return fieldErrorf("authority", "agentnexus never authors approval plans; the plan authority must be the calling approval authority")
	}
	return nil
}

// ApprovalRequest asks the approval authority to route one exact governed
// operation.
type ApprovalRequest struct {
	RequestID          string          `json:"request_id"`
	TraceID            string          `json:"trace_id,omitempty"`
	BusinessContextRef string          `json:"business_context_ref"`
	Capability         string          `json:"capability"`
	ParameterHash      string          `json:"parameter_hash"`
	Purpose            string          `json:"purpose"`
	Plan               ApprovalPlanRef `json:"plan"`
	ExpiresAt          time.Time       `json:"expires_at"`
}

// Validate applies the canonical ApprovalRequest rules.
func (r ApprovalRequest) Validate() error {
	if err := validateRequestID(r.RequestID); err != nil {
		return err
	}
	if err := ValidateHandle(r.BusinessContextRef, HandleWorkCase); err != nil {
		return fieldErrorf("business_context_ref", "%v", err)
	}
	if err := validateCapability(r.Capability); err != nil {
		return err
	}
	if err := ValidateSHA256Ref(r.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if err := requireNonEmpty("purpose", r.Purpose); err != nil {
		return err
	}
	if err := r.Plan.Validate(); err != nil {
		return fieldErrorf("plan", "%v", err)
	}
	if r.ExpiresAt.IsZero() {
		return fieldErrorf("expires_at", "is required")
	}
	return nil
}

// ApprovalDecision is the frozen approval outcome vocabulary.
type ApprovalDecision string

const (
	ApprovalApproved ApprovalDecision = "approved"
	ApprovalDenied   ApprovalDecision = "denied"
	ApprovalNarrowed ApprovalDecision = "narrowed"
)

// Valid reports whether the decision is one of the frozen outcomes.
func (d ApprovalDecision) Valid() bool {
	switch d {
	case ApprovalApproved, ApprovalDenied, ApprovalNarrowed:
		return true
	}
	return false
}

// ApprovalEvidence is the attested proof that the approval authority decided
// one exact operation. It is produced by the authority, never by AgentNexus.
type ApprovalEvidence struct {
	ApprovalRef       string           `json:"approval_ref"`
	PlanRef           string           `json:"plan_ref"`
	PlanHash          string           `json:"plan_hash"`
	Capability        string           `json:"capability"`
	ParameterHash     string           `json:"parameter_hash"`
	Decision          ApprovalDecision `json:"decision"`
	ApproverAuthority string           `json:"approver_authority"`
	DecidedAt         time.Time        `json:"decided_at"`
	Attestation       Signature        `json:"attestation"`
}

// Validate applies the canonical ApprovalEvidence rules.
func (e ApprovalEvidence) Validate() error {
	if err := ValidateHandle(e.ApprovalRef, HandleApprovalEvidence); err != nil {
		return fieldErrorf("approval_ref", "%v", err)
	}
	if err := ValidateHandle(e.PlanRef, HandleApprovalPlan); err != nil {
		return fieldErrorf("plan_ref", "%v", err)
	}
	if err := ValidateSHA256Ref(e.PlanHash); err != nil {
		return fieldErrorf("plan_hash", "%v", err)
	}
	if err := validateCapability(e.Capability); err != nil {
		return err
	}
	if err := ValidateSHA256Ref(e.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if !e.Decision.Valid() {
		return fieldErrorf("decision", "%q is not a frozen approval decision", e.Decision)
	}
	if err := requireNonEmpty("approver_authority", e.ApproverAuthority); err != nil {
		return err
	}
	if e.DecidedAt.IsZero() {
		return fieldErrorf("decided_at", "is required")
	}
	if err := e.Attestation.Validate(); err != nil {
		return fieldErrorf("attestation", "%v", err)
	}
	return nil
}

// StepGrant authorizes exactly one exact sensitive operation: one capability
// with one parameter hash inside one business context, once, until expiry.
type StepGrant struct {
	GrantRef           string    `json:"grant_ref"`
	BusinessContextRef string    `json:"business_context_ref"`
	Capability         string    `json:"capability"`
	ParameterHash      string    `json:"parameter_hash"`
	OneUse             bool      `json:"one_use"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// Validate applies the canonical StepGrant rules; a grant not bound to one
// exact operation, or reusable, is rejected.
func (g StepGrant) Validate() error {
	if err := ValidateHandle(g.GrantRef, HandleGrant); err != nil {
		return fieldErrorf("grant_ref", "%v", err)
	}
	if g.BusinessContextRef == "" {
		return fieldErrorf("business_context_ref", "is required")
	}
	if err := ValidateHandle(g.BusinessContextRef, HandleWorkCase); err != nil {
		return fieldErrorf("business_context_ref", "%v", err)
	}
	if err := validateCapability(g.Capability); err != nil {
		return err
	}
	if g.ParameterHash == "" {
		return fieldErrorf("parameter_hash", "is required; a step grant binds the exact operation")
	}
	if err := ValidateSHA256Ref(g.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if !g.OneUse {
		return fieldErrorf("one_use", "a step grant is one-use by contract")
	}
	if g.IssuedAt.IsZero() {
		return fieldErrorf("issued_at", "is required")
	}
	if g.ExpiresAt.IsZero() {
		return fieldErrorf("expires_at", "is required")
	}
	if !g.ExpiresAt.After(g.IssuedAt) {
		return fieldErrorf("expires_at", "must be after issued_at")
	}
	return nil
}
