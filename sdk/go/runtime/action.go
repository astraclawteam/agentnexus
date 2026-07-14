package runtime

import (
	"encoding/json"
	"time"
)

// ActionStatus is the frozen Action lifecycle. GA Task 0F implements the
// state machine; the states themselves are frozen here and mirrored by
// agentnexus.actions.v1.ActionStatus and the OpenAPI ActionStatus schema.
type ActionStatus string

const (
	StatusRequested        ActionStatus = "requested"
	StatusAwaitingApproval ActionStatus = "awaiting_approval"
	StatusGranted          ActionStatus = "granted"
	StatusDispatched       ActionStatus = "dispatched"
	StatusExecuting        ActionStatus = "executing"
	StatusSucceeded        ActionStatus = "succeeded"
	StatusFailed           ActionStatus = "failed"
	StatusResultUnknown    ActionStatus = "result_unknown"
	StatusReconciling      ActionStatus = "reconciling"
	StatusCompensating     ActionStatus = "compensating"
	StatusHumanTakeover    ActionStatus = "human_takeover"
)

// ActionStatuses returns the frozen states in their frozen order.
func ActionStatuses() []ActionStatus {
	return []ActionStatus{
		StatusRequested, StatusAwaitingApproval, StatusGranted, StatusDispatched,
		StatusExecuting, StatusSucceeded, StatusFailed, StatusResultUnknown,
		StatusReconciling, StatusCompensating, StatusHumanTakeover,
	}
}

// Valid reports whether the status is one of the frozen states.
func (s ActionStatus) Valid() bool {
	switch s {
	case StatusRequested, StatusAwaitingApproval, StatusGranted, StatusDispatched,
		StatusExecuting, StatusSucceeded, StatusFailed, StatusResultUnknown,
		StatusReconciling, StatusCompensating, StatusHumanTakeover:
		return true
	}
	return false
}

// BusinessCapabilityRequest asks whether — and under which constraints — a
// business-semantic capability may be exercised inside a business context.
// It precedes an ActionRequest; parameters may not exist yet, so the
// parameter hash is optional here and mandatory on the ActionRequest.
type BusinessCapabilityRequest struct {
	RequestID          string       `json:"request_id"`
	TraceID            string       `json:"trace_id,omitempty"`
	BusinessContextRef string       `json:"business_context_ref,omitempty"`
	Capability         string       `json:"capability"`
	ParameterHash      string       `json:"parameter_hash,omitempty"`
	Purpose            string       `json:"purpose"`
	Constraints        *Constraints `json:"constraints,omitempty"`
	ExpiresAt          time.Time    `json:"expires_at"`
}

// Validate applies the canonical BusinessCapabilityRequest rules.
func (r BusinessCapabilityRequest) Validate() error {
	if err := validateRequestID(r.RequestID); err != nil {
		return err
	}
	if r.BusinessContextRef != "" {
		if err := ValidateHandle(r.BusinessContextRef, HandleWorkCase); err != nil {
			return fieldErrorf("business_context_ref", "%v", err)
		}
	}
	if err := validateCapability(r.Capability); err != nil {
		return err
	}
	if r.ParameterHash != "" {
		if err := ValidateSHA256Ref(r.ParameterHash); err != nil {
			return fieldErrorf("parameter_hash", "%v", err)
		}
	}
	if err := requireNonEmpty("purpose", r.Purpose); err != nil {
		return err
	}
	if r.Constraints != nil {
		if err := r.Constraints.Validate(); err != nil {
			return fieldErrorf("constraints", "%v", err)
		}
	}
	if r.ExpiresAt.IsZero() {
		return fieldErrorf("expires_at", "is required")
	}
	return nil
}

// Precondition states an assumption that must still hold when the action is
// executed (for example a state hash captured while drafting).
type Precondition struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
	Expected  string `json:"expected,omitempty"`
}

// Validate applies the canonical Precondition rules.
func (p Precondition) Validate() error {
	if p.Kind == "" || p.Reference == "" {
		return fieldErrorf("precondition", "kind and reference are required")
	}
	return nil
}

// PostconditionSpec declares one business-state condition expected to hold
// AFTER the action executed (contract v1.3.0, GA Task 0A amendment). It is
// declared by the calling Agent and later checked by a verification
// observation; AgentNexus records and transmits it but never evaluates
// whether the business goal behind it was achieved.
type PostconditionSpec struct {
	// PostconditionID is the request-scoped identifier VerificationNeed and
	// ObservationReceipt bind to.
	PostconditionID string `json:"postcondition_id"`
	Kind            string `json:"kind"`
	Reference       string `json:"reference"`
	Expected        string `json:"expected,omitempty"`
}

// Validate applies the canonical PostconditionSpec rules; an empty or
// unidentified spec is rejected.
func (p PostconditionSpec) Validate() error {
	if err := requireNonEmpty("postcondition_id", p.PostconditionID); err != nil {
		return err
	}
	if err := requireNonEmpty("kind", p.Kind); err != nil {
		return err
	}
	return requireNonEmpty("reference", p.Reference)
}

// VerificationNeed declares one post-action verification data need
// (contract v1.3.0, GA Task 0A amendment): it binds exactly one declared
// postcondition to a business-semantic data class whose authorized source
// will be observed after execution. The data class is business vocabulary,
// never a connector table, API path or instance selector. A satisfied
// verification need produces a signed ObservationReceipt.
type VerificationNeed struct {
	// NeedID is the request-scoped identifier ObservationReceipt binds to.
	NeedID string `json:"need_id"`
	// PostconditionID references the declared PostconditionSpec this need
	// verifies; an unbound verification need is rejected.
	PostconditionID string `json:"postcondition_id"`
	DataClass       string `json:"data_class"`
}

// Validate applies the canonical VerificationNeed rules; an empty or unbound
// need is rejected.
func (n VerificationNeed) Validate() error {
	if err := requireNonEmpty("need_id", n.NeedID); err != nil {
		return err
	}
	if err := requireNonEmpty("postcondition_id", n.PostconditionID); err != nil {
		return err
	}
	return requireNonEmpty("data_class", n.DataClass)
}

// ActionRequest is the only way an Agent asks for a side effect. It binds the
// Agent client and release through the verified PrincipalContext (never
// through this JSON), the work case, the business-semantic capability, the
// exact hash-bound parameters, the signed RiskDecision of the calling
// authority, the transmitted approval plan, an idempotency key,
// preconditions, postconditions, verification needs, an expiry, the expected
// execution-receipt schema and an optional compensation reference.
type ActionRequest struct {
	RequestID          string          `json:"request_id"`
	TraceID            string          `json:"trace_id,omitempty"`
	BusinessContextRef string          `json:"business_context_ref"`
	Capability         string          `json:"capability"`
	Parameters         json.RawMessage `json:"parameters"`
	ParameterHash      string          `json:"parameter_hash"`
	Purpose            string          `json:"purpose"`
	Constraints        *Constraints    `json:"constraints,omitempty"`
	RiskDecision       RiskDecision    `json:"risk_decision"`
	// ApprovalPlanRef references the approval plan authored by the approval
	// authority. AgentNexus transmits it and never authors it.
	ApprovalPlanRef *ApprovalPlanRef `json:"approval_plan_ref,omitempty"`
	IdempotencyKey  string           `json:"idempotency_key"`
	Preconditions   []Precondition   `json:"preconditions,omitempty"`
	// Postconditions declare the post-state conditions verification
	// observations bind to (contract v1.3.0); optional, validated per entry.
	Postconditions []PostconditionSpec `json:"postconditions,omitempty"`
	// VerificationNeeds declare the exact post-action verification reads the
	// caller requests; each must bind one declared postcondition. Only these
	// declared needs may ever be verified (contract v1.3.0).
	VerificationNeeds     []VerificationNeed `json:"verification_needs,omitempty"`
	ExpiresAt             time.Time          `json:"expires_at"`
	ExpectedReceiptSchema string             `json:"expected_receipt_schema"`
	CompensationRef       string             `json:"compensation_ref,omitempty"`
}

// Validate applies the canonical ActionRequest rules, including the exact
// operation binding between the request and its signed RiskDecision.
func (r ActionRequest) Validate() error {
	if err := validateRequestID(r.RequestID); err != nil {
		return err
	}
	if r.BusinessContextRef == "" {
		return fieldErrorf("business_context_ref", "is required")
	}
	if err := ValidateHandle(r.BusinessContextRef, HandleWorkCase); err != nil {
		return fieldErrorf("business_context_ref", "%v", err)
	}
	if err := validateCapability(r.Capability); err != nil {
		return err
	}
	if len(r.Parameters) == 0 {
		return fieldErrorf("parameters", "typed capability parameters are required")
	}
	if !isJSONObject(r.Parameters) {
		return fieldErrorf("parameters", "must be a single JSON object of capability-typed parameters")
	}
	if r.ParameterHash == "" {
		return fieldErrorf("parameter_hash", "is required")
	}
	if err := ValidateSHA256Ref(r.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if HashParameters(r.Parameters) != r.ParameterHash {
		return fieldErrorf("parameter_hash", "parameter_hash does not match the exact parameter bytes")
	}
	if err := requireNonEmpty("purpose", r.Purpose); err != nil {
		return err
	}
	if r.Constraints != nil {
		if err := r.Constraints.Validate(); err != nil {
			return fieldErrorf("constraints", "%v", err)
		}
	}
	if err := r.RiskDecision.Validate(); err != nil {
		return fieldErrorf("risk_decision", "%v", err)
	}
	if r.RiskDecision.Capability != r.Capability {
		return fieldErrorf("risk_decision", "capability binding %q does not match request capability %q", r.RiskDecision.Capability, r.Capability)
	}
	if r.RiskDecision.ParameterHash != r.ParameterHash {
		return fieldErrorf("risk_decision", "parameter hash binding does not match the request")
	}
	if r.RiskDecision.BusinessContextRef != r.BusinessContextRef {
		return fieldErrorf("risk_decision", "business context binding does not match the request")
	}
	if r.ApprovalPlanRef != nil {
		if err := r.ApprovalPlanRef.Validate(); err != nil {
			return fieldErrorf("approval_plan_ref", "%v", err)
		}
	}
	if err := validateIdempotencyKey(r.IdempotencyKey); err != nil {
		return err
	}
	for i, precondition := range r.Preconditions {
		if err := precondition.Validate(); err != nil {
			return fieldErrorf("preconditions", "[%d]: %v", i, err)
		}
	}
	postconditionIDs := make(map[string]bool, len(r.Postconditions))
	for i, postcondition := range r.Postconditions {
		if err := postcondition.Validate(); err != nil {
			return fieldErrorf("postconditions", "[%d]: %v", i, err)
		}
		if postconditionIDs[postcondition.PostconditionID] {
			return fieldErrorf("postconditions", "[%d]: duplicate postcondition_id %q makes verification bindings ambiguous", i, postcondition.PostconditionID)
		}
		postconditionIDs[postcondition.PostconditionID] = true
	}
	needIDs := make(map[string]bool, len(r.VerificationNeeds))
	for i, need := range r.VerificationNeeds {
		if err := need.Validate(); err != nil {
			return fieldErrorf("verification_needs", "[%d]: %v", i, err)
		}
		if needIDs[need.NeedID] {
			return fieldErrorf("verification_needs", "[%d]: duplicate need_id %q makes observation bindings ambiguous", i, need.NeedID)
		}
		needIDs[need.NeedID] = true
		if !postconditionIDs[need.PostconditionID] {
			return fieldErrorf("verification_needs", "[%d]: postcondition_id %q does not reference a declared postcondition", i, need.PostconditionID)
		}
	}
	if r.ExpiresAt.IsZero() {
		return fieldErrorf("expires_at", "is required")
	}
	if err := requireNonEmpty("expected_receipt_schema", r.ExpectedReceiptSchema); err != nil {
		return err
	}
	return nil
}

// Action is the runtime's view of one requested side effect.
type Action struct {
	ActionRef           string       `json:"action_ref"`
	Status              ActionStatus `json:"status"`
	BusinessContextRef  string       `json:"business_context_ref"`
	Capability          string       `json:"capability"`
	ParameterHash       string       `json:"parameter_hash"`
	GrantRef            string       `json:"grant_ref,omitempty"`
	ApprovalEvidenceRef string       `json:"approval_evidence_ref,omitempty"`
	ReceiptRef          string       `json:"receipt_ref,omitempty"`
	UpdatedAt           time.Time    `json:"updated_at,omitzero"`
}

// Validate applies the canonical Action rules.
func (a Action) Validate() error {
	if err := ValidateHandle(a.ActionRef, HandleAction); err != nil {
		return fieldErrorf("action_ref", "%v", err)
	}
	if !a.Status.Valid() {
		return fieldErrorf("status", "%q is not a frozen action status", a.Status)
	}
	if err := ValidateHandle(a.BusinessContextRef, HandleWorkCase); err != nil {
		return fieldErrorf("business_context_ref", "%v", err)
	}
	if err := validateCapability(a.Capability); err != nil {
		return err
	}
	if err := ValidateSHA256Ref(a.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if a.GrantRef != "" {
		if err := ValidateHandle(a.GrantRef, HandleGrant); err != nil {
			return fieldErrorf("grant_ref", "%v", err)
		}
	}
	if a.ApprovalEvidenceRef != "" {
		if err := ValidateHandle(a.ApprovalEvidenceRef, HandleApprovalEvidence); err != nil {
			return fieldErrorf("approval_evidence_ref", "%v", err)
		}
	}
	if a.ReceiptRef != "" {
		if err := ValidateHandle(a.ReceiptRef, HandleReceipt); err != nil {
			return fieldErrorf("receipt_ref", "%v", err)
		}
	}
	return nil
}
