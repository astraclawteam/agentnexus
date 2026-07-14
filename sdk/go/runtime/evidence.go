package runtime

import "time"

// Constraints bounds a request without ever addressing connector topology.
type Constraints struct {
	// MaxResults caps how many records may be returned.
	MaxResults int64 `json:"max_results,omitempty"`
	// AllowedFields limits the business-semantic fields that may be used.
	AllowedFields []string `json:"allowed_fields,omitempty"`
	// ProhibitedUses names purposes the data must not serve.
	ProhibitedUses []string `json:"prohibited_uses,omitempty"`
}

// Validate applies the canonical Constraints rules.
func (c Constraints) Validate() error {
	if c.MaxResults < 0 {
		return fieldErrorf("max_results", "must be >= 1 when present")
	}
	return nil
}

// DataNeed declares one business-semantic data need. The data class is a
// business vocabulary term (for example "hr.employee_directory"), never a
// connector table, API path or instance selector.
type DataNeed struct {
	NeedID      string       `json:"need_id"`
	DataClass   string       `json:"data_class"`
	Purpose     string       `json:"purpose"`
	Fields      []string     `json:"fields,omitempty"`
	Constraints *Constraints `json:"constraints,omitempty"`
}

// Validate applies the canonical DataNeed rules.
func (n DataNeed) Validate() error {
	if err := requireNonEmpty("need_id", n.NeedID); err != nil {
		return err
	}
	if err := requireNonEmpty("data_class", n.DataClass); err != nil {
		return err
	}
	if err := requireNonEmpty("purpose", n.Purpose); err != nil {
		return err
	}
	if n.Constraints != nil {
		if err := n.Constraints.Validate(); err != nil {
			return fieldErrorf("constraints", "%v", err)
		}
	}
	return nil
}

// EvidenceRequest asks the runtime to locate evidence for declared data
// needs. Trusted identity is bound by the verified PrincipalContext, never by
// this DTO.
type EvidenceRequest struct {
	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id,omitempty"`
	// BusinessContextRef attaches the request to an existing work case; when
	// empty the runtime opens one and returns its handle.
	BusinessContextRef string       `json:"business_context_ref,omitempty"`
	DataNeeds          []DataNeed   `json:"data_needs"`
	Purpose            string       `json:"purpose"`
	Constraints        *Constraints `json:"constraints,omitempty"`
	ExpiresAt          time.Time    `json:"expires_at"`
}

// Validate applies the canonical EvidenceRequest rules.
func (r EvidenceRequest) Validate() error {
	if err := validateRequestID(r.RequestID); err != nil {
		return err
	}
	if r.BusinessContextRef != "" {
		if err := ValidateHandle(r.BusinessContextRef, HandleWorkCase); err != nil {
			return fieldErrorf("business_context_ref", "%v", err)
		}
	}
	if len(r.DataNeeds) == 0 {
		return fieldErrorf("data_needs", "at least one data need is required")
	}
	for i, need := range r.DataNeeds {
		if err := need.Validate(); err != nil {
			return fieldErrorf("data_needs", "[%d]: %v", i, err)
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

// PurposeVerification is the frozen purpose of a verification-purpose read
// (contract v1.4.0, GA Task 0D amendment). A read under this purpose carries
// the all-or-nothing VerificationBinding block and, when allowed, produces a
// signed ObservationReceipt. The coupling is bidirectional: a
// VerificationBinding without this purpose and this purpose without a
// VerificationBinding are BOTH rejected (detached verification reads).
const PurposeVerification = "postcondition_verification"

// VerificationBinding is the OPTIONAL verification block of an
// EvidenceReadRequest (contract v1.4.0, GA Task 0D amendment): it binds the
// original executed Action (action_ref + parameter_hash) and the declared
// PostconditionSpec/VerificationNeed pair this read verifies, and carries the
// need's declared business-semantic data-class expectation (VerificationNeed
// vocabulary - postcondition_id/data_class - plus the ObservationReceipt
// cross-reference name verification_need_id; no parallel vocabulary).
//
// Authority boundary: the block declares WHAT the caller is verifying, never
// how trustworthy the observation is. Source authority, sealed source
// version, observed-at and freshness are DERIVED SERVER-SIDE and can never be
// supplied here - no field of this type can represent them, and the strict
// request decoder rejects the unknown keys. The resulting ObservationReceipt
// proves what an authorized source reported at a bounded time; AgentNexus
// never interprets domain success and never asserts a business Outcome.
type VerificationBinding struct {
	// ActionRef and ParameterHash bind the original executed Action.
	ActionRef     string `json:"action_ref"`
	ParameterHash string `json:"parameter_hash"`
	// PostconditionID references the declared PostconditionSpec under
	// verification; VerificationNeedID references the declared
	// VerificationNeed being satisfied.
	PostconditionID    string `json:"postcondition_id"`
	VerificationNeedID string `json:"verification_need_id"`
	// DataClass is the need's declared business-semantic data class; it must
	// match the data class of the evidence handle actually read (mismatched
	// verification needs are rejected).
	DataClass string `json:"data_class"`
}

// Validate applies the canonical VerificationBinding rules: the block is
// all-or-nothing, so every member is required and validated by the frozen
// v1.3.0 validators.
func (b VerificationBinding) Validate() error {
	if err := ValidateHandle(b.ActionRef, HandleAction); err != nil {
		return fieldErrorf("action_ref", "%v", err)
	}
	if err := ValidateSHA256Ref(b.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if err := requireNonEmpty("postcondition_id", b.PostconditionID); err != nil {
		return err
	}
	if err := requireNonEmpty("verification_need_id", b.VerificationNeedID); err != nil {
		return err
	}
	return requireNonEmpty("data_class", b.DataClass)
}

// EvidenceReadRequest reads one located evidence handle under policy. It is
// the SDK expression of the /v1/runtime/read operation and of
// agentnexus.evidence.v1.EvidenceReadRequest.
type EvidenceReadRequest struct {
	RequestID          string       `json:"request_id"`
	TraceID            string       `json:"trace_id,omitempty"`
	BusinessContextRef string       `json:"business_context_ref"`
	EvidenceRef        string       `json:"evidence_ref"`
	Fields             []string     `json:"fields,omitempty"`
	Purpose            string       `json:"purpose"`
	Constraints        *Constraints `json:"constraints,omitempty"`
	// VerificationBinding is the OPTIONAL verification block (contract
	// v1.4.0): present exactly when Purpose is PurposeVerification.
	VerificationBinding *VerificationBinding `json:"verification_binding,omitempty"`
	ExpiresAt           time.Time            `json:"expires_at"`
}

// Validate applies the canonical EvidenceReadRequest rules, including the
// bidirectional coupling of the verification block and the frozen
// verification purpose (a detached verification read is rejected).
func (r EvidenceReadRequest) Validate() error {
	if err := validateRequestID(r.RequestID); err != nil {
		return err
	}
	if r.BusinessContextRef == "" {
		return fieldErrorf("business_context_ref", "is required")
	}
	if err := ValidateHandle(r.BusinessContextRef, HandleWorkCase); err != nil {
		return fieldErrorf("business_context_ref", "%v", err)
	}
	if err := ValidateHandle(r.EvidenceRef, HandleEvidence); err != nil {
		return fieldErrorf("evidence_ref", "%v", err)
	}
	if err := requireNonEmpty("purpose", r.Purpose); err != nil {
		return err
	}
	if r.Constraints != nil {
		if err := r.Constraints.Validate(); err != nil {
			return fieldErrorf("constraints", "%v", err)
		}
	}
	if r.VerificationBinding != nil {
		if err := r.VerificationBinding.Validate(); err != nil {
			return fieldErrorf("verification_binding", "%v", err)
		}
		if r.Purpose != PurposeVerification {
			return fieldErrorf("purpose", "a verification binding requires the frozen verification purpose %q; a detached verification binding is rejected", PurposeVerification)
		}
	} else if r.Purpose == PurposeVerification {
		return fieldErrorf("verification_binding", "the verification purpose %q requires a verification binding; a detached verification purpose is rejected", PurposeVerification)
	}
	if r.ExpiresAt.IsZero() {
		return fieldErrorf("expires_at", "is required")
	}
	return nil
}

// EvidenceHandle is the opaque, typed handle through which located evidence
// is addressed. It never reveals connector instances, endpoints or paths.
type EvidenceHandle struct {
	EvidenceRef string    `json:"evidence_ref"`
	DataClass   string    `json:"data_class"`
	Summary     string    `json:"summary,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
}

// Validate applies the canonical EvidenceHandle rules.
func (h EvidenceHandle) Validate() error {
	if err := ValidateHandle(h.EvidenceRef, HandleEvidence); err != nil {
		return fieldErrorf("evidence_ref", "%v", err)
	}
	return requireNonEmpty("data_class", h.DataClass)
}
