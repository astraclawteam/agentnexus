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
	ExpiresAt          time.Time    `json:"expires_at"`
}

// Validate applies the canonical EvidenceReadRequest rules.
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
