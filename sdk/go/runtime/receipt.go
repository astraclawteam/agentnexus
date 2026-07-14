package runtime

import (
	"encoding/json"
	"time"
)

// ActionReceipt is the runtime's account of what actually happened to one
// Action. The result payload is hash-bound; the receipt schema names the
// typed shape the caller declared in ActionRequest.ExpectedReceiptSchema.
// GA Task 0G adds receipt signing; the signature slot is frozen here.
type ActionReceipt struct {
	ReceiptRef    string          `json:"receipt_ref"`
	ActionRef     string          `json:"action_ref"`
	Status        ActionStatus    `json:"status"`
	Capability    string          `json:"capability"`
	ParameterHash string          `json:"parameter_hash"`
	ReceiptSchema string          `json:"receipt_schema"`
	Result        json.RawMessage `json:"result,omitempty"`
	ResultHash    string          `json:"result_hash,omitempty"`
	IssuedAt      time.Time       `json:"issued_at"`
	Signature     *Signature      `json:"signature,omitempty"`
}

// Validate applies the canonical ActionReceipt rules.
func (r ActionReceipt) Validate() error {
	if err := ValidateHandle(r.ReceiptRef, HandleReceipt); err != nil {
		return fieldErrorf("receipt_ref", "%v", err)
	}
	if err := ValidateHandle(r.ActionRef, HandleAction); err != nil {
		return fieldErrorf("action_ref", "%v", err)
	}
	if !r.Status.Valid() {
		return fieldErrorf("status", "%q is not a frozen action status", r.Status)
	}
	if err := validateCapability(r.Capability); err != nil {
		return err
	}
	if err := ValidateSHA256Ref(r.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if err := requireNonEmpty("receipt_schema", r.ReceiptSchema); err != nil {
		return err
	}
	if len(r.Result) > 0 {
		if !isJSONObject(r.Result) {
			return fieldErrorf("result", "must be a single JSON object typed by receipt_schema")
		}
		if r.ResultHash == "" {
			return fieldErrorf("result_hash", "is required when a result is present")
		}
		if HashParameters(r.Result) != r.ResultHash {
			return fieldErrorf("result_hash", "result_hash does not match the exact result bytes")
		}
	} else if r.ResultHash != "" {
		if err := ValidateSHA256Ref(r.ResultHash); err != nil {
			return fieldErrorf("result_hash", "%v", err)
		}
	}
	if r.IssuedAt.IsZero() {
		return fieldErrorf("issued_at", "is required")
	}
	if r.Signature != nil {
		if err := r.Signature.Validate(); err != nil {
			return fieldErrorf("signature", "%v", err)
		}
	}
	return nil
}

// ObservationReceipt is the signed proof of what an authorized source
// reported at a bounded time about one declared postcondition of one
// executed Action (contract v1.3.0, GA Task 0A amendment).
//
// Authority boundary: ActionReceipt attests technical execution only;
// ObservationReceipt proves a bounded authoritative observation; NEITHER
// type contains a business Outcome assertion. AgentNexus never decides
// whether a business goal or Outcome was achieved and never owns or queries
// the calling Agent platform's result graph — only the calling Agent's
// deterministic domain runtime turns observed facts into an Outcome.
//
// The receipt binds the original Action and parameter hash, the declared
// PostconditionSpec/VerificationNeed pair, the reporting source and its
// sealed content version, the source authority, the observed-at/freshness
// bounds, the sha256 hash of the NORMALIZED observation and the evidence
// handle carrying the observation content (handle-addressed like
// receipt_ref: the payload is never embedded), the audit reference, and the
// AgentNexus signature over the canonicalized receipt. Unlike ActionReceipt
// (whose signing slot activates with GA Task 0G) the signature here is
// REQUIRED: an unsigned observation is not an ObservationReceipt.
type ObservationReceipt struct {
	// ObservationRef is the opaque obs_* handle of this receipt.
	ObservationRef string `json:"observation_ref"`
	// ActionRef and ParameterHash bind the original executed Action.
	ActionRef     string `json:"action_ref"`
	ParameterHash string `json:"parameter_hash"`
	// PostconditionID and VerificationNeedID bind the declared
	// PostconditionSpec/VerificationNeed pair of the original ActionRequest.
	PostconditionID    string `json:"postcondition_id"`
	VerificationNeedID string `json:"verification_need_id"`
	// Source is the business-semantic identity of the authorized source that
	// reported the observation; never a connector instance, endpoint or path.
	Source string `json:"source"`
	// SourceVersion is the sealed source content version the observation
	// reflects; source versions start at 1.
	SourceVersion int64 `json:"source_version"`
	// Authority names the authority under which the source reported.
	Authority string `json:"authority"`
	// ObservedAt and FreshUntil bound the observation in time: the fact was
	// reported at ObservedAt and may be treated as fresh until FreshUntil.
	ObservedAt time.Time `json:"observed_at"`
	FreshUntil time.Time `json:"fresh_until"`
	// ObservationHash is the sha256 digest of the normalized observation.
	ObservationHash string `json:"observation_hash"`
	// EvidenceRef is the opaque evd_* handle carrying the observation content.
	EvidenceRef string `json:"evidence_ref"`
	// AuditRefID references the audit chain entry recording this observation.
	AuditRefID string `json:"audit_ref_id"`
	// Signature is the REQUIRED AgentNexus signature over the canonicalized
	// receipt.
	Signature Signature `json:"signature"`
}

// Validate applies the canonical ObservationReceipt rules: a receipt without
// source/version/authority/freshness and Action/Postcondition binding, or
// without the AgentNexus signature, is rejected.
func (r ObservationReceipt) Validate() error {
	if err := ValidateHandle(r.ObservationRef, HandleObservation); err != nil {
		return fieldErrorf("observation_ref", "%v", err)
	}
	if err := ValidateHandle(r.ActionRef, HandleAction); err != nil {
		return fieldErrorf("action_ref", "%v", err)
	}
	if err := ValidateSHA256Ref(r.ParameterHash); err != nil {
		return fieldErrorf("parameter_hash", "%v", err)
	}
	if err := requireNonEmpty("postcondition_id", r.PostconditionID); err != nil {
		return err
	}
	if err := requireNonEmpty("verification_need_id", r.VerificationNeedID); err != nil {
		return err
	}
	if err := requireNonEmpty("source", r.Source); err != nil {
		return err
	}
	if r.SourceVersion < 1 {
		return fieldErrorf("source_version", "is required; source versions start at 1")
	}
	if err := requireNonEmpty("authority", r.Authority); err != nil {
		return err
	}
	if r.ObservedAt.IsZero() {
		return fieldErrorf("observed_at", "is required")
	}
	if r.FreshUntil.IsZero() {
		return fieldErrorf("fresh_until", "is required")
	}
	if !r.FreshUntil.After(r.ObservedAt) {
		return fieldErrorf("fresh_until", "must be after observed_at; an observation proves a bounded time window")
	}
	if err := ValidateSHA256Ref(r.ObservationHash); err != nil {
		return fieldErrorf("observation_hash", "%v", err)
	}
	if err := ValidateHandle(r.EvidenceRef, HandleEvidence); err != nil {
		return fieldErrorf("evidence_ref", "%v", err)
	}
	if err := requireNonEmpty("audit_ref_id", r.AuditRefID); err != nil {
		return err
	}
	if err := r.Signature.Validate(); err != nil {
		return fieldErrorf("signature", "%v", err)
	}
	return nil
}

// AuditEvent is one link of the tenant-sequenced audit chain. It binds the
// verified principal, the Agent client release, the sealed organization
// snapshot, the exact operation, the signed risk decision, the approval
// evidence, the grant, the action transition and the receipt. GA Task 0G
// implements chain signing; the fields are frozen here.
// (Placement note: AuditEvent lives in receipt.go per the frozen Task 0A
// file list; there is intentionally no separate audit.go.)
type AuditEvent struct {
	EventID             string       `json:"event_id"`
	TenantRef           string       `json:"tenant_ref"`
	TenantSeq           uint64       `json:"tenant_seq"`
	BusinessContextRef  string       `json:"business_context_ref,omitempty"`
	PrincipalRef        string       `json:"principal_ref"`
	AgentClientRef      string       `json:"agent_client_ref,omitempty"`
	AgentReleaseRef     string       `json:"agent_release_ref,omitempty"`
	OrgSnapshotRef      string       `json:"org_snapshot_ref,omitempty"`
	Capability          string       `json:"capability,omitempty"`
	ParameterHash       string       `json:"parameter_hash,omitempty"`
	RiskDecisionRef     string       `json:"risk_decision_ref,omitempty"`
	ApprovalEvidenceRef string       `json:"approval_evidence_ref,omitempty"`
	GrantRef            string       `json:"grant_ref,omitempty"`
	ActionRef           string       `json:"action_ref,omitempty"`
	StatusFrom          ActionStatus `json:"status_from,omitempty"`
	StatusTo            ActionStatus `json:"status_to,omitempty"`
	ReceiptRef          string       `json:"receipt_ref,omitempty"`
	OccurredAt          time.Time    `json:"occurred_at"`
	PrevHash            string       `json:"prev_hash,omitempty"`
	EventHash           string       `json:"event_hash,omitempty"`
}

// Validate applies the canonical AuditEvent rules.
func (e AuditEvent) Validate() error {
	if err := requireNonEmpty("event_id", e.EventID); err != nil {
		return err
	}
	if err := requireNonEmpty("tenant_ref", e.TenantRef); err != nil {
		return err
	}
	if e.TenantSeq == 0 {
		return fieldErrorf("tenant_seq", "the tenant sequence starts at 1")
	}
	if err := requireNonEmpty("principal_ref", e.PrincipalRef); err != nil {
		return err
	}
	if e.Capability != "" {
		if err := validateCapability(e.Capability); err != nil {
			return err
		}
	}
	if e.ParameterHash != "" {
		if err := ValidateSHA256Ref(e.ParameterHash); err != nil {
			return fieldErrorf("parameter_hash", "%v", err)
		}
	}
	if e.StatusFrom != "" && !e.StatusFrom.Valid() {
		return fieldErrorf("status_from", "%q is not a frozen action status", e.StatusFrom)
	}
	if e.StatusTo != "" && !e.StatusTo.Valid() {
		return fieldErrorf("status_to", "%q is not a frozen action status", e.StatusTo)
	}
	if (e.StatusFrom == "") != (e.StatusTo == "") {
		return fieldErrorf("status_to", "an action transition records both status_from and status_to")
	}
	if e.OccurredAt.IsZero() {
		return fieldErrorf("occurred_at", "is required")
	}
	if e.PrevHash != "" {
		if err := ValidateSHA256Ref(e.PrevHash); err != nil {
			return fieldErrorf("prev_hash", "%v", err)
		}
	}
	if e.EventHash != "" {
		if err := ValidateSHA256Ref(e.EventHash); err != nil {
			return fieldErrorf("event_hash", "%v", err)
		}
	}
	return nil
}
