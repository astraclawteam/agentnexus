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
