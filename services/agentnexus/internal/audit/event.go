package audit

import (
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

type EventInput struct {
	ID                  string
	EnterpriseID        string
	CaseTicketID        string
	StepGrantID         string
	ActorUserID         string
	ConnectorInstanceID string
	ResourceType        string
	ResourceID          string
	Action              string
	Decision            string
	InputHash           string
	OutputHash          string
	EvidencePointer     string
	// GA Task 0G first-class binding refs (recoverable, individually signed).
	StatusFrom          string
	Capability          string
	ParameterHash       string
	GrantRef            string
	ApprovalEvidenceRef string
	ReceiptRef          string
	RiskAuthority       string
	AgentClientRef      string
	AgentReleaseRef     string
	OrgSnapshotRef      string
}

// Event is one durable audit_events row. GA Task 0G adds the signing plane on
// top of the unsigned SHA-256 chain: TenantSeq is the per-tenant monotonic
// sequence, SignedAt is the app-signed instant bound into the canonical
// pre-image, and Signature is the detached ed25519 signature. Legacy rows leave
// all three at their zero value (unsigned); the signed verifier rejects those.
type Event struct {
	ID                  string
	EnterpriseID        string
	CaseTicketID        string
	StepGrantID         string
	ActorUserID         string
	ConnectorInstanceID string
	ResourceType        string
	ResourceID          string
	Action              string
	Decision            string
	InputHash           string
	OutputHash          string
	EvidencePointer     string
	StatusFrom          string
	Capability          string
	ParameterHash       string
	GrantRef            string
	ApprovalEvidenceRef string
	ReceiptRef          string
	RiskAuthority       string
	AgentClientRef      string
	AgentReleaseRef     string
	OrgSnapshotRef      string
	PrevHash            string
	EventHash           string
	CreatedAt           time.Time
	TenantSeq           uint64
	SignedAt            time.Time
	Signature           runtime.Signature
}

// NewEvent builds one UNSIGNED, hash-chained event (the legacy plane: browser,
// approval-transmission and evidence lineage before a signer is wired). Its
// event_hash routes through the shared canonicalization (canonical.go).
func NewEvent(input EventInput, prevHash string) Event {
	event := newEvent(input, prevHash)
	event.EventHash = ComputeHash(event)
	return event
}

// NewSignedEvent builds one event carrying its per-tenant sequence and signed-at
// instant, with its event_hash computed over the canonical pre-image. The
// caller signs the canonical bytes and sets Signature (SignEvent does both);
// the event_hash is stable because the canonical pre-image zeroes the signature
// slot.
func NewSignedEvent(input EventInput, prevHash string, tenantSeq uint64, signedAt time.Time) Event {
	event := newEvent(input, prevHash)
	event.TenantSeq = tenantSeq
	event.SignedAt = signedAt.UTC()
	event.EventHash = ComputeHash(event)
	return event
}

func newEvent(input EventInput, prevHash string) Event {
	return Event{
		ID:                  input.ID,
		EnterpriseID:        input.EnterpriseID,
		CaseTicketID:        input.CaseTicketID,
		StepGrantID:         input.StepGrantID,
		ActorUserID:         input.ActorUserID,
		ConnectorInstanceID: input.ConnectorInstanceID,
		ResourceType:        input.ResourceType,
		ResourceID:          input.ResourceID,
		Action:              input.Action,
		Decision:            input.Decision,
		InputHash:           input.InputHash,
		OutputHash:          input.OutputHash,
		EvidencePointer:     input.EvidencePointer,
		StatusFrom:          input.StatusFrom,
		Capability:          input.Capability,
		ParameterHash:       input.ParameterHash,
		GrantRef:            input.GrantRef,
		ApprovalEvidenceRef: input.ApprovalEvidenceRef,
		ReceiptRef:          input.ReceiptRef,
		RiskAuthority:       input.RiskAuthority,
		AgentClientRef:      input.AgentClientRef,
		AgentReleaseRef:     input.AgentReleaseRef,
		OrgSnapshotRef:      input.OrgSnapshotRef,
		PrevHash:            prevHash,
	}
}
