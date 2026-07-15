// canonical.go is the single boundary between the durable audit_events row
// (this package's Event) and the shared, dependency-free verification core
// (sdk/go/audit). Both the runtime hash-chain layer and the GA Task 0G signing
// and verification layers canonicalize through HERE, so the open-core runtime
// and the standalone offline verifier can never disagree on the pre-image bytes.
package audit

import (
	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
)

// toSDK projects one durable Event onto the shared sdk/go/audit Event. The
// durable enterprise_id is the chain's tenant_ref; the runtime.Signature maps
// field-for-field onto the shared Signature (identical JSON, identical bytes).
// created_at is deliberately absent: it is the database's monotonic ordering
// key, not signed content (tenant_seq and prev_hash are the signed ordering).
func toSDK(e Event) sdkaudit.Event {
	return sdkaudit.Event{
		ID:                  e.ID,
		TenantRef:           e.EnterpriseID,
		TenantSeq:           e.TenantSeq,
		CaseTicketID:        e.CaseTicketID,
		StepGrantID:         e.StepGrantID,
		ActorUserID:         e.ActorUserID,
		ConnectorInstanceID: e.ConnectorInstanceID,
		ResourceType:        e.ResourceType,
		ResourceID:          e.ResourceID,
		Action:              e.Action,
		Decision:            e.Decision,
		InputHash:           e.InputHash,
		OutputHash:          e.OutputHash,
		EvidencePointer:     e.EvidencePointer,
		StatusFrom:          e.StatusFrom,
		Capability:          e.Capability,
		ParameterHash:       e.ParameterHash,
		GrantRef:            e.GrantRef,
		ApprovalEvidenceRef: e.ApprovalEvidenceRef,
		ReceiptRef:          e.ReceiptRef,
		RiskAuthority:       e.RiskAuthority,
		AgentClientRef:      e.AgentClientRef,
		AgentReleaseRef:     e.AgentReleaseRef,
		OrgSnapshotRef:      e.OrgSnapshotRef,
		PrevHash:            e.PrevHash,
		SignedAt:            e.SignedAt,
		Signature: sdkaudit.Signature{
			Algorithm: e.Signature.Algorithm,
			KeyID:     e.Signature.KeyID,
			Value:     e.Signature.Value,
		},
		EventHash: e.EventHash,
	}
}

// CanonicalAuditEvent returns the deterministic signing pre-image of a durable
// audit event: the shared canonicalization with the signature slot and the
// event_hash slot BOTH zeroed and signed_at normalized to UTC. It is the exact
// bytes the ed25519 signature and the event_hash are taken over.
func CanonicalAuditEvent(e Event) ([]byte, error) {
	return sdkaudit.Canonical(toSDK(e))
}
