package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// signedAuditEventFromRow maps a durable audit_events row onto the audit.Event
// verification shape (the signed sub-chain read path).
func signedAuditEventFromRow(r db.AuditEvent) audit.Event {
	e := audit.Event{
		ID: r.ID, EnterpriseID: r.EnterpriseID, CaseTicketID: r.CaseTicketID.String,
		StepGrantID: r.StepGrantID.String, ActorUserID: r.ActorUserID.String,
		ConnectorInstanceID: r.ConnectorInstanceID.String, ResourceType: r.ResourceType.String,
		ResourceID: r.ResourceID.String, Action: r.Action, Decision: r.Decision,
		InputHash: r.InputHash.String, OutputHash: r.OutputHash.String, EvidencePointer: r.EvidencePointer.String,
		StatusFrom: r.StatusFrom.String, Capability: r.Capability.String, ParameterHash: r.ParameterHash.String,
		GrantRef: r.GrantRef.String, ApprovalEvidenceRef: r.ApprovalEvidenceRef.String, ReceiptRef: r.ReceiptRef.String,
		RiskAuthority: r.RiskAuthority.String, AgentClientRef: r.AgentClientRef.String, AgentReleaseRef: r.AgentReleaseRef.String,
		OrgSnapshotRef: r.OrgSnapshotRef.String, PrevHash: r.PrevHash.String, EventHash: r.EventHash,
	}
	if r.TenantSeq.Valid {
		e.TenantSeq = uint64(r.TenantSeq.Int64)
	}
	if r.SignedAt.Valid {
		e.SignedAt = r.SignedAt.Time
	}
	if r.SignatureKeyID.Valid {
		e.Signature = runtime.Signature{Algorithm: r.SignatureAlgorithm.String, KeyID: r.SignatureKeyID.String, Value: r.SignatureValue.String}
	}
	return e
}

// readSignedAuditChain reads the full signed per-tenant chain in sequence order.
func (s *PostgresBrowserAuditSink) readSignedAuditChain(ctx context.Context, tenant string) ([]audit.Event, error) {
	rows, err := db.New(s.pool).ListSignedAuditEventsForTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}
	out := make([]audit.Event, len(rows))
	for i, r := range rows {
		out[i] = signedAuditEventFromRow(r)
	}
	return out, nil
}

// registeredSigningKeys loads the registered signing public keys with their
// revocation state (the verifier trust set / bundle key list).
func (s *PostgresBrowserAuditSink) registeredSigningKeys(ctx context.Context) ([]audit.SigningKey, error) {
	rows, err := db.New(s.pool).ListAuditSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]audit.SigningKey, 0, len(rows))
	for _, r := range rows {
		status := sdkaudit.KeyActive
		if r.Status == string(sdkaudit.KeyRevoked) {
			status = sdkaudit.KeyRevoked
		}
		key := audit.SigningKey{KeyID: r.KeyID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Status: status}
		if r.CreatedAt.Valid {
			key.CreatedAt = r.CreatedAt.Time
		}
		if r.RevokedAt.Valid {
			key.RevokedAt = r.RevokedAt.Time
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// ExportActionAuditPackage builds the offline WORM/SIEM verification package for
// a tenant's signed chain (events + registered keys + signed batch Merkle root +
// witnesses). It fails closed without a signer (the batch root must be signed).
func (s *PostgresBrowserAuditSink) ExportActionAuditPackage(ctx context.Context, tenant string) (audit.VerificationPackage, error) {
	if s == nil || s.pool == nil {
		return audit.VerificationPackage{}, errors.New("audit export requires a pool")
	}
	if s.signer == nil {
		return audit.VerificationPackage{}, errors.Join(audit.ErrUnavailable, errors.New("audit export requires a wired signer for the batch root"))
	}
	chain, err := s.readSignedAuditChain(ctx, tenant)
	if err != nil {
		return audit.VerificationPackage{}, err
	}
	keys, err := s.registeredSigningKeys(ctx)
	if err != nil {
		return audit.VerificationPackage{}, err
	}
	return audit.BuildVerificationPackage(ctx, s.signer, tenant, chain, keys)
}

// PersistActionAuditCheckpoint builds and PERSISTS a signed batch-root checkpoint
// for a tenant's signed chain (the WORM/SIEM anchor). It returns the covered
// last sequence. Truncation below a persisted checkpoint is detectable
// afterwards via DetectActionAuditTruncation. It is a no-op on an empty chain.
func (s *PostgresBrowserAuditSink) PersistActionAuditCheckpoint(ctx context.Context, tenant string) (int64, error) {
	pkg, err := s.ExportActionAuditPackage(ctx, tenant)
	if err != nil {
		return 0, err
	}
	if len(pkg.Events) == 0 {
		return 0, nil
	}
	id, err := randomCheckpointID()
	if err != nil {
		return 0, err
	}
	if _, err := db.New(s.pool).InsertAuditBatchRoot(ctx, db.InsertAuditBatchRootParams{
		ID: id, EnterpriseID: tenant, RootHash: pkg.Batch.RootHash,
		FirstSeq: int64(pkg.Batch.FirstSeq), LastSeq: int64(pkg.Batch.LastSeq), EventCount: int64(pkg.Batch.EventCount),
		SignedAt:           pgtype.Timestamptz{Time: pkg.Batch.SignedAt.UTC(), Valid: true},
		SignatureAlgorithm: pkg.Batch.Signature.Algorithm, SignatureKeyID: pkg.Batch.Signature.KeyID, SignatureValue: pkg.Batch.Signature.Value,
	}); err != nil {
		return 0, err
	}
	return int64(pkg.Batch.LastSeq), nil
}

// DetectActionAuditTruncation compares the current signed-chain head against the
// most recent persisted checkpoint: a head below the checkpoint's last covered
// sequence is a truncation (evidence the checkpoint proved existed is gone). No
// checkpoint yet ⇒ nothing to compare ⇒ nil.
func (s *PostgresBrowserAuditSink) DetectActionAuditTruncation(ctx context.Context, tenant string) error {
	queries := db.New(s.pool)
	latest, err := queries.GetLatestAuditBatchRoot(ctx, tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	// AUTHENTICITY: verify the persisted checkpoint's signature against the
	// registered keys BEFORE trusting its last_seq. A DB role that inserts a
	// forged checkpoint (bogus signature, or an unregistered key) to mask
	// truncation is rejected here rather than silently trusted.
	keys, err := s.registeredSigningKeys(ctx)
	if err != nil {
		return err
	}
	batch := sdkaudit.BatchRoot{
		TenantRef: latest.EnterpriseID, FirstSeq: uint64(latest.FirstSeq), LastSeq: uint64(latest.LastSeq),
		EventCount: int(latest.EventCount), RootHash: latest.RootHash,
		Signature: sdkaudit.Signature{Algorithm: latest.SignatureAlgorithm, KeyID: latest.SignatureKeyID, Value: latest.SignatureValue},
	}
	if latest.SignedAt.Valid {
		batch.SignedAt = latest.SignedAt.Time
	}
	if err := sdkaudit.VerifyBatchRoot(batch, sdkaudit.NewKeySet(keys...)); err != nil {
		return fmt.Errorf("persisted audit checkpoint is not authentic: %w", err)
	}
	chain, err := s.readSignedAuditChain(ctx, tenant)
	if err != nil {
		return err
	}
	var headSeq int64
	if len(chain) > 0 {
		headSeq = int64(chain[len(chain)-1].TenantSeq)
	}
	return audit.DetectTruncation(headSeq, latest.LastSeq)
}

func randomCheckpointID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "auditroot_" + hex.EncodeToString(buf), nil
}
