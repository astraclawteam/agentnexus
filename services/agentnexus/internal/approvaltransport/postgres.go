package approvaltransport

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the durable transmission store (migration 000009). It
// upholds the same invariants as MemoryStore — one correlation per
// (tenant, plan_ref), monotonic status, one validated evidence record per
// plan, a tenant-unique approval_ref and append-only delivery/revocation
// history — enforced by constraints and triggers and serialized under a
// per-plan advisory lock.
type PostgresStore struct{ pool *pgxpool.Pool }

// NewPostgresStore builds a durable store over a pgx pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

// lockTransmission acquires the per-plan advisory lock. Tenant and plan are
// SEPARATE text parameters of the two-int lock form: PostgreSQL rejects NUL
// bytes (0x00) in text parameters, so no delimiter-joined key ever crosses
// the SQL boundary. The NUL joiner is legal ONLY for in-process Go map keys
// (MemoryStore.storeKey); TestApprovalTransportSQLParametersCarryNoNULJoiner
// keeps it out of this file and the SQL surface.
func lockTransmission(ctx context.Context, queries *db.Queries, tenantRef, planRef string) error {
	_, err := queries.AcquireApprovalTransmissionLock(ctx, db.AcquireApprovalTransmissionLockParams{TenantRef: tenantRef, PlanRef: planRef})
	return err
}

func pgTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: !t.IsZero()}
}

func timeOf(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func (s *PostgresStore) begin(ctx context.Context) (pgx.Tx, *db.Queries, error) {
	if s == nil || s.pool == nil {
		return nil, nil, errors.Join(ErrUnavailable, errors.New("approval transmission store is not wired"))
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, errors.Join(ErrUnavailable, err)
	}
	return tx, db.New(tx), nil
}

func (s *PostgresStore) CreateTransmission(ctx context.Context, transmission Transmission) (Transmission, bool, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Transmission{}, false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	inserted, err := queries.InsertApprovalTransmission(ctx, db.InsertApprovalTransmissionParams{
		TenantRef:          transmission.TenantRef,
		PlanRef:            transmission.PlanRef,
		PlanHash:           transmission.PlanHash,
		Authority:          transmission.Authority,
		BusinessContextRef: transmission.BusinessContextRef,
		Capability:         transmission.Capability,
		ParameterHash:      transmission.ParameterHash,
		Purpose:            transmission.Purpose,
		ExpiresAt:          pgTimestamptz(transmission.ExpiresAt),
		AuditRefID:         transmission.AuditRefID,
		CreatedAt:          pgTimestamptz(transmission.CreatedAt),
	})
	if err != nil {
		return Transmission{}, false, errors.Join(ErrUnavailable, err)
	}
	row, err := queries.GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: transmission.TenantRef, PlanRef: transmission.PlanRef})
	if err != nil {
		return Transmission{}, false, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Transmission{}, false, errors.Join(ErrUnavailable, err)
	}
	return transmissionFromRow(row), inserted == 1, nil
}

func (s *PostgresStore) GetTransmission(ctx context.Context, tenantRef, planRef string) (Transmission, error) {
	if s == nil || s.pool == nil {
		return Transmission{}, errors.Join(ErrUnavailable, errors.New("approval transmission store is not wired"))
	}
	row, err := db.New(s.pool).GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: tenantRef, PlanRef: planRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Transmission{}, ErrNotFound
		}
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	return transmissionFromRow(row), nil
}

func (s *PostgresStore) RecordDeliveryAttempt(ctx context.Context, tenantRef, planRef string, outcome DeliveryOutcome, reason string, at time.Time) (Transmission, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Transmission{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := lockTransmission(ctx, queries, tenantRef, planRef); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if _, err := queries.GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: tenantRef, PlanRef: planRef}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Transmission{}, ErrNotFound
		}
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if _, err := queries.InsertApprovalDeliveryAttempt(ctx, db.InsertApprovalDeliveryAttemptParams{TenantRef: tenantRef, PlanRef: planRef, Outcome: string(outcome), Reason: reason, CreatedAt: pgTimestamptz(at)}); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if _, err := queries.UpdateApprovalTransmissionDelivery(ctx, db.UpdateApprovalTransmissionDeliveryParams{TenantRef: tenantRef, PlanRef: planRef, LastDeliveryOutcome: string(outcome), LastDeliveryReason: reason, UpdatedAt: pgTimestamptz(at)}); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	row, err := queries.GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: tenantRef, PlanRef: planRef})
	if err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	return transmissionFromRow(row), nil
}

func (s *PostgresStore) RecordEvidence(ctx context.Context, record EvidenceRecord) (EvidenceRecord, bool, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return EvidenceRecord{}, false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tenantRef, planRef := record.TenantRef, record.Evidence.PlanRef
	if err := lockTransmission(ctx, queries, tenantRef, planRef); err != nil {
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	transmissionRow, err := queries.GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: tenantRef, PlanRef: planRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EvidenceRecord{}, false, ErrNotFound
		}
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	if TransmissionStatus(transmissionRow.Status) == StatusRevoked {
		return EvidenceRecord{}, false, ErrTransmissionRevoked
	}
	// approval_ref replay gate: an existing record under this ref must be the
	// byte-identical decision for the same plan, otherwise it is a replay.
	if existing, err := queries.GetApprovalEvidenceByRef(ctx, db.GetApprovalEvidenceByRefParams{TenantRef: tenantRef, ApprovalRef: record.Evidence.ApprovalRef}); err == nil {
		if existing.PlanRef == planRef && existing.EvidenceHash == record.EvidenceHash {
			stored, convertErr := evidenceFromRow(existing)
			if convertErr != nil {
				return EvidenceRecord{}, false, errors.Join(ErrUnavailable, convertErr)
			}
			if err := tx.Commit(ctx); err != nil {
				return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
			}
			return stored, false, nil
		}
		return EvidenceRecord{}, false, ErrEvidenceReplay
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	// One validated decision per plan.
	if _, err := queries.GetApprovalEvidenceByPlan(ctx, db.GetApprovalEvidenceByPlanParams{TenantRef: tenantRef, PlanRef: planRef}); err == nil {
		return EvidenceRecord{}, false, ErrEvidenceReplay
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	attestation, err := json.Marshal(record.Evidence.Attestation)
	if err != nil {
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	inserted, err := queries.InsertApprovalEvidenceRecord(ctx, db.InsertApprovalEvidenceRecordParams{
		TenantRef:         tenantRef,
		ApprovalRef:       record.Evidence.ApprovalRef,
		PlanRef:           planRef,
		PlanHash:          record.Evidence.PlanHash,
		Capability:        record.Evidence.Capability,
		ParameterHash:     record.Evidence.ParameterHash,
		Decision:          string(record.Evidence.Decision),
		ApproverAuthority: record.Evidence.ApproverAuthority,
		DecidedAt:         pgTimestamptz(record.Evidence.DecidedAt),
		EvidenceHash:      record.EvidenceHash,
		Attestation:       attestation,
		AuditRefID:        record.AuditRefID,
		CreatedAt:         pgTimestamptz(record.RecordedAt),
	})
	if err != nil {
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	if inserted != 1 {
		// The advisory lock makes this unreachable in practice; fail closed as
		// a replay rather than guessing.
		return EvidenceRecord{}, false, ErrEvidenceReplay
	}
	updated, err := queries.UpdateApprovalTransmissionEvidence(ctx, db.UpdateApprovalTransmissionEvidenceParams{
		TenantRef: tenantRef,
		PlanRef:   planRef,
		Decision:  string(record.Evidence.Decision),
		DecidedAt: pgTimestamptz(record.Evidence.DecidedAt),
		UpdatedAt: pgTimestamptz(record.RecordedAt),
	})
	if err != nil || updated != 1 {
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, errors.New("approval transmission status update failed"), err)
	}
	if err := tx.Commit(ctx); err != nil {
		return EvidenceRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	return record, true, nil
}

func (s *PostgresStore) GetEvidence(ctx context.Context, tenantRef, planRef string) (EvidenceRecord, error) {
	if s == nil || s.pool == nil {
		return EvidenceRecord{}, errors.Join(ErrUnavailable, errors.New("approval transmission store is not wired"))
	}
	row, err := db.New(s.pool).GetApprovalEvidenceByPlan(ctx, db.GetApprovalEvidenceByPlanParams{TenantRef: tenantRef, PlanRef: planRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EvidenceRecord{}, ErrNotFound
		}
		return EvidenceRecord{}, errors.Join(ErrUnavailable, err)
	}
	return evidenceFromRow(row)
}

func (s *PostgresStore) ConsumeEvidence(ctx context.Context, tenantRef, planRef string, at time.Time) (ConsumedEvidence, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return ConsumedEvidence{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := lockTransmission(ctx, queries, tenantRef, planRef); err != nil {
		return ConsumedEvidence{}, errors.Join(ErrUnavailable, err)
	}
	transmission, err := queries.GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: tenantRef, PlanRef: planRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ConsumedEvidence{}, ErrNotFound
		}
		return ConsumedEvidence{}, errors.Join(ErrUnavailable, err)
	}
	if TransmissionStatus(transmission.Status) == StatusRevoked {
		return ConsumedEvidence{}, ErrTransmissionRevoked
	}
	row, err := queries.ConsumeApprovalEvidence(ctx, db.ConsumeApprovalEvidenceParams{TenantRef: tenantRef, PlanRef: planRef, ConsumedAt: pgTimestamptz(at)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No unconsumed record matched: distinguish an absent record from an
			// already-consumed one so Task 0F fails closed with the right sentinel.
			if _, getErr := queries.GetApprovalEvidenceByPlan(ctx, db.GetApprovalEvidenceByPlanParams{TenantRef: tenantRef, PlanRef: planRef}); getErr == nil {
				return ConsumedEvidence{}, ErrEvidenceConsumed
			} else if errors.Is(getErr, pgx.ErrNoRows) {
				return ConsumedEvidence{}, ErrNotFound
			}
			return ConsumedEvidence{}, errors.Join(ErrUnavailable, err)
		}
		return ConsumedEvidence{}, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ConsumedEvidence{}, errors.Join(ErrUnavailable, err)
	}
	return ConsumedEvidence{
		ApprovalRef:   row.ApprovalRef,
		PlanRef:       row.PlanRef,
		Capability:    row.Capability,
		ParameterHash: row.ParameterHash,
		Decision:      runtime.ApprovalDecision(row.Decision),
	}, nil
}

func (s *PostgresStore) Revoke(ctx context.Context, tenantRef, planRef, reason, revocationID string, at time.Time) (Transmission, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Transmission{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := lockTransmission(ctx, queries, tenantRef, planRef); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	existing, err := queries.GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: tenantRef, PlanRef: planRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Transmission{}, ErrNotFound
		}
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if TransmissionStatus(existing.Status) == StatusRevoked {
		if err := tx.Commit(ctx); err != nil {
			return Transmission{}, errors.Join(ErrUnavailable, err)
		}
		return transmissionFromRow(existing), nil
	}
	if _, err := queries.InsertApprovalRevocation(ctx, db.InsertApprovalRevocationParams{TenantRef: tenantRef, RevocationID: revocationID, PlanRef: planRef, Reason: reason, CreatedAt: pgTimestamptz(at)}); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if _, err := queries.UpdateApprovalTransmissionRevoked(ctx, db.UpdateApprovalTransmissionRevokedParams{TenantRef: tenantRef, PlanRef: planRef, RevokedAt: pgTimestamptz(at), RevocationReason: reason}); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	row, err := queries.GetApprovalTransmission(ctx, db.GetApprovalTransmissionParams{TenantRef: tenantRef, PlanRef: planRef})
	if err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	return transmissionFromRow(row), nil
}

func transmissionFromRow(row db.ApprovalTransmission) Transmission {
	return Transmission{
		TenantRef:           row.TenantRef,
		PlanRef:             row.PlanRef,
		PlanHash:            row.PlanHash,
		Authority:           row.Authority,
		BusinessContextRef:  row.BusinessContextRef,
		Capability:          row.Capability,
		ParameterHash:       row.ParameterHash,
		Purpose:             row.Purpose,
		Status:              TransmissionStatus(row.Status),
		ExpiresAt:           timeOf(row.ExpiresAt),
		DeliveryAttempts:    int(row.DeliveryAttempts),
		LastDeliveryOutcome: DeliveryOutcome(row.LastDeliveryOutcome),
		LastDeliveryReason:  row.LastDeliveryReason,
		Decision:            runtime.ApprovalDecision(row.Decision),
		DecidedAt:           timeOf(row.DecidedAt),
		RevokedAt:           timeOf(row.RevokedAt),
		RevocationReason:    row.RevocationReason,
		AuditRefID:          row.AuditRefID,
		CreatedAt:           timeOf(row.CreatedAt),
		UpdatedAt:           timeOf(row.UpdatedAt),
	}
}

func evidenceFromRow(row db.ApprovalEvidenceRecord) (EvidenceRecord, error) {
	var attestation runtime.Signature
	if err := json.Unmarshal(row.Attestation, &attestation); err != nil {
		return EvidenceRecord{}, errors.Join(ErrUnavailable, err)
	}
	return EvidenceRecord{
		TenantRef: row.TenantRef,
		Evidence: runtime.ApprovalEvidence{
			ApprovalRef:       row.ApprovalRef,
			PlanRef:           row.PlanRef,
			PlanHash:          row.PlanHash,
			Capability:        row.Capability,
			ParameterHash:     row.ParameterHash,
			Decision:          runtime.ApprovalDecision(row.Decision),
			ApproverAuthority: row.ApproverAuthority,
			DecidedAt:         timeOf(row.DecidedAt),
			Attestation:       attestation,
		},
		EvidenceHash: row.EvidenceHash,
		AuditRefID:   row.AuditRefID,
		RecordedAt:   timeOf(row.CreatedAt),
		ConsumedAt:   timeOf(row.ConsumedAt),
	}, nil
}
