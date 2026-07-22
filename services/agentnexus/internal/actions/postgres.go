package actions

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

// PostgresStore is the durable action store (migration 000010). It upholds the
// same invariants as MemoryStore — one Action per (tenant, idempotency_key),
// monotonic status along the allowed edges, one one-use grant per Action, an
// append-only outbox and a dedup inbox — enforced by constraints and triggers
// and serialized under a per-action advisory lock.
type PostgresStore struct{ pool *pgxpool.Pool }

// NewPostgresStore builds a durable store over a pgx pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: !t.IsZero()}
}

func timeOf(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

// lockAction acquires the per-action advisory lock. Tenant and action are
// SEPARATE text parameters of the two-int lock form: PostgreSQL rejects NUL
// bytes (0x00) in text parameters, so no delimiter-joined key ever crosses the
// SQL boundary. The NUL joiner is legal ONLY for in-process Go map keys
// (MemoryStore.storeKey); TestActionSQLParametersCarryNoNULJoiner keeps it out
// of this file and the SQL surface.
func lockAction(ctx context.Context, queries *db.Queries, tenantRef, actionRef string) error {
	_, err := queries.AcquireActionLock(ctx, db.AcquireActionLockParams{TenantRef: tenantRef, ActionRef: actionRef})
	return err
}

func (s *PostgresStore) begin(ctx context.Context) (pgx.Tx, *db.Queries, error) {
	if s == nil || s.pool == nil {
		return nil, nil, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, errors.Join(ErrUnavailable, err)
	}
	return tx, db.New(tx), nil
}

func (s *PostgresStore) PutRequested(ctx context.Context, action Action) (Action, bool, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Action{}, false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	postconditions, verificationNeeds, err := marshalDeclared(action)
	if err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	inserted, err := queries.InsertAction(ctx, db.InsertActionParams{
		TenantRef:             action.TenantRef,
		ActionRef:             action.ActionRef,
		Status:                string(action.Status),
		BusinessContextRef:    action.BusinessContextRef,
		Capability:            action.Capability,
		ParameterHash:         action.ParameterHash,
		IdempotencyKey:        action.IdempotencyKey,
		RiskAuthority:         action.RiskAuthority,
		RiskLevel:             string(action.RiskLevel),
		ApprovalPlanRef:       action.ApprovalPlanRef,
		CompensationRef:       action.CompensationRef,
		CompensationOf:        action.CompensationOf,
		ExpectedReceiptSchema: action.ExpectedReceiptSchema,
		Postconditions:        postconditions,
		VerificationNeeds:     verificationNeeds,
		ExpiresAt:             pgTime(action.ExpiresAt),
		AuditRefID:            action.AuditRefID,
		CreatedAt:             pgTime(action.CreatedAt),
	})
	if err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	if inserted != 1 {
		existingRow, err := queries.GetActionByIdempotencyKey(ctx, db.GetActionByIdempotencyKeyParams{TenantRef: action.TenantRef, IdempotencyKey: action.IdempotencyKey})
		if err != nil {
			return Action{}, false, errors.Join(ErrUnavailable, err)
		}
		existing, err := actionFromRow(existingRow)
		if err != nil {
			return Action{}, false, errors.Join(ErrUnavailable, err)
		}
		if existing.Capability != action.Capability || existing.ParameterHash != action.ParameterHash || existing.BusinessContextRef != action.BusinessContextRef {
			return Action{}, false, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return Action{}, false, errors.Join(ErrUnavailable, err)
		}
		return existing, false, nil
	}
	row, err := queries.GetAction(ctx, db.GetActionParams{TenantRef: action.TenantRef, ActionRef: action.ActionRef})
	if err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	stored, err := actionFromRow(row)
	if err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	return stored, true, nil
}

func (s *PostgresStore) GetByIdempotencyKey(ctx context.Context, tenantRef, idempotencyKey string) (Action, error) {
	if s == nil || s.pool == nil {
		return Action{}, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	row, err := db.New(s.pool).GetActionByIdempotencyKey(ctx, db.GetActionByIdempotencyKeyParams{TenantRef: tenantRef, IdempotencyKey: idempotencyKey})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Action{}, ErrNotFound
		}
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	return actionFromRow(row)
}

func (s *PostgresStore) GetAction(ctx context.Context, tenantRef, actionRef string) (Action, error) {
	if s == nil || s.pool == nil {
		return Action{}, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	row, err := db.New(s.pool).GetAction(ctx, db.GetActionParams{TenantRef: tenantRef, ActionRef: actionRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Action{}, ErrNotFound
		}
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	return actionFromRow(row)
}

func (s *PostgresStore) Grant(ctx context.Context, action Action, grant Grant) (Action, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Action{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := lockAction(ctx, queries, action.TenantRef, action.ActionRef); err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	grantRows, err := queries.InsertActionGrant(ctx, db.InsertActionGrantParams{
		TenantRef:          grant.TenantRef,
		GrantRef:           grant.GrantRef,
		ActionRef:          grant.ActionRef,
		BusinessContextRef: grant.BusinessContextRef,
		Capability:         grant.Capability,
		ParameterHash:      grant.ParameterHash,
		IssuedAt:           pgTime(grant.IssuedAt),
		ExpiresAt:          pgTime(grant.ExpiresAt),
	})
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if grantRows != 1 {
		return Action{}, ErrForbiddenTransition // a grant already exists for this action
	}
	updated, err := queries.GrantAction(ctx, db.GrantActionParams{
		TenantRef:           action.TenantRef,
		ActionRef:           action.ActionRef,
		GrantRef:            grant.GrantRef,
		ApprovalEvidenceRef: action.ApprovalEvidenceRef,
		UpdatedAt:           pgTime(grant.IssuedAt),
	})
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if updated != 1 {
		return Action{}, ErrForbiddenTransition
	}
	return s.commitAndReload(ctx, tx, queries, action.TenantRef, action.ActionRef)
}

func (s *PostgresStore) Dispatch(ctx context.Context, tenantRef, actionRef string, dispatch Dispatch, at time.Time) (Action, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Action{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := lockAction(ctx, queries, tenantRef, actionRef); err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	dispatched, err := queries.DispatchAction(ctx, db.DispatchActionParams{TenantRef: tenantRef, ActionRef: actionRef, UpdatedAt: pgTime(at)})
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if dispatched != 1 {
		return Action{}, ErrForbiddenTransition
	}
	// Consume the one-use grant in the SAME transaction as the outbox write.
	if _, err := queries.ConsumeActionGrant(ctx, db.ConsumeActionGrantParams{TenantRef: tenantRef, ActionRef: actionRef, ConsumedAt: pgTime(at)}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Action{}, ErrEvidenceConsumed
		}
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if _, err := queries.InsertActionOutbox(ctx, db.InsertActionOutboxParams{
		TenantRef:     dispatch.TenantRef,
		DispatchRef:   dispatch.DispatchRef,
		ActionRef:     dispatch.ActionRef,
		Capability:    dispatch.Capability,
		ParameterHash: dispatch.ParameterHash,
		GrantRef:      dispatch.GrantRef,
		Kind:          string(dispatch.Kind),
		CreatedAt:     pgTime(dispatch.CreatedAt),
	}); err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	return s.commitAndReload(ctx, tx, queries, tenantRef, actionRef)
}

func (s *PostgresStore) Transition(ctx context.Context, tenantRef, actionRef string, from, to runtime.ActionStatus, reason string, at time.Time) (Action, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Action{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := lockAction(ctx, queries, tenantRef, actionRef); err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if _, err := queries.GetAction(ctx, db.GetActionParams{TenantRef: tenantRef, ActionRef: actionRef}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Action{}, ErrNotFound
		}
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	rows, err := queries.TransitionAction(ctx, db.TransitionActionParams{
		TenantRef: tenantRef,
		ActionRef: actionRef,
		Status:    string(to),
		Column4:   reason,
		UpdatedAt: pgTime(at),
		Status_2:  string(from),
	})
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if rows != 1 {
		return Action{}, ErrForbiddenTransition
	}
	return s.commitAndReload(ctx, tx, queries, tenantRef, actionRef)
}

func (s *PostgresStore) IngestResult(ctx context.Context, result Result, to runtime.ActionStatus, at time.Time) (Action, bool, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return Action{}, false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := lockAction(ctx, queries, result.TenantRef, result.ActionRef); err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	insertedInbox, err := queries.InsertActionInbox(ctx, db.InsertActionInboxParams{
		TenantRef:  result.TenantRef,
		ResultID:   result.ResultID,
		ActionRef:  result.ActionRef,
		ReceiptRef: result.Receipt.ReceiptRef,
		AppliedAt:  pgTime(at),
	})
	if err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	if insertedInbox != 1 {
		// Duplicate/redelivered result: a clean idempotent no-op.
		action, err := s.reload(ctx, tx, queries, result.TenantRef, result.ActionRef)
		if err != nil {
			return Action{}, false, err
		}
		return action, false, nil
	}
	var resultBytes []byte
	if len(result.Receipt.Result) > 0 {
		resultBytes = []byte(result.Receipt.Result)
	}
	var signatureBytes []byte
	if result.Receipt.Signature != nil {
		signatureBytes, err = json.Marshal(result.Receipt.Signature)
		if err != nil {
			return Action{}, false, errors.Join(ErrUnavailable, err)
		}
	}
	if _, err := queries.InsertActionReceipt(ctx, db.InsertActionReceiptParams{
		TenantRef:     result.TenantRef,
		ReceiptRef:    result.Receipt.ReceiptRef,
		ActionRef:     result.ActionRef,
		Status:        string(result.Receipt.Status),
		Capability:    result.Receipt.Capability,
		ParameterHash: result.Receipt.ParameterHash,
		ReceiptSchema: result.Receipt.ReceiptSchema,
		Result:        resultBytes,
		ResultHash:    result.Receipt.ResultHash,
		IssuedAt:      pgTime(result.Receipt.IssuedAt),
		Signature:     signatureBytes,
		CreatedAt:     pgTime(at),
	}); err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	completed, err := queries.CompleteAction(ctx, db.CompleteActionParams{
		TenantRef:  result.TenantRef,
		ActionRef:  result.ActionRef,
		Status:     string(to),
		ReceiptRef: result.Receipt.ReceiptRef,
		UpdatedAt:  pgTime(at),
	})
	if err != nil {
		return Action{}, false, errors.Join(ErrUnavailable, err)
	}
	if completed != 1 {
		return Action{}, false, ErrForbiddenTransition
	}
	action, err := s.commitAndReload(ctx, tx, queries, result.TenantRef, result.ActionRef)
	if err != nil {
		return Action{}, false, err
	}
	return action, true, nil
}

func (s *PostgresStore) GetReceipt(ctx context.Context, tenantRef, receiptRef string) (runtime.ActionReceipt, error) {
	if s == nil || s.pool == nil {
		return runtime.ActionReceipt{}, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	row, err := db.New(s.pool).GetActionReceipt(ctx, db.GetActionReceiptParams{TenantRef: tenantRef, ReceiptRef: receiptRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runtime.ActionReceipt{}, ErrNotFound
		}
		return runtime.ActionReceipt{}, errors.Join(ErrUnavailable, err)
	}
	return receiptFromRow(row)
}

func (s *PostgresStore) ResultApplied(ctx context.Context, tenantRef, resultID string) (bool, error) {
	if s == nil || s.pool == nil {
		return false, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	applied, err := db.New(s.pool).ActionResultApplied(ctx, db.ActionResultAppliedParams{TenantRef: tenantRef, ResultID: resultID})
	if err != nil {
		return false, errors.Join(ErrUnavailable, err)
	}
	return applied, nil
}

// dispatchFromRow projects one outbox row onto the durable dispatch intent.
func dispatchFromRow(row db.ActionOutbox) Dispatch {
	return Dispatch{
		TenantRef:      row.TenantRef,
		DispatchRef:    row.DispatchRef,
		ActionRef:      row.ActionRef,
		Capability:     row.Capability,
		ParameterHash:  row.ParameterHash,
		GrantRef:       row.GrantRef,
		Kind:           DispatchKind(row.Kind),
		Published:      row.Published,
		Attempts:       int(row.Attempts),
		CreatedAt:      timeOf(row.CreatedAt),
		PublishedAt:    timeOf(row.PublishedAt),
		NextAttemptAt:  timeOf(row.NextAttemptAt),
		LastError:      row.LastError,
		DeadLetteredAt: timeOf(row.DeadLetteredAt),
	}
}

func dispatchesFromRows(rows []db.ActionOutbox) []Dispatch {
	out := make([]Dispatch, 0, len(rows))
	for _, row := range rows {
		out = append(out, dispatchFromRow(row))
	}
	return out
}

func outboxLimit(limit int) int32 {
	if limit <= 0 {
		return defaultDispatchClaimBatch
	}
	return int32(limit)
}

func (s *PostgresStore) PendingDispatches(ctx context.Context, tenantRef string, limit int) ([]Dispatch, error) {
	if s == nil || s.pool == nil {
		return nil, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	rows, err := db.New(s.pool).ListPendingActionOutbox(ctx, db.ListPendingActionOutboxParams{TenantRef: tenantRef, Limit: outboxLimit(limit)})
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return dispatchesFromRows(rows), nil
}

func (s *PostgresStore) DeadLetteredDispatches(ctx context.Context, tenantRef string, limit int) ([]Dispatch, error) {
	if s == nil || s.pool == nil {
		return nil, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	rows, err := db.New(s.pool).ListDeadLetteredActionOutbox(ctx, db.ListDeadLetteredActionOutboxParams{TenantRef: tenantRef, Limit: outboxLimit(limit)})
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return dispatchesFromRows(rows), nil
}

// ClaimDispatch locks ONE outbox row with FOR UPDATE SKIP LOCKED, delivers it
// and writes the attempt's outcome inside that same transaction. Holding the
// row lock across the publish is the point: it is what stops a concurrent
// replica — or the recovery pump racing the dispatching request — from
// publishing the same intent a second time. A row another claimer already holds
// is SKIPPED (claimed=false), never queued behind.
func (s *PostgresStore) ClaimDispatch(ctx context.Context, tenantRef, dispatchRef string, at time.Time, deliver DispatchDeliverer) (bool, error) {
	if deliver == nil {
		return false, errors.Join(ErrInvalidInput, errors.New("a dispatch claim requires a deliverer"))
	}
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	row, err := queries.ClaimActionOutbox(ctx, db.ClaimActionOutboxParams{TenantRef: tenantRef, DispatchRef: dispatchRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Already published, dead lettered, absent, or held by another
			// claimer. All four mean: not ours to deliver.
			return false, nil
		}
		return false, errors.Join(ErrUnavailable, err)
	}
	dispatch := dispatchFromRow(row)
	if err := applyDispatchOutcome(ctx, queries, dispatch, deliver(ctx, dispatch), at); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, errors.Join(ErrUnavailable, err)
	}
	return true, nil
}

// ClaimPendingDispatches drains the eligible outbox rows oldest-first, ONE
// transaction per row. Per-row transactions are deliberate: a store failure on
// the fifth intent must not roll back the published stamp of the first four and
// make them republish, and a row whose delivery fails must not abort the pass —
// its outcome commits and the drain moves to the next row.
func (s *PostgresStore) ClaimPendingDispatches(ctx context.Context, tenantRef string, limit int, at time.Time, deliver DispatchDeliverer) (int, error) {
	if deliver == nil {
		return 0, errors.Join(ErrInvalidInput, errors.New("a dispatch claim requires a deliverer"))
	}
	if s == nil || s.pool == nil {
		return 0, errors.Join(ErrUnavailable, errors.New("action store is not wired"))
	}
	bound := int(outboxLimit(limit))
	claimed := 0
	for claimed < bound {
		ok, err := s.claimNext(ctx, tenantRef, at, deliver)
		if err != nil {
			return claimed, err
		}
		if !ok {
			break
		}
		claimed++
	}
	return claimed, nil
}

// claimNext claims and delivers the oldest eligible row in its own transaction.
// It reports ok=false when nothing is eligible or every eligible row is held by
// another claimer, which is what ends the drain pass.
func (s *PostgresStore) claimNext(ctx context.Context, tenantRef string, at time.Time, deliver DispatchDeliverer) (bool, error) {
	tx, queries, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	row, err := queries.ClaimNextActionOutbox(ctx, db.ClaimNextActionOutboxParams{TenantRef: tenantRef, NextAttemptAt: pgTime(at)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, errors.Join(ErrUnavailable, err)
	}
	dispatch := dispatchFromRow(row)
	if err := applyDispatchOutcome(ctx, queries, dispatch, deliver(ctx, dispatch), at); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, errors.Join(ErrUnavailable, err)
	}
	return true, nil
}

// applyDispatchOutcome writes one delivery attempt onto the claimed row: the
// publish stamp, or the failed attempt with its backoff / dead-letter stamp.
// Both shapes raise attempts, so the column counts ATTEMPTS rather than
// publishes and the retry policy has something real to read.
func applyDispatchOutcome(ctx context.Context, queries *db.Queries, dispatch Dispatch, outcome DispatchOutcome, at time.Time) error {
	if outcome.Published {
		affected, err := queries.MarkActionOutboxPublished(ctx, db.MarkActionOutboxPublishedParams{
			TenantRef:   dispatch.TenantRef,
			DispatchRef: dispatch.DispatchRef,
			PublishedAt: pgTime(at),
		})
		if err != nil {
			return errors.Join(ErrUnavailable, err)
		}
		if affected != 1 {
			return errors.Join(ErrUnavailable, errors.New("claimed outbox row could not be stamped published"))
		}
		return nil
	}
	deadLetteredAt := time.Time{}
	nextAttemptAt := outcome.NextAttemptAt
	if outcome.DeadLetter {
		deadLetteredAt = at
		nextAttemptAt = time.Time{}
	}
	affected, err := queries.RecordActionOutboxAttempt(ctx, db.RecordActionOutboxAttemptParams{
		TenantRef:      dispatch.TenantRef,
		DispatchRef:    dispatch.DispatchRef,
		NextAttemptAt:  pgTime(nextAttemptAt),
		LastError:      truncateOutboxError(outcome.LastError),
		DeadLetteredAt: pgTime(deadLetteredAt),
	})
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if affected != 1 {
		return errors.Join(ErrUnavailable, errors.New("claimed outbox row could not record its failed attempt"))
	}
	return nil
}

// maxOutboxErrorLength bounds the persisted failure reason: a transport can
// return an arbitrarily long error and the outbox row is evidence, not a log.
const maxOutboxErrorLength = 512

func truncateOutboxError(reason string) string {
	if len(reason) <= maxOutboxErrorLength {
		return reason
	}
	return reason[:maxOutboxErrorLength]
}

func (s *PostgresStore) commitAndReload(ctx context.Context, tx pgx.Tx, queries *db.Queries, tenantRef, actionRef string) (Action, error) {
	row, err := queries.GetAction(ctx, db.GetActionParams{TenantRef: tenantRef, ActionRef: actionRef})
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	action, err := actionFromRow(row)
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	return action, nil
}

func (s *PostgresStore) reload(ctx context.Context, tx pgx.Tx, queries *db.Queries, tenantRef, actionRef string) (Action, error) {
	row, err := queries.GetAction(ctx, db.GetActionParams{TenantRef: tenantRef, ActionRef: actionRef})
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	action, err := actionFromRow(row)
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	return action, nil
}

func marshalDeclared(action Action) ([]byte, []byte, error) {
	postconditions := action.Postconditions
	if postconditions == nil {
		postconditions = []runtime.PostconditionSpec{}
	}
	needs := action.VerificationNeeds
	if needs == nil {
		needs = []runtime.VerificationNeed{}
	}
	pc, err := json.Marshal(postconditions)
	if err != nil {
		return nil, nil, err
	}
	vn, err := json.Marshal(needs)
	if err != nil {
		return nil, nil, err
	}
	return pc, vn, nil
}

func actionFromRow(row db.Action) (Action, error) {
	var postconditions []runtime.PostconditionSpec
	if len(row.Postconditions) > 0 {
		if err := json.Unmarshal(row.Postconditions, &postconditions); err != nil {
			return Action{}, err
		}
	}
	var needs []runtime.VerificationNeed
	if len(row.VerificationNeeds) > 0 {
		if err := json.Unmarshal(row.VerificationNeeds, &needs); err != nil {
			return Action{}, err
		}
	}
	return Action{
		TenantRef:             row.TenantRef,
		ActionRef:             row.ActionRef,
		Status:                runtime.ActionStatus(row.Status),
		BusinessContextRef:    row.BusinessContextRef,
		Capability:            row.Capability,
		ParameterHash:         row.ParameterHash,
		IdempotencyKey:        row.IdempotencyKey,
		RiskAuthority:         row.RiskAuthority,
		RiskLevel:             runtime.RiskLevel(row.RiskLevel),
		ApprovalPlanRef:       row.ApprovalPlanRef,
		GrantRef:              row.GrantRef,
		ApprovalEvidenceRef:   row.ApprovalEvidenceRef,
		ReceiptRef:            row.ReceiptRef,
		CompensationRef:       row.CompensationRef,
		CompensationOf:        row.CompensationOf,
		ExpectedReceiptSchema: row.ExpectedReceiptSchema,
		Postconditions:        postconditions,
		VerificationNeeds:     needs,
		ExpiresAt:             timeOf(row.ExpiresAt),
		FailureReason:         row.FailureReason,
		AuditRefID:            row.AuditRefID,
		CreatedAt:             timeOf(row.CreatedAt),
		UpdatedAt:             timeOf(row.UpdatedAt),
	}, nil
}

func receiptFromRow(row db.ActionReceipt) (runtime.ActionReceipt, error) {
	receipt := runtime.ActionReceipt{
		ReceiptRef:    row.ReceiptRef,
		ActionRef:     row.ActionRef,
		Status:        runtime.ActionStatus(row.Status),
		Capability:    row.Capability,
		ParameterHash: row.ParameterHash,
		ReceiptSchema: row.ReceiptSchema,
		ResultHash:    row.ResultHash,
		IssuedAt:      timeOf(row.IssuedAt),
	}
	if len(row.Result) > 0 {
		receipt.Result = append(json.RawMessage(nil), row.Result...)
	}
	if len(row.Signature) > 0 {
		var signature runtime.Signature
		if err := json.Unmarshal(row.Signature, &signature); err != nil {
			return runtime.ActionReceipt{}, err
		}
		receipt.Signature = &signature
	}
	return receipt, nil
}
