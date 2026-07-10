package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type approvalWriteTx interface {
	AcquireEnterpriseOrgPublicationLock(context.Context, string) (any, error)
	AcquireEnterpriseAuditLock(context.Context, string) (any, error)
	GetLatestApprovalOrgVersion(context.Context, string) (int64, error)
	GetCurrentApprovalPolicyVersion(context.Context, string) (int64, error)
	GetApprovalResolution(context.Context, db.GetApprovalResolutionParams) (db.ApprovalResolutionIdempotency, error)
	InsertApprovalResolution(context.Context, db.InsertApprovalResolutionParams) (int64, error)
	GetLatestEnterpriseAuditHash(context.Context, string) (string, error)
	InsertApprovalQueueItem(context.Context, db.InsertApprovalQueueItemParams) error
	AppendAuditEvent(context.Context, db.AppendAuditEventParams) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type approvalWriteTxBeginner interface {
	BeginApprovalWriteTx(context.Context, pgx.TxOptions) (approvalWriteTx, error)
}

type postgresApprovalWritePool struct{ pool *pgxpool.Pool }

func (p *postgresApprovalWritePool) BeginApprovalWriteTx(ctx context.Context, options pgx.TxOptions) (approvalWriteTx, error) {
	if p == nil || p.pool == nil {
		return nil, errors.New("approval store unavailable")
	}
	tx, err := p.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &postgresApprovalWriteTx{Tx: tx, queries: db.New(tx)}, nil
}

type postgresApprovalWriteTx struct {
	pgx.Tx
	queries *db.Queries
}

func (t *postgresApprovalWriteTx) AcquireEnterpriseAuditLock(ctx context.Context, enterpriseID string) (any, error) {
	return t.queries.AcquireEnterpriseAuditLock(ctx, enterpriseID)
}
func (t *postgresApprovalWriteTx) AcquireEnterpriseOrgPublicationLock(ctx context.Context, enterpriseID string) (any, error) {
	return t.queries.AcquireEnterpriseOrgPublicationLock(ctx, enterpriseID)
}
func (t *postgresApprovalWriteTx) GetLatestApprovalOrgVersion(ctx context.Context, enterpriseID string) (int64, error) {
	return t.queries.GetLatestApprovalOrgVersion(ctx, enterpriseID)
}
func (t *postgresApprovalWriteTx) GetCurrentApprovalPolicyVersion(ctx context.Context, enterpriseID string) (int64, error) {
	return t.queries.GetCurrentApprovalPolicyVersion(ctx, enterpriseID)
}
func (t *postgresApprovalWriteTx) GetApprovalResolution(ctx context.Context, params db.GetApprovalResolutionParams) (db.ApprovalResolutionIdempotency, error) {
	return t.queries.GetApprovalResolution(ctx, params)
}
func (t *postgresApprovalWriteTx) InsertApprovalResolution(ctx context.Context, params db.InsertApprovalResolutionParams) (int64, error) {
	return t.queries.InsertApprovalResolution(ctx, params)
}
func (t *postgresApprovalWriteTx) GetLatestEnterpriseAuditHash(ctx context.Context, enterpriseID string) (string, error) {
	return t.queries.GetLatestEnterpriseAuditHash(ctx, enterpriseID)
}
func (t *postgresApprovalWriteTx) InsertApprovalQueueItem(ctx context.Context, params db.InsertApprovalQueueItemParams) error {
	_, err := t.queries.InsertApprovalQueueItem(ctx, params)
	return err
}
func (t *postgresApprovalWriteTx) AppendAuditEvent(ctx context.Context, params db.AppendAuditEventParams) error {
	_, err := t.queries.AppendAuditEvent(ctx, params)
	return err
}

type PostgresApprovalStore struct {
	pool   approvalWriteTxBeginner
	random io.Reader
}

func (s *PostgresApprovalStore) LookupResolution(ctx context.Context, enterpriseID, idempotencyHash, requestHash string) (approval.Route, bool, error) {
	if s == nil || s.pool == nil || len(idempotencyHash) != 64 || len(requestHash) != 64 {
		return approval.Route{}, false, errors.New("approval store unavailable")
	}
	tx, err := s.pool.BeginApprovalWriteTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return approval.Route{}, false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.AcquireEnterpriseOrgPublicationLock(ctx, enterpriseID); err != nil {
		return approval.Route{}, false, err
	}
	row, err := tx.GetApprovalResolution(ctx, db.GetApprovalResolutionParams{EnterpriseID: enterpriseID, IdempotencyKeyHash: idempotencyHash})
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.Route{}, false, nil
	}
	if err != nil {
		return approval.Route{}, false, err
	}
	if row.RequestHash != requestHash {
		return approval.Route{}, false, ErrApprovalIdempotencyConflict
	}
	route, err := routeFromResolution(row)
	if err != nil {
		return approval.Route{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return approval.Route{}, false, err
	}
	return route, true, nil
}

func NewPostgresApprovalStore(pool *pgxpool.Pool) *PostgresApprovalStore {
	return newPostgresApprovalStoreWithPool(&postgresApprovalWritePool{pool: pool}, rand.Reader)
}

func newPostgresApprovalStoreWithPool(pool approvalWriteTxBeginner, randomSource io.Reader) *PostgresApprovalStore {
	return &PostgresApprovalStore{pool: pool, random: randomSource}
}

func (s *PostgresApprovalStore) Record(ctx context.Context, req approval.Request, route approval.Route) error {
	_, err := s.RecordResolution(ctx, req, route)
	return err
}

func (s *PostgresApprovalStore) RecordResolution(ctx context.Context, req approval.Request, route approval.Route) (result approval.Route, resultErr error) {
	if s == nil || s.pool == nil || s.random == nil || !validRecordedRoute(req, route) {
		return approval.Route{}, errors.New("approval store unavailable")
	}
	inputHash, outputHash, err := approvalEvidenceHashes(req, route)
	if err != nil {
		return approval.Route{}, err
	}
	tx, err := s.pool.BeginApprovalWriteTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return approval.Route{}, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err := tx.AcquireEnterpriseOrgPublicationLock(ctx, req.EnterpriseID); err != nil {
		return approval.Route{}, err
	}
	existing, err := tx.GetApprovalResolution(ctx, db.GetApprovalResolutionParams{EnterpriseID: req.EnterpriseID, IdempotencyKeyHash: req.IdempotencyHash})
	if err == nil {
		if existing.RequestHash != req.ReplayHash {
			return approval.Route{}, ErrApprovalIdempotencyConflict
		}
		replayed, err := routeFromResolution(existing)
		if err != nil {
			return approval.Route{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return approval.Route{}, err
		}
		return replayed, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return approval.Route{}, err
	}
	currentOrg, err := tx.GetLatestApprovalOrgVersion(ctx, req.EnterpriseID)
	if err != nil || currentOrg != req.OrgVersion {
		return approval.Route{}, ErrApprovalStale
	}
	currentPolicy, err := tx.GetCurrentApprovalPolicyVersion(ctx, req.EnterpriseID)
	if err != nil || currentPolicy != req.PolicyVersion {
		return approval.Route{}, ErrApprovalStale
	}
	if _, err := tx.AcquireEnterpriseAuditLock(ctx, req.EnterpriseID); err != nil {
		return approval.Route{}, err
	}
	previous, err := tx.GetLatestEnterpriseAuditHash(ctx, req.EnterpriseID)
	if err != nil {
		return approval.Route{}, err
	}
	auditID, err := randomApprovalID(s.random, "approvalaudit_")
	if err != nil {
		return approval.Route{}, err
	}
	queueID := ""
	if route.Mode != approval.ModeSingleConfirmation {
		queueID, err = randomApprovalID(s.random, "approval_")
		if err != nil {
			return approval.Route{}, err
		}
	}
	reasons, _ := json.Marshal(route.RiskReasons)
	path, _ := json.Marshal(route.OrgPath)
	reviewerUnit := ""
	if route.Mode == approval.ModeUpwardReview {
		reviewerUnit = route.OrgPath[len(route.OrgPath)-1]
	}
	inserted, err := tx.InsertApprovalResolution(ctx, db.InsertApprovalResolutionParams{EnterpriseID: req.EnterpriseID, IdempotencyKeyHash: req.IdempotencyHash, RequestHash: req.ReplayHash, RequesterUserID: req.RequesterUserID, OrgVersion: req.OrgVersion, OrgUnitID: req.OrgUnitID, PolicyVersion: req.PolicyVersion, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: req.Action, RouteMode: string(route.Mode), RiskLevel: string(route.RiskLevel), RiskReasons: reasons, ReviewerUserID: textValue(route.ReviewerUserID), ReviewerOrgUnitID: textValue(reviewerUnit), ReviewerDisplayName: textValue(route.ReviewerDisplayName), OrgPath: path, Queue: textValue(route.Queue), QueueItemID: textValue(queueID), AuditEventID: auditID})
	if err != nil || inserted != 1 {
		return approval.Route{}, errors.Join(ErrApprovalIdempotencyConflict, err)
	}
	if queueID != "" {
		if err := tx.InsertApprovalQueueItem(ctx, db.InsertApprovalQueueItemParams{ID: queueID, EnterpriseID: req.EnterpriseID, RequesterUserID: req.RequesterUserID, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: req.Action, RiskLevel: string(route.RiskLevel), OrgUnitID: req.OrgUnitID, ReviewerUserID: textValue(route.ReviewerUserID), OrgVersion: req.OrgVersion, RiskReasons: reasons, RouteMode: string(route.Mode), OrgPath: path, Queue: textValue(route.Queue), RouteInputHash: inputHash, RouteOutputHash: outputHash, PolicyVersion: req.PolicyVersion, IdempotencyKeyHash: req.IdempotencyHash, ReviewerOrgUnitID: textValue(reviewerUnit), ReviewerDisplayName: textValue(route.ReviewerDisplayName)}); err != nil {
			return approval.Route{}, err
		}
	}
	event := audit.NewEvent(audit.EventInput{ID: auditID, EnterpriseID: req.EnterpriseID, ActorUserID: req.RequesterUserID, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: "approval.route.resolve", Decision: string(route.Mode), InputHash: inputHash, OutputHash: outputHash, EvidencePointer: queueID}, previous)
	if err := tx.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: event.ID, EnterpriseID: event.EnterpriseID, ActorUserID: textValue(event.ActorUserID), ResourceType: textValue(event.ResourceType), ResourceID: textValue(event.ResourceID), Action: event.Action, Decision: event.Decision, InputHash: textValue(event.InputHash), OutputHash: textValue(event.OutputHash), EvidencePointer: textValue(event.EvidencePointer), PrevHash: textValue(event.PrevHash), EventHash: event.EventHash}); err != nil {
		return approval.Route{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return approval.Route{}, err
	}
	return route, nil
}

func routeFromResolution(row db.ApprovalResolutionIdempotency) (approval.Route, error) {
	var reasons []approval.RiskReason
	var path []string
	if err := json.Unmarshal(row.RiskReasons, &reasons); err != nil || reasons == nil {
		return approval.Route{}, errors.New("invalid stored approval resolution")
	}
	if err := json.Unmarshal(row.OrgPath, &path); err != nil || path == nil {
		return approval.Route{}, errors.New("invalid stored approval resolution")
	}
	return approval.Route{Mode: approval.RouteMode(row.RouteMode), RiskLevel: approval.RiskLevel(row.RiskLevel), RiskReasons: reasons, RequesterUserID: row.RequesterUserID, ReviewerUserID: row.ReviewerUserID.String, ReviewerDisplayName: row.ReviewerDisplayName.String, OrgPath: path, Queue: row.Queue.String, AutoPublish: row.AutoPublish, PolicyVersion: row.PolicyVersion}, nil
}
