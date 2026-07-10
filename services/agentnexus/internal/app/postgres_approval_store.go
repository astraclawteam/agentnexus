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
	AcquireEnterpriseAuditLock(context.Context, string) (any, error)
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

func NewPostgresApprovalStore(pool *pgxpool.Pool) *PostgresApprovalStore {
	return newPostgresApprovalStoreWithPool(&postgresApprovalWritePool{pool: pool}, rand.Reader)
}

func newPostgresApprovalStoreWithPool(pool approvalWriteTxBeginner, randomSource io.Reader) *PostgresApprovalStore {
	return &PostgresApprovalStore{pool: pool, random: randomSource}
}

func (s *PostgresApprovalStore) Record(ctx context.Context, req approval.Request, route approval.Route) (resultErr error) {
	if s == nil || s.pool == nil || s.random == nil || !validRecordedRoute(req, route) {
		return errors.New("approval store unavailable")
	}
	inputHash, outputHash, err := approvalEvidenceHashes(req, route)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginApprovalWriteTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err := tx.AcquireEnterpriseAuditLock(ctx, req.EnterpriseID); err != nil {
		return err
	}
	previous, err := tx.GetLatestEnterpriseAuditHash(ctx, req.EnterpriseID)
	if err != nil {
		return err
	}
	evidencePointer := ""
	if route.Mode != approval.ModeSingleConfirmation {
		queueID, err := randomApprovalID(s.random, "approval_")
		if err != nil {
			return err
		}
		reasons, err := json.Marshal(route.RiskReasons)
		if err != nil {
			return err
		}
		path, err := json.Marshal(route.OrgPath)
		if err != nil {
			return err
		}
		if err := tx.InsertApprovalQueueItem(ctx, db.InsertApprovalQueueItemParams{ID: queueID, EnterpriseID: req.EnterpriseID, RequesterUserID: req.RequesterUserID, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: req.Action, RiskLevel: string(route.RiskLevel), OrgUnitID: req.OrgUnitID, ReviewerUserID: textValue(route.ReviewerUserID), OrgVersion: req.OrgVersion, RiskReasons: reasons, RouteMode: string(route.Mode), OrgPath: path, Queue: textValue(route.Queue), RouteInputHash: inputHash, RouteOutputHash: outputHash}); err != nil {
			return err
		}
		evidencePointer = queueID
	}
	auditID, err := randomApprovalID(s.random, "approvalaudit_")
	if err != nil {
		return err
	}
	event := audit.NewEvent(audit.EventInput{ID: auditID, EnterpriseID: req.EnterpriseID, ActorUserID: req.RequesterUserID, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: "approval.route.resolve", Decision: string(route.Mode), InputHash: inputHash, OutputHash: outputHash, EvidencePointer: evidencePointer}, previous)
	if err := tx.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: event.ID, EnterpriseID: event.EnterpriseID, ActorUserID: textValue(event.ActorUserID), ResourceType: textValue(event.ResourceType), ResourceID: textValue(event.ResourceID), Action: event.Action, Decision: event.Decision, InputHash: textValue(event.InputHash), OutputHash: textValue(event.OutputHash), EvidencePointer: textValue(event.EvidencePointer), PrevHash: textValue(event.PrevHash), EventHash: event.EventHash}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
