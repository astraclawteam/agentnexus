package app

import (
	"context"
	"errors"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LoadedApprovalSnapshot struct {
	Snapshot    approval.OrgSnapshot
	Permissions approval.PermissionChecker
}

type ApprovalSnapshotSource interface {
	LoadApprovalSnapshot(context.Context, string, int64, string) (LoadedApprovalSnapshot, error)
}

type approvalSnapshotTx interface {
	GetLatestApprovalOrgVersion(context.Context, string) (int64, error)
	ListApprovalOrgUnits(context.Context, db.ListApprovalOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error)
	ListApprovalMemberships(context.Context, db.ListApprovalMembershipsParams) ([]db.OrgPolicySnapshotMembership, error)
	ListApprovalUsers(context.Context, db.ListApprovalUsersParams) ([]db.ListApprovalUsersRow, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type approvalSnapshotTxBeginner interface {
	BeginApprovalSnapshotTx(context.Context, pgx.TxOptions) (approvalSnapshotTx, error)
}

type postgresApprovalSnapshotPool struct{ pool *pgxpool.Pool }

func (p *postgresApprovalSnapshotPool) BeginApprovalSnapshotTx(ctx context.Context, options pgx.TxOptions) (approvalSnapshotTx, error) {
	if p == nil || p.pool == nil {
		return nil, approval.ErrApprovalUnavailable
	}
	tx, err := p.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &postgresApprovalSnapshotTx{Tx: tx, queries: db.New(tx)}, nil
}

type postgresApprovalSnapshotTx struct {
	pgx.Tx
	queries *db.Queries
}

func (t *postgresApprovalSnapshotTx) GetLatestApprovalOrgVersion(ctx context.Context, enterpriseID string) (int64, error) {
	return t.queries.GetLatestApprovalOrgVersion(ctx, enterpriseID)
}
func (t *postgresApprovalSnapshotTx) ListApprovalOrgUnits(ctx context.Context, params db.ListApprovalOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error) {
	return t.queries.ListApprovalOrgUnits(ctx, params)
}
func (t *postgresApprovalSnapshotTx) ListApprovalMemberships(ctx context.Context, params db.ListApprovalMembershipsParams) ([]db.OrgPolicySnapshotMembership, error) {
	return t.queries.ListApprovalMemberships(ctx, params)
}
func (t *postgresApprovalSnapshotTx) ListApprovalUsers(ctx context.Context, params db.ListApprovalUsersParams) ([]db.ListApprovalUsersRow, error) {
	return t.queries.ListApprovalUsers(ctx, params)
}

type PostgresApprovalSource struct{ pool approvalSnapshotTxBeginner }

func NewPostgresApprovalSource(pool *pgxpool.Pool) *PostgresApprovalSource {
	return newPostgresApprovalSourceWithPool(&postgresApprovalSnapshotPool{pool: pool})
}

func newPostgresApprovalSourceWithPool(pool approvalSnapshotTxBeginner) *PostgresApprovalSource {
	return &PostgresApprovalSource{pool: pool}
}

func (s *PostgresApprovalSource) LoadApprovalSnapshot(ctx context.Context, enterpriseID string, requestedVersion int64, requesterUserID string) (result LoadedApprovalSnapshot, resultErr error) {
	if s == nil || s.pool == nil || !canonicalAuthorizationValue(enterpriseID) || !canonicalAuthorizationValue(requesterUserID) || requestedVersion < 1 {
		return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
	}
	tx, err := s.pool.BeginApprovalSnapshotTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if err := ctx.Err(); err != nil {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	version, err := tx.GetLatestApprovalOrgVersion(ctx, enterpriseID)
	if err != nil || version != requestedVersion {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	units, err := tx.ListApprovalOrgUnits(ctx, db.ListApprovalOrgUnitsParams{EnterpriseID: enterpriseID, VersionNumber: version})
	if err != nil || len(units) > approval.MaxSnapshotOrgUnits {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	memberships, err := tx.ListApprovalMemberships(ctx, db.ListApprovalMembershipsParams{EnterpriseID: enterpriseID, VersionNumber: version})
	if err != nil || len(memberships) > approval.MaxSnapshotPrincipals {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	users, err := tx.ListApprovalUsers(ctx, db.ListApprovalUsersParams{EnterpriseID: enterpriseID, VersionNumber: version})
	if err != nil || len(users) > approval.MaxSnapshotPrincipals {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}

	approvalUnits := make([]approval.SnapshotUnit, 0, len(units))
	atlasUnits := make([]policy.AtlasOrgUnit, 0, len(units))
	for _, row := range units {
		if row.EnterpriseID != enterpriseID || row.VersionNumber != version || !canonicalAuthorizationValue(row.OrgUnitID) || (row.ParentID.Valid && !canonicalAuthorizationValue(row.ParentID.String)) {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		parentID := ""
		if row.ParentID.Valid {
			parentID = row.ParentID.String
		}
		approvalUnits = append(approvalUnits, approval.SnapshotUnit{ID: row.OrgUnitID, ParentID: parentID})
		atlasUnits = append(atlasUnits, policy.AtlasOrgUnit{ID: row.OrgUnitID, ParentID: parentID})
	}
	approvalUsers := make([]approval.SnapshotUser, 0, len(users))
	knownUsers := make(map[string]struct{}, len(users))
	for _, row := range users {
		if row.EnterpriseID != enterpriseID || !canonicalAuthorizationValue(row.ID) || !canonicalAuthorizationValue(row.DisplayName) {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		if _, exists := knownUsers[row.ID]; exists {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		knownUsers[row.ID] = struct{}{}
		approvalUsers = append(approvalUsers, approval.SnapshotUser{ID: row.ID, DisplayName: row.DisplayName})
	}
	approvalMemberships := make([]approval.SnapshotMembership, 0, len(memberships))
	actorMemberships := make(map[string][]policy.AtlasMembership)
	for _, row := range memberships {
		if row.EnterpriseID != enterpriseID || row.VersionNumber != version || !canonicalAuthorizationValue(row.EnterpriseUserID) || !canonicalAuthorizationValue(row.OrgUnitID) || !canonicalAuthorizationValue(row.Role) {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		if _, exists := knownUsers[row.EnterpriseUserID]; !exists {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		approvalMemberships = append(approvalMemberships, approval.SnapshotMembership{UserID: row.EnterpriseUserID, OrgUnitID: row.OrgUnitID, Role: row.Role})
		actorMemberships[row.EnterpriseUserID] = append(actorMemberships[row.EnterpriseUserID], policy.AtlasMembership{OrgUnitID: row.OrgUnitID, Role: row.Role})
	}
	snapshot, err := approval.NewOrgSnapshot(enterpriseID, version, approvalUnits, approvalMemberships, approvalUsers)
	if err != nil {
		return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
	}
	fixedSource := policy.NewMemoryAtlasPolicySource()
	for userID, rows := range actorMemberships {
		fixedSource.StoreSnapshot(enterpriseID, userID, policy.AtlasAccessSnapshot{EnterpriseID: enterpriseID, OrgVersion: version, OrgUnits: atlasUnits, Memberships: rows})
	}
	if _, exists := actorMemberships[requesterUserID]; !exists {
		fixedSource.StoreSnapshot(enterpriseID, requesterUserID, policy.AtlasAccessSnapshot{EnterpriseID: enterpriseID, OrgVersion: version, OrgUnits: atlasUnits, Memberships: []policy.AtlasMembership{}})
	}
	if err := tx.Commit(ctx); err != nil {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	return LoadedApprovalSnapshot{Snapshot: snapshot, Permissions: &atlasApprovalPermissionChecker{evaluator: policy.NewAgentAtlasEvaluator(fixedSource)}}, nil
}

type atlasApprovalPermissionChecker struct{ evaluator *policy.AgentAtlasEvaluator }

func (c *atlasApprovalPermissionChecker) Allows(ctx context.Context, req approval.PermissionRequest) (bool, error) {
	if c == nil || c.evaluator == nil {
		return false, approval.ErrApprovalUnavailable
	}
	resourceType := policy.ResourceKnowledge
	action := policy.ActionKnowledgePublishLowRisk
	expected := policy.PermissionPublishLowRisk
	if req.Permission == approval.PermissionApproveHighRisk {
		action = policy.ActionKnowledgeApproveHighRisk
		expected = policy.PermissionApproveHighRisk
	} else if req.Permission != approval.PermissionPublishLowRisk {
		return false, approval.ErrApprovalUnavailable
	}
	decision, err := c.evaluator.Evaluate(ctx, policy.ScopedRequest{EnterpriseID: req.EnterpriseID, ActorUserID: req.UserID, OrgUnitID: req.OrgUnitID, OrgVersion: req.OrgVersion, ResourceType: resourceType, ResourceID: req.ResourceID, Action: action})
	if err != nil {
		return false, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	if decision.Decision != policy.DecisionAllow || decision.OrgVersion != req.OrgVersion {
		return false, nil
	}
	for _, permission := range decision.Permissions {
		if permission == expected {
			return true, nil
		}
	}
	return false, nil
}
