package app

import (
	"context"
	"errors"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LoadedApprovalSnapshot struct {
	Snapshot      approval.OrgSnapshot
	Policy        approval.Policy
	PolicyVersion int64
}

type ApprovalSnapshotSource interface {
	LoadApprovalSnapshot(context.Context, string, int64, string) (LoadedApprovalSnapshot, error)
}

type approvalSnapshotTx interface {
	GetLatestApprovalOrgVersion(context.Context, string) (int64, error)
	GetEnterpriseApprovalPolicy(context.Context, string) (db.EnterpriseApprovalPolicy, error)
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
func (t *postgresApprovalSnapshotTx) GetEnterpriseApprovalPolicy(ctx context.Context, enterpriseID string) (db.EnterpriseApprovalPolicy, error) {
	return t.queries.GetEnterpriseApprovalPolicy(ctx, enterpriseID)
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
	approvalPolicy := approval.DefaultPolicy()
	policyVersion := int64(0)
	policyRow, err := tx.GetEnterpriseApprovalPolicy(ctx, enterpriseID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	if err == nil {
		if policyRow.EnterpriseID != enterpriseID || policyRow.PolicyVersion < 1 || policyRow.MaxLowImpactedUsers < 0 || policyRow.MaxLowImpactedOrgUnits < 0 {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		approvalPolicy = approval.Policy{MinimumRisk: approval.RiskLevel(policyRow.MinimumRisk), MaxLowImpactedUsers: int(policyRow.MaxLowImpactedUsers), MaxLowImpactedOrgUnits: int(policyRow.MaxLowImpactedOrgUnits)}
		policyVersion = policyRow.PolicyVersion
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
	for _, row := range units {
		if row.EnterpriseID != enterpriseID || row.VersionNumber != version || !canonicalAuthorizationValue(row.OrgUnitID) || (row.ParentID.Valid && !canonicalAuthorizationValue(row.ParentID.String)) {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		parentID := ""
		if row.ParentID.Valid {
			parentID = row.ParentID.String
		}
		approvalUnits = append(approvalUnits, approval.SnapshotUnit{ID: row.OrgUnitID, ParentID: parentID})
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
	for _, row := range memberships {
		if row.EnterpriseID != enterpriseID || row.VersionNumber != version || !canonicalAuthorizationValue(row.EnterpriseUserID) || !canonicalAuthorizationValue(row.OrgUnitID) || !canonicalAuthorizationValue(row.Role) {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		if _, exists := knownUsers[row.EnterpriseUserID]; !exists {
			return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
		}
		approvalMemberships = append(approvalMemberships, approval.SnapshotMembership{UserID: row.EnterpriseUserID, OrgUnitID: row.OrgUnitID, Role: row.Role})
	}
	snapshot, err := approval.NewOrgSnapshot(enterpriseID, version, approvalUnits, approvalMemberships, approvalUsers)
	if err != nil {
		return LoadedApprovalSnapshot{}, approval.ErrApprovalUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return LoadedApprovalSnapshot{}, errors.Join(approval.ErrApprovalUnavailable, err)
	}
	return LoadedApprovalSnapshot{Snapshot: snapshot, Policy: approvalPolicy, PolicyVersion: policyVersion}, nil
}
