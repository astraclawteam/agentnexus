package app

import (
	"context"
	"errors"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type atlasPolicyTx interface {
	GetLatestAuthorizationOrgVersion(context.Context, string) (int64, error)
	ListAuthorizationOrgUnits(context.Context, db.ListAuthorizationOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error)
	ListAuthorizationMemberships(context.Context, db.ListAuthorizationMembershipsParams) ([]db.OrgPolicySnapshotMembership, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type atlasPolicyTxBeginner interface {
	BeginAtlasPolicyTx(context.Context, pgx.TxOptions) (atlasPolicyTx, error)
}

type postgresAtlasPolicyPool struct {
	pool *pgxpool.Pool
}

func (p *postgresAtlasPolicyPool) BeginAtlasPolicyTx(ctx context.Context, options pgx.TxOptions) (atlasPolicyTx, error) {
	if p == nil || p.pool == nil {
		return nil, policy.ErrAtlasPolicyUnavailable
	}
	tx, err := p.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &postgresAtlasPolicyTx{Tx: tx, queries: db.New(tx)}, nil
}

type postgresAtlasPolicyTx struct {
	pgx.Tx
	queries *db.Queries
}

func (t *postgresAtlasPolicyTx) GetLatestAuthorizationOrgVersion(ctx context.Context, enterpriseID string) (int64, error) {
	return t.queries.GetLatestAuthorizationOrgVersion(ctx, enterpriseID)
}

func (t *postgresAtlasPolicyTx) ListAuthorizationOrgUnits(ctx context.Context, params db.ListAuthorizationOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error) {
	return t.queries.ListAuthorizationOrgUnits(ctx, params)
}

func (t *postgresAtlasPolicyTx) ListAuthorizationMemberships(ctx context.Context, params db.ListAuthorizationMembershipsParams) ([]db.OrgPolicySnapshotMembership, error) {
	return t.queries.ListAuthorizationMemberships(ctx, params)
}

type postgresAtlasPolicySource struct {
	pool atlasPolicyTxBeginner
}

func NewPostgresAtlasPolicySource(pool *pgxpool.Pool) policy.AtlasPolicySource {
	return newPostgresAtlasPolicySourceWithPool(&postgresAtlasPolicyPool{pool: pool})
}

func newPostgresAtlasPolicySourceWithPool(pool atlasPolicyTxBeginner) *postgresAtlasPolicySource {
	return &postgresAtlasPolicySource{pool: pool}
}

func (s *postgresAtlasPolicySource) LoadAccessSnapshot(ctx context.Context, enterpriseID, actorUserID string) (policy.AtlasAccessSnapshot, error) {
	if s == nil || s.pool == nil || enterpriseID == "" || actorUserID == "" {
		return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
	}
	tx, err := s.pool.BeginAtlasPolicyTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	version, err := tx.GetLatestAuthorizationOrgVersion(ctx, enterpriseID)
	if err != nil || version < 1 {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	units, err := tx.ListAuthorizationOrgUnits(ctx, db.ListAuthorizationOrgUnitsParams{EnterpriseID: enterpriseID, VersionNumber: version})
	if err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	if len(units) > policy.MaxAtlasOrgUnits {
		return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
	}
	memberships, err := tx.ListAuthorizationMemberships(ctx, db.ListAuthorizationMembershipsParams{EnterpriseID: enterpriseID, VersionNumber: version, EnterpriseUserID: actorUserID})
	if err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	if len(memberships) > policy.MaxAtlasMemberships {
		return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
	}

	snapshot := policy.AtlasAccessSnapshot{EnterpriseID: enterpriseID, OrgVersion: version, OrgUnits: make([]policy.AtlasOrgUnit, 0, len(units)), Memberships: make([]policy.AtlasMembership, 0, len(memberships))}
	for _, unit := range units {
		if err := ctx.Err(); err != nil {
			return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
		}
		if unit.EnterpriseID != enterpriseID || unit.VersionNumber != version {
			return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
		}
		parentID := ""
		if unit.ParentID.Valid {
			parentID = unit.ParentID.String
		}
		snapshot.OrgUnits = append(snapshot.OrgUnits, policy.AtlasOrgUnit{ID: unit.OrgUnitID, ParentID: parentID})
	}
	for _, membership := range memberships {
		if err := ctx.Err(); err != nil {
			return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
		}
		if membership.EnterpriseID != enterpriseID || membership.VersionNumber != version || membership.EnterpriseUserID != actorUserID {
			return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
		}
		snapshot.Memberships = append(snapshot.Memberships, policy.AtlasMembership{OrgUnitID: membership.OrgUnitID, Role: membership.Role})
	}
	if err := tx.Commit(ctx); err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	return snapshot, nil
}
