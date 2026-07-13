package app

import (
	"context"
	"errors"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// latestOrgVersionReader reads the current sealed organization snapshot
// version with a single indexed query.
type latestOrgVersionReader interface {
	GetLatestAuthorizationOrgVersion(context.Context, string) (int64, error)
}

// postgresOrgVersionSource resolves the sealed org snapshot version pinned at
// ingress. It runs ONE `GetLatestAuthorizationOrgVersion` query (the same
// sealed-version selection LoadAccessSnapshot performs internally) and never
// materializes the up-to-10k-row org snapshot, which the capability evaluator
// loads later only when a decision is actually taken.
type postgresOrgVersionSource struct {
	reader latestOrgVersionReader
}

// NewPostgresOrgVersionSource is the ingress org-version resolver used by the
// trust layer; distinct from the full snapshot source used by the evaluator.
func NewPostgresOrgVersionSource(pool *pgxpool.Pool) trust.OrgSnapshotResolver {
	return &postgresOrgVersionSource{reader: db.New(pool)}
}

func (s *postgresOrgVersionSource) ResolveSealedOrgVersion(ctx context.Context, tenantRef, _ string) (int64, error) {
	if s == nil || s.reader == nil || tenantRef == "" {
		return 0, trust.ErrSourceUnavailable
	}
	version, err := s.reader.GetLatestAuthorizationOrgVersion(ctx, tenantRef)
	if err != nil {
		// No sealed policy (pgx.ErrNoRows) or a database fault both fail closed
		// as retryable-unavailable; the caller maps this to 503.
		return 0, errors.Join(trust.ErrSourceUnavailable, err)
	}
	if version < 1 {
		return 0, trust.ErrSourceUnavailable
	}
	return version, nil
}

type policySnapshotTx interface {
	GetLatestAuthorizationOrgVersion(context.Context, string) (int64, error)
	ListAuthorizationOrgUnits(context.Context, db.ListAuthorizationOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error)
	ListAuthorizationMemberships(context.Context, db.ListAuthorizationMembershipsParams) ([]db.OrgPolicySnapshotMembership, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type policySnapshotTxBeginner interface {
	BeginPolicySnapshotTx(context.Context, pgx.TxOptions) (policySnapshotTx, error)
}

type postgresPolicySnapshotPool struct {
	pool *pgxpool.Pool
}

func (p *postgresPolicySnapshotPool) BeginPolicySnapshotTx(ctx context.Context, options pgx.TxOptions) (policySnapshotTx, error) {
	if p == nil || p.pool == nil {
		return nil, policy.ErrPolicyUnavailable
	}
	tx, err := p.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &postgresPolicySnapshotTx{Tx: tx, queries: db.New(tx)}, nil
}

type postgresPolicySnapshotTx struct {
	pgx.Tx
	queries *db.Queries
}

func (t *postgresPolicySnapshotTx) GetLatestAuthorizationOrgVersion(ctx context.Context, enterpriseID string) (int64, error) {
	return t.queries.GetLatestAuthorizationOrgVersion(ctx, enterpriseID)
}

func (t *postgresPolicySnapshotTx) ListAuthorizationOrgUnits(ctx context.Context, params db.ListAuthorizationOrgUnitsParams) ([]db.OrgPolicySnapshotUnit, error) {
	return t.queries.ListAuthorizationOrgUnits(ctx, params)
}

func (t *postgresPolicySnapshotTx) ListAuthorizationMemberships(ctx context.Context, params db.ListAuthorizationMembershipsParams) ([]db.OrgPolicySnapshotMembership, error) {
	return t.queries.ListAuthorizationMemberships(ctx, params)
}

type postgresSnapshotSource struct {
	pool policySnapshotTxBeginner
}

func NewPostgresSnapshotSource(pool *pgxpool.Pool) policy.SnapshotSource {
	return newPostgresSnapshotSourceWithPool(&postgresPolicySnapshotPool{pool: pool})
}

func newPostgresSnapshotSourceWithPool(pool policySnapshotTxBeginner) *postgresSnapshotSource {
	return &postgresSnapshotSource{pool: pool}
}

func (s *postgresSnapshotSource) LoadAccessSnapshot(ctx context.Context, enterpriseID, actorUserID string) (policy.SealedAccessSnapshot, error) {
	if s == nil || s.pool == nil || enterpriseID == "" || actorUserID == "" {
		return policy.SealedAccessSnapshot{}, policy.ErrPolicyUnavailable
	}
	tx, err := s.pool.BeginPolicySnapshotTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	version, err := tx.GetLatestAuthorizationOrgVersion(ctx, enterpriseID)
	if err != nil || version < 1 {
		return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
	}
	units, err := tx.ListAuthorizationOrgUnits(ctx, db.ListAuthorizationOrgUnitsParams{EnterpriseID: enterpriseID, VersionNumber: version})
	if err != nil {
		return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
	}
	if len(units) > policy.MaxSealedOrgUnits {
		return policy.SealedAccessSnapshot{}, policy.ErrPolicyUnavailable
	}
	memberships, err := tx.ListAuthorizationMemberships(ctx, db.ListAuthorizationMembershipsParams{EnterpriseID: enterpriseID, VersionNumber: version, EnterpriseUserID: actorUserID})
	if err != nil {
		return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
	}
	if len(memberships) > policy.MaxSealedMemberships {
		return policy.SealedAccessSnapshot{}, policy.ErrPolicyUnavailable
	}

	snapshot := policy.SealedAccessSnapshot{TenantRef: enterpriseID, OrgVersion: version, OrgUnits: make([]policy.SealedOrgUnit, 0, len(units)), Memberships: make([]policy.SealedMembership, 0, len(memberships))}
	for _, unit := range units {
		if err := ctx.Err(); err != nil {
			return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
		}
		if unit.EnterpriseID != enterpriseID || unit.VersionNumber != version {
			return policy.SealedAccessSnapshot{}, policy.ErrPolicyUnavailable
		}
		parentID := ""
		if unit.ParentID.Valid {
			parentID = unit.ParentID.String
		}
		snapshot.OrgUnits = append(snapshot.OrgUnits, policy.SealedOrgUnit{ID: unit.OrgUnitID, ParentID: parentID})
	}
	for _, membership := range memberships {
		if err := ctx.Err(); err != nil {
			return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
		}
		if membership.EnterpriseID != enterpriseID || membership.VersionNumber != version || membership.EnterpriseUserID != actorUserID {
			return policy.SealedAccessSnapshot{}, policy.ErrPolicyUnavailable
		}
		snapshot.Memberships = append(snapshot.Memberships, policy.SealedMembership{OrgUnitID: membership.OrgUnitID, Role: membership.Role})
	}
	if err := tx.Commit(ctx); err != nil {
		return policy.SealedAccessSnapshot{}, errors.Join(policy.ErrPolicyUnavailable, err)
	}
	return snapshot, nil
}
