package app

import (
	"context"
	"errors"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5/pgxpool"
)

type atlasPolicyQueries interface {
	GetLatestAuthorizationOrgVersion(context.Context, string) (int64, error)
	ListAuthorizationOrgUnits(context.Context, string) ([]db.OrgUnit, error)
	ListAuthorizationMemberships(context.Context, db.ListAuthorizationMembershipsParams) ([]db.OrgMembership, error)
}

type postgresAtlasPolicySource struct {
	queries atlasPolicyQueries
}

func NewPostgresAtlasPolicySource(pool *pgxpool.Pool) policy.AtlasPolicySource {
	if pool == nil {
		return newPostgresAtlasPolicySourceWithQueries(nil)
	}
	return newPostgresAtlasPolicySourceWithQueries(db.New(pool))
}

func newPostgresAtlasPolicySourceWithQueries(queries atlasPolicyQueries) *postgresAtlasPolicySource {
	return &postgresAtlasPolicySource{queries: queries}
}

func (s *postgresAtlasPolicySource) LoadAccessSnapshot(ctx context.Context, enterpriseID, actorUserID string) (policy.AtlasAccessSnapshot, error) {
	if s == nil || s.queries == nil || enterpriseID == "" || actorUserID == "" {
		return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
	}
	version, err := s.queries.GetLatestAuthorizationOrgVersion(ctx, enterpriseID)
	if err != nil || version < 1 {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	units, err := s.queries.ListAuthorizationOrgUnits(ctx, enterpriseID)
	if err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}
	memberships, err := s.queries.ListAuthorizationMemberships(ctx, db.ListAuthorizationMembershipsParams{EnterpriseID: enterpriseID, EnterpriseUserID: actorUserID})
	if err != nil {
		return policy.AtlasAccessSnapshot{}, errors.Join(policy.ErrAtlasPolicyUnavailable, err)
	}

	snapshot := policy.AtlasAccessSnapshot{EnterpriseID: enterpriseID, OrgVersion: version, OrgUnits: make([]policy.AtlasOrgUnit, 0, len(units)), Memberships: make([]policy.AtlasMembership, 0, len(memberships))}
	for _, unit := range units {
		if unit.EnterpriseID != enterpriseID {
			return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
		}
		parentID := ""
		if unit.ParentID.Valid {
			parentID = unit.ParentID.String
		}
		snapshot.OrgUnits = append(snapshot.OrgUnits, policy.AtlasOrgUnit{ID: unit.ID, ParentID: parentID})
	}
	for _, membership := range memberships {
		if membership.EnterpriseID != enterpriseID || membership.EnterpriseUserID != actorUserID {
			return policy.AtlasAccessSnapshot{}, policy.ErrAtlasPolicyUnavailable
		}
		snapshot.Memberships = append(snapshot.Memberships, policy.AtlasMembership{OrgUnitID: membership.OrgUnitID, Role: membership.Role})
	}
	return snapshot, nil
}
