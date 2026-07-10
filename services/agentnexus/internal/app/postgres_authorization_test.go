package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

type stubAtlasQueries struct {
	versionEnterprise    string
	unitsEnterprise      string
	membershipEnterprise string
	membershipUser       string
	units                []db.OrgUnit
	memberships          []db.OrgMembership
}

func (s *stubAtlasQueries) GetLatestAuthorizationOrgVersion(_ context.Context, enterpriseID string) (int64, error) {
	s.versionEnterprise = enterpriseID
	return 17, nil
}

func (s *stubAtlasQueries) ListAuthorizationOrgUnits(_ context.Context, enterpriseID string) ([]db.OrgUnit, error) {
	s.unitsEnterprise = enterpriseID
	if s.units != nil {
		return s.units, nil
	}
	return []db.OrgUnit{{ID: "child", EnterpriseID: enterpriseID}, {ID: "parent", EnterpriseID: enterpriseID}}, nil
}

func (s *stubAtlasQueries) ListAuthorizationMemberships(_ context.Context, arg db.ListAuthorizationMembershipsParams) ([]db.OrgMembership, error) {
	s.membershipEnterprise = arg.EnterpriseID
	s.membershipUser = arg.EnterpriseUserID
	if s.memberships != nil {
		return s.memberships, nil
	}
	return []db.OrgMembership{{EnterpriseID: arg.EnterpriseID, EnterpriseUserID: arg.EnterpriseUserID, OrgUnitID: "parent", Role: "edit"}}, nil
}

func TestPostgresAtlasPolicySourceRejectsCrossTenantRows(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		queries *stubAtlasQueries
	}{
		{name: "foreign org unit", queries: &stubAtlasQueries{units: []db.OrgUnit{{ID: "dept", EnterpriseID: "enterprise-2"}}, memberships: []db.OrgMembership{}}},
		{name: "foreign membership", queries: &stubAtlasQueries{units: []db.OrgUnit{{ID: "dept", EnterpriseID: "enterprise-1"}}, memberships: []db.OrgMembership{{EnterpriseID: "enterprise-2", EnterpriseUserID: "user-1", OrgUnitID: "dept", Role: "suggest"}}}},
		{name: "foreign user membership", queries: &stubAtlasQueries{units: []db.OrgUnit{{ID: "dept", EnterpriseID: "enterprise-1"}}, memberships: []db.OrgMembership{{EnterpriseID: "enterprise-1", EnterpriseUserID: "user-2", OrgUnitID: "dept", Role: "suggest"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := newPostgresAtlasPolicySourceWithQueries(test.queries).LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
			if !errors.Is(err, policy.ErrAtlasPolicyUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPostgresAtlasPolicySourceUsesCompositeEnterpriseScope(t *testing.T) {
	t.Parallel()
	queries := &stubAtlasQueries{}
	source := newPostgresAtlasPolicySourceWithQueries(queries)

	snapshot, err := source.LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if queries.versionEnterprise != "enterprise-1" || queries.unitsEnterprise != "enterprise-1" || queries.membershipEnterprise != "enterprise-1" || queries.membershipUser != "user-1" {
		t.Fatalf("queries were not composite scoped: %#v", queries)
	}
	if snapshot.EnterpriseID != "enterprise-1" || snapshot.OrgVersion != 17 {
		t.Fatalf("snapshot identity/version = %#v", snapshot)
	}
	if !reflect.DeepEqual(snapshot.Memberships, []policy.AtlasMembership{{OrgUnitID: "parent", Role: "edit"}}) {
		t.Fatalf("memberships = %#v", snapshot.Memberships)
	}
	if got := []string{snapshot.OrgUnits[0].ID, snapshot.OrgUnits[1].ID}; !reflect.DeepEqual(got, []string{"child", "parent"}) {
		t.Fatalf("org units = %#v", snapshot.OrgUnits)
	}
}
