package iam

import (
	"context"
	"strings"
	"testing"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/jackc/pgx/v5"
)

type enterpriseProvisioningDB struct {
	db.DBTX
	query string
	args  []any
}

func (f *enterpriseProvisioningDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	f.query, f.args = query, args
	return enterpriseProvisioningRow{}
}

type enterpriseProvisioningRow struct{}

func (enterpriseProvisioningRow) Scan(dest ...any) error {
	*dest[0].(*string) = "ent-new"
	*dest[1].(*string) = "New Enterprise"
	*dest[2].(*time.Time) = time.Unix(1, 0).UTC()
	return nil
}

func TestPostgresCreateEnterpriseAtomicallyProvisionsApprovalPolicy(t *testing.T) {
	database := &enterpriseProvisioningDB{}
	created, err := newPostgresStoreWithDB(database).CreateEnterprise(context.Background(), Enterprise{ID: "ent-new", Name: "New Enterprise"})
	if err != nil || created.ID != "ent-new" {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	sql := strings.ToLower(strings.Join(strings.Fields(database.query), " "))
	for _, fragment := range []string{
		"with created_enterprise as",
		"insert into enterprise_approval_policies",
		"select id, $3, $4, $5, 1 from created_enterprise",
		"on conflict (enterprise_id) do nothing",
	} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("enterprise creation is not atomic policy provisioning: missing %q in %s", fragment, sql)
		}
	}
	policy := approval.DefaultPolicy()
	if len(database.args) != 5 || database.args[2] != string(policy.MinimumRisk) || database.args[3] != policy.MaxLowImpactedUsers || database.args[4] != policy.MaxLowImpactedOrgUnits {
		t.Fatalf("enterprise default policy args=%v want=%+v", database.args, policy)
	}
}
