package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/storage"
)

func TestPostgresOrgImportPersistsGraph(t *testing.T) {
	dsn := os.Getenv("AGENTNEXUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTNEXUS_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	adminPool, err := storage.OpenPostgres(ctx, storage.PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatalf("open admin postgres pool: %v", err)
	}
	defer adminPool.Close()

	schema := fmt.Sprintf("agentnexus_org_import_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer adminPool.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)

	pool, err := storage.OpenPostgres(ctx, storage.PostgresConfig{DSN: dsn, SearchPath: schema})
	if err != nil {
		t.Fatalf("open schema postgres pool: %v", err)
	}
	defer pool.Close()
	if err := storage.ApplyEmbeddedMigrations(ctx, pool); err != nil {
		t.Fatalf("apply embedded migrations: %v", err)
	}

	service := iam.NewService(
		iam.NewPostgresStore(pool),
		iam.WithIDGenerator(sequenceIDs("identity_oa", "identity_email", "identity_llmrouter", "event_1", "version_1")),
	)
	result, err := service.ConfirmOrgImport(ctx, iam.ConfirmOrgImportInput{
		EnterpriseID:   "ent_1",
		EnterpriseName: "Enterprise 1",
		Provider:       iam.ProviderOAHTTP,
		SourceHash:     "sha256:source",
		Snapshot: orgsource.Snapshot{
			Departments: []orgsource.Department{{ID: "dept_rd", Name: "R&D"}},
			Employees:   []orgsource.Employee{{ID: "user_ada", DisplayName: "Ada", Email: "ada@example.test", DepartmentIDs: []string{"dept_rd"}}},
		},
	})
	if err != nil {
		t.Fatalf("ConfirmOrgImport returned error: %v", err)
	}
	if result.OrgVersion.ID != "version_1" || result.OrgVersion.VersionNumber != 1 {
		t.Fatalf("result = %+v", result)
	}

	graph, err := service.GetOrgGraph(ctx, "ent_1")
	if err != nil {
		t.Fatalf("GetOrgGraph returned error: %v", err)
	}
	if len(graph.Departments) != 1 || len(graph.Users) != 1 || len(graph.Memberships) != 1 || len(graph.ExternalIdentities) != 3 || len(graph.Versions) != 1 {
		t.Fatalf("graph = %+v", graph)
	}
}

func sequenceIDs(ids ...string) func() string {
	index := 0
	return func() string {
		if index >= len(ids) {
			return "extra_id"
		}
		id := ids[index]
		index++
		return id
	}
}
