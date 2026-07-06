package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/instance"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/storage"
)

func TestPostgresConnectorInstancePersistsRefsOnly(t *testing.T) {
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

	schema := fmt.Sprintf("agentnexus_connector_instance_test_%d", time.Now().UnixNano())
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
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1, $2)`, "ent_1", "Enterprise 1"); err != nil {
		t.Fatalf("insert enterprise: %v", err)
	}

	ids := connectorInstanceSequenceIDs("pkg_1", "instance_1", "audit_1")
	service := instance.NewService(instance.NewPostgresStore(pool), instance.ServiceConfig{
		SecretResolver: instance.StaticSecretResolver{"secret://agentnexus/dev/file-storage": "resolved-secret-value"},
		AuditSink:      instance.NewMemoryAuditSink(),
		NewID:          ids,
	})
	draft, err := service.DraftInstance(ctx, instance.DraftInstanceInput{
		EnterpriseID: "ent_1",
		Manifest:     validConnectorInstanceManifest(),
		BaseURL:      "https://files.example.test",
		AccountSet:   []string{"readonly"},
		DataScope:    []string{"legal_contracts"},
		CredentialRefs: map[string]string{
			"api_key": "secret://agentnexus/dev/file-storage",
		},
	})
	if err != nil {
		t.Fatalf("DraftInstance returned error: %v", err)
	}

	var persistedConfig string
	if err := pool.QueryRow(ctx, `SELECT config::text FROM connector_instance_versions WHERE connector_instance_id = $1`, draft.Instance.ID).Scan(&persistedConfig); err != nil {
		t.Fatalf("select persisted config: %v", err)
	}
	if !strings.Contains(persistedConfig, "secret://agentnexus/dev/file-storage") {
		t.Fatalf("persisted config does not include credential ref: %s", persistedConfig)
	}
	if strings.Contains(persistedConfig, "resolved-secret-value") {
		t.Fatalf("persisted config leaked resolved secret: %s", persistedConfig)
	}

	smoke, err := service.SmokeInstance(ctx, instance.SmokeInstanceInput{
		EnterpriseID: "ent_1",
		InstanceID:   draft.Instance.ID,
		Resource:     "legal_contracts",
		Operation:    "read",
		Fields:       []string{"title", "body", "owner_email"},
	})
	if err != nil {
		t.Fatalf("SmokeInstance returned error: %v", err)
	}
	if !smoke.OK || !smoke.CredentialResolved || !smoke.SchemaValid || !smoke.MaskingValid {
		t.Fatalf("smoke = %+v", smoke)
	}

	confirmed, err := service.ConfirmInstance(ctx, instance.ConfirmInstanceInput{
		EnterpriseID:        "ent_1",
		InstanceID:          draft.Instance.ID,
		HumanConfirmationID: "confirm_1",
	})
	if err != nil {
		t.Fatalf("ConfirmInstance returned error: %v", err)
	}
	if confirmed.Status != instance.StatusPublished {
		t.Fatalf("confirmed status = %q", confirmed.Status)
	}

	reloaded, err := instance.NewPostgresStore(pool).GetInstance(ctx, "ent_1", draft.Instance.ID)
	if err != nil {
		t.Fatalf("reload instance: %v", err)
	}
	if reloaded.Status != instance.StatusPublished || reloaded.CredentialRefs["api_key"] != "secret://agentnexus/dev/file-storage" {
		t.Fatalf("reloaded instance = %+v", reloaded)
	}
}

func validConnectorInstanceManifest() connector.Manifest {
	return connector.Manifest{
		SchemaVersion: "1",
		Name:          "file-storage-demo",
		Version:       "0.1.0",
		Credentials: []connector.Credential{{
			Name:          "api_key",
			CredentialRef: "secret://agentnexus/dev/file-storage",
		}},
		Resources: []connector.Resource{{
			Name:       "legal_contracts",
			Type:       connector.ResourceTypeFile,
			Operations: []connector.Operation{{Name: "read"}},
			Fields: []connector.Field{
				{Name: "title", Type: "string"},
				{Name: "body", Type: "string", Mask: true},
				{Name: "owner_email", Type: "string", Mask: true},
			},
			InputSchema:  map[string]any{"type": "object"},
			OutputSchema: map[string]any{"type": "object"},
			SmokeTests: []connector.SmokeTest{{
				Name:      "read legal contracts",
				Operation: "read",
				Fields:    []string{"title", "body", "owner_email"},
			}},
			Risk: connector.RiskMetadata{Level: connector.RiskHigh},
		}},
	}
}

func connectorInstanceSequenceIDs(ids ...string) func() string {
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
