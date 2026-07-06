package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/storage"
)

func TestPostgresCore(t *testing.T) {
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

	schema := fmt.Sprintf("agentnexus_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer adminPool.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)

	pool, err := storage.OpenPostgres(ctx, storage.PostgresConfig{
		DSN:        dsn,
		SearchPath: schema,
	})
	if err != nil {
		t.Fatalf("open schema postgres pool: %v", err)
	}
	defer pool.Close()

	if err := storage.ApplyEmbeddedMigrations(ctx, pool); err != nil {
		t.Fatalf("apply embedded migrations: %v", err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1, $2)`, "ent_test", "Test Enterprise"); err != nil {
		t.Fatalf("insert enterprise: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO enterprise_users (id, enterprise_id, display_name) VALUES ($1, $2, $3)`, "user_test", "ent_test", "Test User"); err != nil {
		t.Fatalf("insert enterprise user: %v", err)
	}

	var enterpriseName string
	if err := pool.QueryRow(ctx, `SELECT name FROM enterprises WHERE id = $1`, "ent_test").Scan(&enterpriseName); err != nil {
		t.Fatalf("get enterprise: %v", err)
	}
	if enterpriseName != "Test Enterprise" {
		t.Fatalf("enterprise name = %q, want %q", enterpriseName, "Test Enterprise")
	}

	var userName string
	if err := pool.QueryRow(ctx, `SELECT display_name FROM enterprise_users WHERE enterprise_id = $1 AND id = $2`, "ent_test", "user_test").Scan(&userName); err != nil {
		t.Fatalf("get enterprise user: %v", err)
	}
	if userName != "Test User" {
		t.Fatalf("user name = %q, want %q", userName, "Test User")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO audit_hash_heads (enterprise_id, event_hash) VALUES ($1, $2)`, "ent_test", "sha256:test"); err != nil {
		t.Fatalf("insert audit hash head: %v", err)
	}
}
