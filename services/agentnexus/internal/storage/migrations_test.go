package storage

import (
	"strings"
	"testing"
)

func TestEmbeddedCoreMigrationContainsM1Tables(t *testing.T) {
	migrations := EmbeddedMigrations()
	if len(migrations) == 0 {
		t.Fatal("EmbeddedMigrations returned no migrations")
	}
	sql := strings.Join(migrations, "\n")
	for _, table := range []string{
		"enterprises",
		"enterprise_users",
		"task_runs",
		"task_steps",
		"connector_packages",
		"connector_instances",
		"case_tickets",
		"step_grants",
		"audit_events",
		"audit_hash_heads",
	} {
		if !strings.Contains(sql, "CREATE TABLE "+table) {
			t.Fatalf("embedded migrations missing CREATE TABLE %s", table)
		}
	}
}
