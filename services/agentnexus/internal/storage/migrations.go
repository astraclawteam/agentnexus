package storage

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema/*.sql
var schemaFS embed.FS

func EmbeddedMigrations() []string {
	entries, err := schemaFS.ReadDir("schema")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	migrations := make([]string, 0, len(names))
	for _, name := range names {
		bytes, err := schemaFS.ReadFile("schema/" + name)
		if err != nil {
			return nil
		}
		migrations = append(migrations, extractUpSQL(string(bytes)))
	}
	return migrations
}

func ApplyEmbeddedMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("postgres pool is required")
	}
	for _, migration := range EmbeddedMigrations() {
		if strings.TrimSpace(migration) == "" {
			continue
		}
		if _, err := pool.Exec(ctx, migration); err != nil {
			return err
		}
	}
	return nil
}

func extractUpSQL(migration string) string {
	start := strings.Index(migration, "-- +goose Up")
	end := strings.Index(migration, "-- +goose Down")
	if start == -1 {
		return migration
	}
	if end == -1 {
		return migration[start:]
	}
	return migration[start:end]
}
