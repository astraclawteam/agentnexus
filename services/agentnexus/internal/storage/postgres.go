package storage

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresConfig struct {
	DSN        string
	SearchPath string
}

func OpenPostgres(ctx context.Context, cfg PostgresConfig) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, err
	}

	if cfg.SearchPath != "" {
		poolConfig.ConnConfig.RuntimeParams["search_path"] = cfg.SearchPath
	}

	return pgxpool.NewWithConfig(ctx, poolConfig)
}
