package instance

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreatePackage(ctx context.Context, pkg Package) (Package, error) {
	manifestJSON, err := json.Marshal(pkg.Manifest)
	if err != nil {
		return Package{}, err
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO connector_packages (id, name, manifest_version, manifest_json, created_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at
	`, pkg.ID, pkg.Name, pkg.Version, manifestJSON, pkg.CreatedAt).Scan(&pkg.CreatedAt)
	if err != nil {
		return Package{}, err
	}
	return pkg, nil
}

func (s *PostgresStore) CreateInstance(ctx context.Context, cfg Config) (Config, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Config{}, err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		INSERT INTO connector_instances (id, enterprise_id, connector_package_id, name, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at, updated_at
	`, cfg.ID, cfg.EnterpriseID, cfg.PackageID, cfg.PackageName, cfg.Status, cfg.CreatedAt, cfg.UpdatedAt).Scan(&cfg.CreatedAt, &cfg.UpdatedAt)
	if err != nil {
		return Config{}, err
	}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return Config{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO connector_instance_versions (id, enterprise_id, connector_instance_id, version_number, config, status, created_at)
		VALUES ($1, $2, $3, 1, $4, $5, $6)
	`, cfg.ID+"_version_1", cfg.EnterpriseID, cfg.ID, configJSON, cfg.Status, cfg.CreatedAt)
	if err != nil {
		return Config{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (s *PostgresStore) CreateHealthEvent(ctx context.Context, event HealthEvent) (HealthEvent, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO connector_health_events (id, enterprise_id, connector_instance_id, status, message, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at
	`, event.ID, event.EnterpriseID, event.InstanceID, event.Status, event.Message, event.CreatedAt).Scan(&event.CreatedAt)
	if err != nil {
		return HealthEvent{}, err
	}
	return event, nil
}

func (s *PostgresStore) GetPackage(ctx context.Context, id string) (Package, error) {
	var pkg Package
	var manifestJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, manifest_version, manifest_json, created_at
		FROM connector_packages
		WHERE id = $1
	`, id).Scan(&pkg.ID, &pkg.Name, &pkg.Version, &manifestJSON, &pkg.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Package{}, fmt.Errorf("connector package not found")
		}
		return Package{}, err
	}
	if err := json.Unmarshal(manifestJSON, &pkg.Manifest); err != nil {
		return Package{}, err
	}
	return pkg, nil
}

func (s *PostgresStore) GetInstance(ctx context.Context, enterpriseID, id string) (Config, error) {
	cfg, err := s.getInstance(ctx, enterpriseID, id)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (s *PostgresStore) UpdateInstanceStatus(ctx context.Context, enterpriseID, id, status string) (Config, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Config{}, err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE connector_instances
		SET status = $1, updated_at = now()
		WHERE enterprise_id = $2 AND id = $3
	`, status, enterpriseID, id)
	if err != nil {
		return Config{}, err
	}
	if tag.RowsAffected() == 0 {
		return Config{}, fmt.Errorf("connector instance not found")
	}
	tag, err = tx.Exec(ctx, `
		UPDATE connector_instance_versions
		SET status = $1
		WHERE enterprise_id = $2 AND connector_instance_id = $3
	`, status, enterpriseID, id)
	if err != nil {
		return Config{}, err
	}
	if tag.RowsAffected() == 0 {
		return Config{}, fmt.Errorf("connector instance version not found")
	}
	if err := tx.Commit(ctx); err != nil {
		return Config{}, err
	}
	return s.getInstance(ctx, enterpriseID, id)
}

func (s *PostgresStore) getInstance(ctx context.Context, enterpriseID, id string) (Config, error) {
	var cfg Config
	var configJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT ci.id, ci.enterprise_id, ci.connector_package_id, cp.name, ci.status, ci.created_at, ci.updated_at, civ.config
		FROM connector_instances ci
		JOIN connector_packages cp ON cp.id = ci.connector_package_id
		JOIN connector_instance_versions civ ON civ.connector_instance_id = ci.id
		WHERE ci.enterprise_id = $1 AND ci.id = $2
		ORDER BY civ.version_number DESC
		LIMIT 1
	`, enterpriseID, id).Scan(&cfg.ID, &cfg.EnterpriseID, &cfg.PackageID, &cfg.PackageName, &cfg.Status, &cfg.CreatedAt, &cfg.UpdatedAt, &configJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Config{}, fmt.Errorf("connector instance not found")
		}
		return Config{}, err
	}
	var stored Config
	if err := json.Unmarshal(configJSON, &stored); err != nil {
		return Config{}, err
	}
	cfg.BaseURL = stored.BaseURL
	cfg.AccountSet = stored.AccountSet
	cfg.FieldMapping = stored.FieldMapping
	cfg.DataScope = stored.DataScope
	cfg.CredentialRefs = stored.CredentialRefs
	return cfg, nil
}

var _ Store = (*PostgresStore)(nil)
