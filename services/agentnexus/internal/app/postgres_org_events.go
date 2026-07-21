package app

import (
	"context"
	"errors"
	"math"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresOrgEventSource struct {
	reader *db.Queries
}

// NewPostgresOrgEventSource reads the sealed organization change feed. It is a
// READ-ONLY projection of rows the organization-import path already writes; it
// never seals a version and never publishes an unsealed one.
func NewPostgresOrgEventSource(pool *pgxpool.Pool) OrgEventSource {
	return &postgresOrgEventSource{reader: db.New(pool)}
}

func (s *postgresOrgEventSource) LatestSealedVersion(ctx context.Context, tenantRef string) (int64, error) {
	if s == nil || s.reader == nil || tenantRef == "" {
		return 0, errors.New("org event source unavailable")
	}
	version, err := s.reader.GetLatestAuthorizationOrgVersion(ctx, tenantRef)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// A tenant that has never sealed an organization version has a
			// current version of zero. That is a legitimate empty feed, not an
			// outage: a first-time consumer must be able to subscribe before
			// the first import completes.
			return 0, nil
		}
		return 0, err
	}
	if version < 0 {
		return 0, nil
	}
	return version, nil
}

func (s *postgresOrgEventSource) EventsSince(ctx context.Context, tenantRef string, sinceVersion int64, limit int) ([]OrgEventRecord, error) {
	if s == nil || s.reader == nil || tenantRef == "" {
		return nil, errors.New("org event source unavailable")
	}
	if limit <= 0 || limit > math.MaxInt32 {
		return nil, errors.New("org event page limit out of range")
	}
	rows, err := s.reader.ListSealedOrgEventsSince(ctx, db.ListSealedOrgEventsSinceParams{
		EnterpriseID:  tenantRef,
		VersionNumber: sinceVersion,
		Limit:         int32(limit),
	})
	if err != nil {
		return nil, err
	}
	events := make([]OrgEventRecord, 0, len(rows))
	for _, row := range rows {
		events = append(events, OrgEventRecord{
			EventID:    row.ID,
			EventType:  row.EventType,
			OrgVersion: row.VersionNumber,
			OccurredAt: row.CreatedAt.Time,
		})
	}
	return events, nil
}
