package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the durable evidence store. Handle immutability and the
// append-only handle event log are enforced by database triggers (migration
// 000008); this store never updates or deletes either table.
type PostgresStore struct{ pool *pgxpool.Pool }

// NewPostgresStore builds a durable store over a pgx pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func optionalTimestamptz(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func (s *PostgresStore) UpsertSourceBinding(ctx context.Context, binding SourceBinding) (SourceBinding, error) {
	if s == nil || s.pool == nil {
		return SourceBinding{}, ErrUnavailable
	}
	row, err := db.New(s.pool).UpsertEvidenceSourceBinding(ctx, db.UpsertEvidenceSourceBindingParams{
		TenantRef:           binding.TenantRef,
		ID:                  binding.ID,
		DataClass:           binding.DataClass,
		SourceRef:           binding.SourceRef,
		SourceVersion:       binding.SourceVersion,
		AccessCapability:    binding.AccessCapability,
		SourceCapability:    binding.SourceCapability,
		ResourceType:        binding.ResourceType,
		ResourceID:          binding.ResourceID,
		CachedReadAllowed:   binding.CachedReadAllowed,
		RetentionTtlSeconds: int64(binding.RetentionTTL / time.Second),
	})
	if err != nil {
		return SourceBinding{}, err
	}
	return sourceBindingFromRow(row), nil
}

func (s *PostgresStore) GetSourceBinding(ctx context.Context, tenantRef, dataClass string) (SourceBinding, error) {
	if s == nil || s.pool == nil {
		return SourceBinding{}, ErrUnavailable
	}
	row, err := db.New(s.pool).GetEvidenceSourceBinding(ctx, db.GetEvidenceSourceBindingParams{TenantRef: tenantRef, DataClass: dataClass})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SourceBinding{}, ErrNotFound
		}
		return SourceBinding{}, err
	}
	return sourceBindingFromRow(row), nil
}

func (s *PostgresStore) BumpSourceVersion(ctx context.Context, tenantRef, dataClass string, _ time.Time) (SourceBinding, error) {
	if s == nil || s.pool == nil {
		return SourceBinding{}, ErrUnavailable
	}
	row, err := db.New(s.pool).BumpEvidenceSourceVersion(ctx, db.BumpEvidenceSourceVersionParams{TenantRef: tenantRef, DataClass: dataClass})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SourceBinding{}, ErrNotFound
		}
		return SourceBinding{}, err
	}
	return sourceBindingFromRow(row), nil
}

func (s *PostgresStore) MarkSourceDeleted(ctx context.Context, tenantRef, dataClass string, _ time.Time) (SourceBinding, error) {
	if s == nil || s.pool == nil {
		return SourceBinding{}, ErrUnavailable
	}
	row, err := db.New(s.pool).MarkEvidenceSourceDeleted(ctx, db.MarkEvidenceSourceDeletedParams{TenantRef: tenantRef, DataClass: dataClass})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SourceBinding{}, ErrNotFound
		}
		return SourceBinding{}, err
	}
	return sourceBindingFromRow(row), nil
}

func (s *PostgresStore) CreateHandle(ctx context.Context, handle Handle) (Handle, error) {
	if s == nil || s.pool == nil {
		return Handle{}, ErrUnavailable
	}
	lineage, err := json.Marshal(handle.Lineage)
	if err != nil {
		return Handle{}, err
	}
	row, err := db.New(s.pool).InsertEvidenceHandle(ctx, db.InsertEvidenceHandleParams{
		TenantRef:          handle.TenantRef,
		ID:                 handle.EvidenceRef,
		PrincipalRef:       handle.PrincipalRef,
		AgentClientRef:     handle.AgentClientRef,
		AgentReleaseRef:    handle.AgentReleaseRef,
		OrgVersion:         handle.OrgVersion,
		DataClass:          handle.DataClass,
		BindingID:          handle.BindingID,
		SourceVersion:      handle.SourceVersion,
		Purpose:            handle.Purpose,
		BusinessContextRef: handle.BusinessContextRef,
		ContentHash:        handle.ContentHash,
		ContentBytes:       handle.ContentBytes,
		RecordCount:        handle.RecordCount,
		RecordOffset:       handle.RecordOffset,
		PageLimit:          handle.PageLimit,
		ObjectKey:          handle.ObjectKey,
		KeyRef:             handle.KeyRef,
		AuthorizationRef:   handle.AuthorizationRef,
		Lineage:            lineage,
		CachedReadAllowed:  handle.CachedReadAllowed,
		StagedAt:           timestamptz(handle.StagedAt),
		ExpiresAt:          timestamptz(handle.ExpiresAt),
		RetentionExpiresAt: optionalTimestamptz(handle.RetentionExpiresAt),
	})
	if err != nil {
		return Handle{}, err
	}
	return handleFromRow(row)
}

func (s *PostgresStore) GetHandle(ctx context.Context, tenantRef, evidenceRef string) (Handle, error) {
	if s == nil || s.pool == nil {
		return Handle{}, ErrUnavailable
	}
	row, err := db.New(s.pool).GetEvidenceHandle(ctx, db.GetEvidenceHandleParams{TenantRef: tenantRef, ID: evidenceRef})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Handle{}, ErrNotFound
		}
		return Handle{}, err
	}
	return handleFromRow(row)
}

func (s *PostgresStore) AppendHandleEvent(ctx context.Context, event HandleEvent) (HandleEvent, error) {
	if s == nil || s.pool == nil {
		return HandleEvent{}, ErrUnavailable
	}
	row, err := db.New(s.pool).InsertEvidenceHandleEvent(ctx, db.InsertEvidenceHandleEventParams{
		TenantRef:   event.TenantRef,
		ID:          event.ID,
		EvidenceRef: event.EvidenceRef,
		Kind:        string(event.Kind),
		Reason:      event.Reason,
	})
	if err != nil {
		if isForeignKeyViolation(err) {
			return HandleEvent{}, ErrNotFound
		}
		return HandleEvent{}, err
	}
	return handleEventFromRow(row), nil
}

func (s *PostgresStore) ListHandleEvents(ctx context.Context, tenantRef, evidenceRef string) ([]HandleEvent, error) {
	if s == nil || s.pool == nil {
		return nil, ErrUnavailable
	}
	rows, err := db.New(s.pool).ListEvidenceHandleEvents(ctx, db.ListEvidenceHandleEventsParams{TenantRef: tenantRef, EvidenceRef: evidenceRef})
	if err != nil {
		return nil, err
	}
	out := make([]HandleEvent, 0, len(rows))
	for _, row := range rows {
		out = append(out, handleEventFromRow(row))
	}
	return out, nil
}

func (s *PostgresStore) ListRetentionExpired(ctx context.Context, tenantRef string, now time.Time, limit int) ([]Handle, error) {
	if s == nil || s.pool == nil {
		return nil, ErrUnavailable
	}
	if limit <= 0 || limit > 10_000 {
		limit = 10_000
	}
	rows, err := db.New(s.pool).ListEvidenceRetentionExpired(ctx, db.ListEvidenceRetentionExpiredParams{
		TenantRef:          tenantRef,
		RetentionExpiresAt: timestamptz(now),
		Limit:              int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Handle, 0, len(rows))
	for _, row := range rows {
		handle, err := handleFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, handle)
	}
	return out, nil
}

func sourceBindingFromRow(r db.EvidenceSourceBinding) SourceBinding {
	return SourceBinding{
		TenantRef:         r.TenantRef,
		ID:                r.ID,
		DataClass:         r.DataClass,
		SourceRef:         r.SourceRef,
		SourceVersion:     r.SourceVersion,
		AccessCapability:  r.AccessCapability,
		SourceCapability:  r.SourceCapability,
		ResourceType:      r.ResourceType,
		ResourceID:        r.ResourceID,
		CachedReadAllowed: r.CachedReadAllowed,
		RetentionTTL:      time.Duration(r.RetentionTtlSeconds) * time.Second,
		Deleted:           r.DeletedAt.Valid,
		CreatedAt:         r.CreatedAt.Time,
		UpdatedAt:         r.UpdatedAt.Time,
	}
}

func handleFromRow(r db.EvidenceHandle) (Handle, error) {
	var lineage []string
	if len(r.Lineage) > 0 {
		if err := json.Unmarshal(r.Lineage, &lineage); err != nil {
			return Handle{}, err
		}
	}
	handle := Handle{
		TenantRef:          r.TenantRef,
		EvidenceRef:        r.ID,
		PrincipalRef:       r.PrincipalRef,
		AgentClientRef:     r.AgentClientRef,
		AgentReleaseRef:    r.AgentReleaseRef,
		OrgVersion:         r.OrgVersion,
		DataClass:          r.DataClass,
		BindingID:          r.BindingID,
		SourceVersion:      r.SourceVersion,
		Purpose:            r.Purpose,
		BusinessContextRef: r.BusinessContextRef,
		ContentHash:        r.ContentHash,
		ContentBytes:       r.ContentBytes,
		RecordCount:        r.RecordCount,
		RecordOffset:       r.RecordOffset,
		PageLimit:          r.PageLimit,
		ObjectKey:          r.ObjectKey,
		KeyRef:             r.KeyRef,
		AuthorizationRef:   r.AuthorizationRef,
		Lineage:            lineage,
		CachedReadAllowed:  r.CachedReadAllowed,
		StagedAt:           r.StagedAt.Time,
		ExpiresAt:          r.ExpiresAt.Time,
		CreatedAt:          r.CreatedAt.Time,
	}
	if r.RetentionExpiresAt.Valid {
		handle.RetentionExpiresAt = r.RetentionExpiresAt.Time
	}
	return handle, nil
}

func handleEventFromRow(r db.EvidenceHandleEvent) HandleEvent {
	return HandleEvent{
		TenantRef:   r.TenantRef,
		ID:          r.ID,
		EvidenceRef: r.EvidenceRef,
		Kind:        HandleEventKind(r.Kind),
		Reason:      r.Reason,
		Seq:         r.Seq.Int64,
		CreatedAt:   r.CreatedAt.Time,
	}
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23503"
	}
	return false
}
