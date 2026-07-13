package agenttrust

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the durable trust registry store. It upholds the same
// invariants as MemoryStore — immutable revisions, an append-only hash-chained
// status log, atomic revision assignment and supersede — enforced by database
// triggers and serialized inside transactions.
type PostgresStore struct{ pool *pgxpool.Pool }

// NewPostgresStore builds a durable store over a pgx pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func timestamptz(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

func (s *PostgresStore) CreateAgentClient(ctx context.Context, client AgentClient) (AgentClient, error) {
	if s == nil || s.pool == nil {
		return AgentClient{}, ErrRegistryUnavailable
	}
	row, err := db.New(s.pool).UpsertAgentClient(ctx, db.UpsertAgentClientParams{
		TenantRef:            client.TenantRef,
		ID:                   client.ID,
		Publisher:            client.Publisher,
		Product:              client.Product,
		Origin:               client.Origin,
		EnterpriseRegistered: client.EnterpriseRegistered,
	})
	if err != nil {
		return AgentClient{}, err
	}
	return agentClientFromRow(row), nil
}

func (s *PostgresStore) GetAgentClient(ctx context.Context, tenantRef, publisher, product string) (AgentClient, error) {
	if s == nil || s.pool == nil {
		return AgentClient{}, ErrRegistryUnavailable
	}
	row, err := db.New(s.pool).GetAgentClient(ctx, db.GetAgentClientParams{TenantRef: tenantRef, Publisher: publisher, Product: product})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AgentClient{}, ErrNotFound
		}
		return AgentClient{}, err
	}
	return agentClientFromRow(row), nil
}

func (s *PostgresStore) ListCertifications(ctx context.Context, tenantRef, publisher, product string) ([]Certification, error) {
	if s == nil || s.pool == nil {
		return nil, ErrRegistryUnavailable
	}
	rows, err := db.New(s.pool).ListAgentCertifications(ctx, db.ListAgentCertificationsParams{TenantRef: tenantRef, Publisher: publisher, Product: product})
	if err != nil {
		return nil, err
	}
	out := make([]Certification, 0, len(rows))
	for _, row := range rows {
		cert, err := certificationFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	return out, nil
}

func (s *PostgresStore) LatestStatus(ctx context.Context, tenantRef, certificationID string) (StatusChange, error) {
	if s == nil || s.pool == nil {
		return StatusChange{}, ErrRegistryUnavailable
	}
	row, err := db.New(s.pool).GetLatestCertificationStatus(ctx, db.GetLatestCertificationStatusParams{TenantRef: tenantRef, CertificationID: certificationID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StatusChange{}, ErrNotFound
		}
		return StatusChange{}, err
	}
	return statusChangeFromRow(row), nil
}

func (s *PostgresStore) CreateCertification(ctx context.Context, cert Certification, statusID func() string, now time.Time) (Certification, error) {
	if s == nil || s.pool == nil {
		return Certification{}, ErrRegistryUnavailable
	}
	ceiling, err := json.Marshal([]string(cert.Binding.CapabilityCeiling))
	if err != nil {
		return Certification{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Certification{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(tx)

	// Serialize concurrent certifications of the same product so revision
	// assignment and supersede stay linearizable.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
		cert.TenantRef+"\x00"+cert.Binding.Publisher+"\x00"+cert.Binding.Product); err != nil {
		return Certification{}, err
	}
	maxRevision, err := q.GetMaxCertificationRevision(ctx, db.GetMaxCertificationRevisionParams{TenantRef: cert.TenantRef, Publisher: cert.Binding.Publisher, Product: cert.Binding.Product})
	if err != nil {
		return Certification{}, err
	}
	cert.Revision = maxRevision + 1

	inserted, err := q.InsertAgentCertification(ctx, db.InsertAgentCertificationParams{
		TenantRef:                 cert.TenantRef,
		ID:                        cert.ID,
		AgentClientID:             cert.AgentClientID,
		Revision:                  cert.Revision,
		TrustClass:                string(cert.Binding.TrustClass),
		Publisher:                 cert.Binding.Publisher,
		Product:                   cert.Binding.Product,
		Origin:                    cert.Origin,
		VersionMin:                cert.Binding.VersionRange.MinInclusive,
		VersionMax:                cert.Binding.VersionRange.MaxExclusive,
		SigningKeyID:              cert.Binding.SigningKey.KeyID,
		SigningKeyAlgorithm:       cert.Binding.SigningKey.Algorithm,
		SigningKeyPublicKey:       cert.Binding.SigningKey.PublicKey,
		ReleaseManifestDigest:     cert.Binding.ReleaseManifestDigest,
		CapabilityCeiling:         ceiling,
		SignedBuildManifest:       cert.SignedBuildManifest,
		EnterpriseRegistered:      cert.EnterpriseRegistered,
		CertifiedDecisionProvider: cert.CertifiedDecisionProvider,
		IssuedAt:                  timestamptz(cert.IssuedAt),
		ExpiresAt:                 timestamptz(cert.ExpiresAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Certification{}, ErrCertificationRejected
		}
		return Certification{}, err
	}

	// Initial active status begins a fresh hash chain.
	initialHash := hashStatusChange(cert.TenantRef, cert.ID, StatusActive, "certified", "")
	if _, err := q.InsertCertificationStatusChange(ctx, db.InsertCertificationStatusChangeParams{
		TenantRef: cert.TenantRef, ID: statusID(), CertificationID: cert.ID,
		Status: string(StatusActive), Reason: "certified", PrevHash: "", EventHash: initialHash,
	}); err != nil {
		return Certification{}, err
	}

	// Supersede prior active revisions of the same product (append-only).
	priors, err := q.ListAgentCertifications(ctx, db.ListAgentCertificationsParams{TenantRef: cert.TenantRef, Publisher: cert.Binding.Publisher, Product: cert.Binding.Product})
	if err != nil {
		return Certification{}, err
	}
	for _, prior := range priors {
		if prior.ID == cert.ID {
			continue
		}
		// Lock the prior cert row FOR UPDATE BEFORE reading its latest status, so
		// supersede and a concurrent Revoke serialize on the SAME row lock and can
		// never both chain onto a stale tail (fork prevention, Important 1c).
		if _, err := q.LockAgentCertification(ctx, db.LockAgentCertificationParams{TenantRef: cert.TenantRef, ID: prior.ID}); err != nil {
			return Certification{}, err
		}
		latest, err := q.GetLatestCertificationStatus(ctx, db.GetLatestCertificationStatusParams{TenantRef: cert.TenantRef, CertificationID: prior.ID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return Certification{}, err
		}
		if CertificationStatus(latest.Status) != StatusActive {
			continue
		}
		reason := "superseded by " + cert.ID
		if _, err := q.InsertCertificationStatusChange(ctx, db.InsertCertificationStatusChangeParams{
			TenantRef: cert.TenantRef, ID: statusID(), CertificationID: prior.ID,
			Status: string(StatusSuperseded), Reason: reason, PrevHash: latest.EventHash,
			EventHash: hashStatusChange(cert.TenantRef, prior.ID, StatusSuperseded, reason, latest.EventHash),
		}); err != nil {
			return Certification{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Certification{}, err
	}
	return certificationFromRow(inserted)
}

func (s *PostgresStore) AppendStatus(ctx context.Context, tenantRef, certificationID string, status CertificationStatus, reason, statusID string, now time.Time) (StatusChange, error) {
	if s == nil || s.pool == nil {
		return StatusChange{}, ErrRegistryUnavailable
	}
	if !status.valid() {
		return StatusChange{}, ErrInvalidInput
	}
	_ = now // created_at is the database default now(); the parameter keeps the port uniform with MemoryStore.
	// The FOR UPDATE lock below already serializes writers on the cert row; the
	// UNIQUE(tenant,cert,prev_hash) constraint is the structural backstop. If a
	// writer still loses the chain race it re-reads the tail and retries.
	for attempt := 0; attempt < 8; attempt++ {
		change, retry, err := s.appendStatusOnce(ctx, tenantRef, certificationID, status, reason, statusID)
		if retry {
			continue
		}
		return change, err
	}
	return StatusChange{}, ErrRegistryUnavailable
}

// appendStatusOnce runs one chained-append transaction. retry is true when the
// append lost the per-certification chain race (UNIQUE prev_hash violation) and
// should be re-attempted against the fresh tail.
func (s *PostgresStore) appendStatusOnce(ctx context.Context, tenantRef, certificationID string, status CertificationStatus, reason, statusID string) (change StatusChange, retry bool, err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return StatusChange{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(tx)

	// Lock the immutable certification row (SELECT FOR UPDATE does not fire the
	// immutability trigger) so concurrent status appends — revoke and supersede
	// alike — chain linearly.
	if _, err := q.LockAgentCertification(ctx, db.LockAgentCertificationParams{TenantRef: tenantRef, ID: certificationID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StatusChange{}, false, ErrNotFound
		}
		return StatusChange{}, false, err
	}
	prev := ""
	latest, err := q.GetLatestCertificationStatus(ctx, db.GetLatestCertificationStatusParams{TenantRef: tenantRef, CertificationID: certificationID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return StatusChange{}, false, err
	}
	if err == nil {
		prev = latest.EventHash
	}
	row, err := q.InsertCertificationStatusChange(ctx, db.InsertCertificationStatusChangeParams{
		TenantRef: tenantRef, ID: statusID, CertificationID: certificationID,
		Status: string(status), Reason: reason, PrevHash: prev,
		EventHash: hashStatusChange(tenantRef, certificationID, status, reason, prev),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return StatusChange{}, true, nil
		}
		return StatusChange{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return StatusChange{}, false, err
	}
	return statusChangeFromRow(row), false, nil
}

func agentClientFromRow(r db.AgentClient) AgentClient {
	return AgentClient{
		ID:                   r.ID,
		TenantRef:            r.TenantRef,
		Publisher:            r.Publisher,
		Product:              r.Product,
		Origin:               r.Origin,
		EnterpriseRegistered: r.EnterpriseRegistered,
		CreatedAt:            r.CreatedAt.Time,
	}
}

func certificationFromRow(r db.AgentCertification) (Certification, error) {
	var ceiling []string
	if len(r.CapabilityCeiling) > 0 {
		if err := json.Unmarshal(r.CapabilityCeiling, &ceiling); err != nil {
			return Certification{}, err
		}
	}
	return Certification{
		ID:            r.ID,
		TenantRef:     r.TenantRef,
		AgentClientID: r.AgentClientID,
		Origin:        r.Origin,
		Revision:      r.Revision,
		Binding: runtime.CertificationBinding{
			Publisher:             r.Publisher,
			Product:               r.Product,
			VersionRange:          runtime.VersionRange{MinInclusive: r.VersionMin, MaxExclusive: r.VersionMax},
			SigningKey:            runtime.SigningKey{KeyID: r.SigningKeyID, Algorithm: r.SigningKeyAlgorithm, PublicKey: r.SigningKeyPublicKey},
			ReleaseManifestDigest: r.ReleaseManifestDigest,
			TrustClass:            runtime.TrustClass(r.TrustClass),
			CapabilityCeiling:     runtime.CapabilityCeiling(ceiling),
		},
		SignedBuildManifest:       r.SignedBuildManifest,
		EnterpriseRegistered:      r.EnterpriseRegistered,
		CertifiedDecisionProvider: r.CertifiedDecisionProvider,
		IssuedAt:                  r.IssuedAt.Time,
		ExpiresAt:                 r.ExpiresAt.Time,
		CreatedAt:                 r.CreatedAt.Time,
	}, nil
}

func statusChangeFromRow(r db.AgentCertificationStatusChange) StatusChange {
	return StatusChange{
		ID:              r.ID,
		TenantRef:       r.TenantRef,
		CertificationID: r.CertificationID,
		Status:          CertificationStatus(r.Status),
		Reason:          r.Reason,
		PrevHash:        r.PrevHash,
		EventHash:       r.EventHash,
		Seq:             r.Seq.Int64,
		CreatedAt:       r.CreatedAt.Time,
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
