package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type grantWriteTx interface {
	AcquireEnterpriseOrgPublicationLock(context.Context, string) (any, error)
	GetActiveCaseTicketForGrant(context.Context, db.GetActiveCaseTicketForGrantParams) (db.CaseTicket, error)
	GetGrantResourceOwnerForGrant(context.Context, db.GetGrantResourceOwnerForGrantParams) (db.SensitiveResourceOwnership, error)
	GetLatestGrantOrgVersion(context.Context, string) (int64, error)
	AcquireEnterpriseAuditLock(context.Context, string) (any, error)
	GetLatestEnterpriseAuditHash(context.Context, string) (string, error)
	CreateStepGrant(context.Context, db.CreateStepGrantParams) (db.StepGrant, error)
	InsertStepGrantIssuance(context.Context, db.InsertStepGrantIssuanceParams) (db.StepGrantIssuance, error)
	GetStepGrantByTokenHash(context.Context, db.GetStepGrantByTokenHashParams) (db.GetStepGrantByTokenHashRow, error)
	AppendAuditEvent(context.Context, db.AppendAuditEventParams) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type grantWriteTxBeginner interface {
	BeginGrantWriteTx(context.Context, pgx.TxOptions) (grantWriteTx, error)
}
type grantReader interface {
	GetGrantResourceOwner(context.Context, db.GetGrantResourceOwnerParams) (db.SensitiveResourceOwnership, error)
	GetStepGrantByTokenHash(context.Context, db.GetStepGrantByTokenHashParams) (db.GetStepGrantByTokenHashRow, error)
}

type postgresGrantPool struct{ pool *pgxpool.Pool }

func (p *postgresGrantPool) BeginGrantWriteTx(ctx context.Context, options pgx.TxOptions) (grantWriteTx, error) {
	if p == nil || p.pool == nil {
		return nil, tickets.ErrGrantUnavailable
	}
	tx, err := p.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &postgresGrantTx{Tx: tx, queries: db.New(tx)}, nil
}
func (p *postgresGrantPool) GetGrantResourceOwner(ctx context.Context, params db.GetGrantResourceOwnerParams) (db.SensitiveResourceOwnership, error) {
	return db.New(p.pool).GetGrantResourceOwner(ctx, params)
}
func (p *postgresGrantPool) GetStepGrantByTokenHash(ctx context.Context, params db.GetStepGrantByTokenHashParams) (db.GetStepGrantByTokenHashRow, error) {
	return db.New(p.pool).GetStepGrantByTokenHash(ctx, params)
}

type postgresGrantTx struct {
	pgx.Tx
	queries *db.Queries
}

func (t *postgresGrantTx) AcquireEnterpriseOrgPublicationLock(ctx context.Context, id string) (any, error) {
	return t.queries.AcquireEnterpriseOrgPublicationLock(ctx, id)
}
func (t *postgresGrantTx) GetActiveCaseTicketForGrant(ctx context.Context, p db.GetActiveCaseTicketForGrantParams) (db.CaseTicket, error) {
	return t.queries.GetActiveCaseTicketForGrant(ctx, p)
}
func (t *postgresGrantTx) GetGrantResourceOwnerForGrant(ctx context.Context, p db.GetGrantResourceOwnerForGrantParams) (db.SensitiveResourceOwnership, error) {
	return t.queries.GetGrantResourceOwnerForGrant(ctx, p)
}
func (t *postgresGrantTx) GetLatestGrantOrgVersion(ctx context.Context, id string) (int64, error) {
	return t.queries.GetLatestGrantOrgVersion(ctx, id)
}
func (t *postgresGrantTx) AcquireEnterpriseAuditLock(ctx context.Context, id string) (any, error) {
	return t.queries.AcquireEnterpriseAuditLock(ctx, id)
}
func (t *postgresGrantTx) GetLatestEnterpriseAuditHash(ctx context.Context, id string) (string, error) {
	return t.queries.GetLatestEnterpriseAuditHash(ctx, id)
}
func (t *postgresGrantTx) CreateStepGrant(ctx context.Context, p db.CreateStepGrantParams) (db.StepGrant, error) {
	return t.queries.CreateStepGrant(ctx, p)
}
func (t *postgresGrantTx) InsertStepGrantIssuance(ctx context.Context, p db.InsertStepGrantIssuanceParams) (db.StepGrantIssuance, error) {
	return t.queries.InsertStepGrantIssuance(ctx, p)
}
func (t *postgresGrantTx) GetStepGrantByTokenHash(ctx context.Context, p db.GetStepGrantByTokenHashParams) (db.GetStepGrantByTokenHashRow, error) {
	return t.queries.GetStepGrantByTokenHash(ctx, p)
}
func (t *postgresGrantTx) AppendAuditEvent(ctx context.Context, p db.AppendAuditEventParams) error {
	_, err := t.queries.AppendAuditEvent(ctx, p)
	return err
}

type PostgresGrantStore struct {
	writer grantWriteTxBeginner
	reader grantReader
}

func NewPostgresGrantStore(pool *pgxpool.Pool) *PostgresGrantStore {
	wrapped := &postgresGrantPool{pool: pool}
	return &PostgresGrantStore{writer: wrapped, reader: wrapped}
}
func newPostgresGrantStoreWithPool(writer grantWriteTxBeginner) *PostgresGrantStore {
	return &PostgresGrantStore{writer: writer}
}

func (s *PostgresGrantStore) CreateCaseTicket(tickets.CaseTicket) (tickets.CaseTicket, error) {
	return tickets.CaseTicket{}, tickets.ErrGrantUnavailable
}
func (s *PostgresGrantStore) CreateStepGrant(tickets.StepGrant) (tickets.StepGrant, error) {
	return tickets.StepGrant{}, tickets.ErrGrantUnavailable
}

func (s *PostgresGrantStore) ResolveGrantResourceOwner(ctx context.Context, enterpriseID, resourceType, resourceID string) (GrantResourceOwner, error) {
	if s == nil || s.reader == nil {
		return GrantResourceOwner{}, tickets.ErrGrantUnavailable
	}
	row, err := s.reader.GetGrantResourceOwner(ctx, db.GetGrantResourceOwnerParams{EnterpriseID: enterpriseID, ResourceType: resourceType, ResourceID: resourceID})
	if err != nil {
		return GrantResourceOwner{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	return GrantResourceOwner{EnterpriseID: row.EnterpriseID, ResourceType: row.ResourceType, ResourceID: row.ResourceID, OrgUnitID: row.OrgUnitID, OrgVersion: row.OrgVersion}, nil
}

// LookupStepGrantIdentity resolves the verified identity bound to a Step Grant
// credential (tenant, actor, Case Ticket lineage and grant ref) from its
// opaque token hash. It is the persistence half of the trust layer's Step
// Grant context source; the trust resolver enforces the grant's expiry
// fail-closed. Errors translate onto the verifier sentinel contract.
func (s *PostgresGrantStore) LookupStepGrantIdentity(ctx context.Context, enterpriseID, tokenHash string) (trust.GrantIdentity, error) {
	if s == nil || s.reader == nil || !canonicalAuthorizationValue(enterpriseID) || len(tokenHash) != 64 {
		return trust.GrantIdentity{}, trust.ErrSourceUnavailable
	}
	row, err := s.reader.GetStepGrantByTokenHash(ctx, db.GetStepGrantByTokenHashParams{EnterpriseID: enterpriseID, TokenHash: tokenHash})
	if errors.Is(err, pgx.ErrNoRows) {
		return trust.GrantIdentity{}, trust.ErrCredentialRejected
	}
	if err != nil {
		return trust.GrantIdentity{}, errors.Join(trust.ErrSourceUnavailable, err)
	}
	if row.EnterpriseID != enterpriseID || row.TokenHash != tokenHash || !canonicalAuthorizationValue(row.ID) || !canonicalAuthorizationValue(row.ActorUserID) || !canonicalAuthorizationValue(row.CaseTicketID) || !row.ExpiresAt.Valid {
		return trust.GrantIdentity{}, trust.ErrCredentialRejected
	}
	return trust.GrantIdentity{TenantRef: row.EnterpriseID, PrincipalRef: row.ActorUserID, TicketRef: row.CaseTicketID, GrantRef: row.ID, ExpiresAt: row.ExpiresAt.Time}, nil
}

// stepGrantTrustVerifier adapts the grant store onto the trust layer's Step
// Grant credential source, hashing the presented opaque token before lookup.
type stepGrantTrustVerifier struct {
	enterpriseID string
	store        *PostgresGrantStore
}

// NewPostgresStepGrantVerifier wires the fourth advertised trusted-context
// source (Step Grant) in production so `Authorization: StepGrant <token>`
// resolves a verified principal context.
func NewPostgresStepGrantVerifier(enterpriseID string, store *PostgresGrantStore) trust.StepGrantVerifier {
	return stepGrantTrustVerifier{enterpriseID: enterpriseID, store: store}
}

func (v stepGrantTrustVerifier) VerifyStepGrant(ctx context.Context, token string) (trust.GrantIdentity, error) {
	if v.store == nil || !canonicalAuthorizationValue(v.enterpriseID) {
		return trust.GrantIdentity{}, trust.ErrSourceUnavailable
	}
	return v.store.LookupStepGrantIdentity(ctx, v.enterpriseID, tickets.HashStepGrantToken(token))
}

func (s *PostgresGrantStore) CreateStepGrantAndAudit(ctx context.Context, grant tickets.StepGrant, auditID string) (result tickets.StepGrant, resultErr error) {
	if s == nil || s.writer == nil || len(grant.TokenHash) != 64 || grant.Token != "" || auditID == "" {
		return tickets.StepGrant{}, tickets.ErrGrantUnavailable
	}
	tx, err := s.writer.BeginGrantWriteTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return tickets.StepGrant{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanup); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err = tx.AcquireEnterpriseOrgPublicationLock(ctx, grant.EnterpriseID); err != nil {
		return tickets.StepGrant{}, err
	}
	ticket, err := tx.GetActiveCaseTicketForGrant(ctx, db.GetActiveCaseTicketForGrantParams{EnterpriseID: grant.EnterpriseID, ID: grant.CaseTicketID, ActorUserID: grant.ActorUserID, ExpiresAt: pgtype.Timestamptz{Time: grant.CreatedAt, Valid: true}})
	if err != nil {
		return tickets.StepGrant{}, err
	}
	if !ticket.ExpiresAt.Valid || !ticket.ExpiresAt.Time.After(grant.CreatedAt) {
		return tickets.StepGrant{}, tickets.ErrGrantDenied
	}
	if ticket.ExpiresAt.Time.Before(grant.ExpiresAt) {
		grant.ExpiresAt = ticket.ExpiresAt.Time
	}
	owner, err := tx.GetGrantResourceOwnerForGrant(ctx, db.GetGrantResourceOwnerForGrantParams{EnterpriseID: grant.EnterpriseID, ResourceType: grant.ResourceType, ResourceID: grant.ResourceID})
	if err != nil {
		return tickets.StepGrant{}, err
	}
	latest, err := tx.GetLatestGrantOrgVersion(ctx, grant.EnterpriseID)
	if err != nil || latest != grant.OrgVersion || owner.EnterpriseID != grant.EnterpriseID || owner.OrgVersion != grant.OrgVersion || owner.OrgUnitID != grant.OrgUnitID {
		return tickets.StepGrant{}, tickets.ErrGrantDenied
	}
	if _, err = tx.AcquireEnterpriseAuditLock(ctx, grant.EnterpriseID); err != nil {
		return tickets.StepGrant{}, err
	}
	previous, err := tx.GetLatestEnterpriseAuditHash(ctx, grant.EnterpriseID)
	if err != nil {
		return tickets.StepGrant{}, err
	}
	scopes, err := json.Marshal(grant.Scopes)
	if err != nil {
		return tickets.StepGrant{}, err
	}
	if _, err = tx.CreateStepGrant(ctx, db.CreateStepGrantParams{ID: grant.ID, EnterpriseID: grant.EnterpriseID, CaseTicketID: grant.CaseTicketID, ResourceType: grant.ResourceType, ResourceID: grant.ResourceID, Action: grant.Action, Scopes: scopes, ExpiresAt: pgtype.Timestamptz{Time: grant.ExpiresAt, Valid: true}, CreatedAt: pgtype.Timestamptz{Time: grant.CreatedAt, Valid: true}}); err != nil {
		return tickets.StepGrant{}, err
	}
	inputHash, outputHash := grantEvidenceHashes(grant)
	event := audit.NewEvent(audit.EventInput{ID: auditID, EnterpriseID: grant.EnterpriseID, CaseTicketID: grant.CaseTicketID, StepGrantID: grant.ID, ActorUserID: grant.ActorUserID, ResourceType: grant.ResourceType, ResourceID: grant.ResourceID, Action: "step_grant.issue", Decision: "allow", InputHash: inputHash, OutputHash: outputHash, EvidencePointer: grant.ID}, previous)
	if _, err = tx.InsertStepGrantIssuance(ctx, db.InsertStepGrantIssuanceParams{EnterpriseID: grant.EnterpriseID, StepGrantID: grant.ID, TokenHash: grant.TokenHash, ActorUserID: grant.ActorUserID, OrgVersion: grant.OrgVersion, OrgUnitID: grant.OrgUnitID, AuditEventID: auditID, ExpectedAuditInputHash: inputHash, ExpectedAuditOutputHash: outputHash, CreatedAt: pgtype.Timestamptz{Time: grant.CreatedAt, Valid: true}}); err != nil {
		return tickets.StepGrant{}, err
	}
	if err = tx.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: event.ID, EnterpriseID: event.EnterpriseID, CaseTicketID: textValue(event.CaseTicketID), StepGrantID: textValue(event.StepGrantID), ActorUserID: textValue(event.ActorUserID), ResourceType: textValue(event.ResourceType), ResourceID: textValue(event.ResourceID), Action: event.Action, Decision: event.Decision, InputHash: textValue(event.InputHash), OutputHash: textValue(event.OutputHash), EvidencePointer: textValue(event.EvidencePointer), PrevHash: textValue(event.PrevHash), EventHash: event.EventHash}); err != nil {
		return tickets.StepGrant{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return tickets.StepGrant{}, err
	}
	return grant, nil
}

func grantEvidenceHashes(grant tickets.StepGrant) (string, string) {
	raw, _ := json.Marshal(struct {
		EnterpriseID, ActorUserID, CaseTicketID, OrgUnitID, ResourceType, ResourceID, Action string
		OrgVersion                                                                           int64
		Scopes                                                                               []string
		ExpiresAt                                                                            int64
	}{grant.EnterpriseID, grant.ActorUserID, grant.CaseTicketID, grant.OrgUnitID, grant.ResourceType, grant.ResourceID, grant.Action, grant.OrgVersion, grant.Scopes, grant.ExpiresAt.UnixNano()})
	in := sha256.Sum256(raw)
	out := sha256.Sum256([]byte(grant.TokenHash))
	return hex.EncodeToString(in[:]), hex.EncodeToString(out[:])
}

func (s *PostgresGrantStore) VerifyStepGrantAndAudit(ctx context.Context, actor tickets.Actor, input tickets.VerifyStepGrantInput, tokenHash, auditID string, now time.Time) (result tickets.StepGrant, resultErr error) {
	if s == nil || s.writer == nil || len(tokenHash) != 64 || auditID == "" {
		return tickets.StepGrant{}, tickets.ErrGrantUnavailable
	}
	tx, err := s.writer.BeginGrantWriteTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return tickets.StepGrant{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanup); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	row, err := tx.GetStepGrantByTokenHash(ctx, db.GetStepGrantByTokenHashParams{EnterpriseID: actor.EnterpriseID, TokenHash: tokenHash})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tickets.StepGrant{}, tickets.ErrGrantDenied
		}
		return tickets.StepGrant{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	var scopes []string
	if json.Unmarshal(row.Scopes, &scopes) != nil {
		return tickets.StepGrant{}, tickets.ErrGrantUnavailable
	}
	grant := tickets.StepGrant{ID: row.ID, TokenHash: row.TokenHash, EnterpriseID: row.EnterpriseID, ActorUserID: row.ActorUserID, CaseTicketID: row.CaseTicketID, OrgUnitID: row.OrgUnitID, OrgVersion: row.OrgVersion, ResourceType: row.ResourceType, ResourceID: row.ResourceID, Action: row.Action, Scopes: scopes, ExpiresAt: row.ExpiresAt.Time, CreatedAt: row.CreatedAt.Time}
	if grant.EnterpriseID != actor.EnterpriseID || grant.ActorUserID != actor.UserID || grant.ResourceType != input.ResourceType || grant.ResourceID != input.ResourceID || grant.Action != input.Action || len(grant.Scopes) != 1 || grant.Scopes[0] != input.Scope || !now.Before(grant.ExpiresAt) {
		return tickets.StepGrant{}, tickets.ErrGrantDenied
	}
	if _, err = tx.AcquireEnterpriseAuditLock(ctx, grant.EnterpriseID); err != nil {
		return tickets.StepGrant{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	previous, err := tx.GetLatestEnterpriseAuditHash(ctx, grant.EnterpriseID)
	if err != nil {
		return tickets.StepGrant{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	inputHash, outputHash := grantVerificationEvidenceHashes(actor, input, grant, now)
	event := audit.NewEvent(audit.EventInput{ID: auditID, EnterpriseID: grant.EnterpriseID, CaseTicketID: grant.CaseTicketID, StepGrantID: grant.ID, ActorUserID: grant.ActorUserID, ResourceType: grant.ResourceType, ResourceID: grant.ResourceID, Action: "step_grant.verify", Decision: "allow", InputHash: inputHash, OutputHash: outputHash, EvidencePointer: grant.ID}, previous)
	if err = tx.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: event.ID, EnterpriseID: event.EnterpriseID, CaseTicketID: textValue(event.CaseTicketID), StepGrantID: textValue(event.StepGrantID), ActorUserID: textValue(event.ActorUserID), ResourceType: textValue(event.ResourceType), ResourceID: textValue(event.ResourceID), Action: event.Action, Decision: event.Decision, InputHash: textValue(event.InputHash), OutputHash: textValue(event.OutputHash), EvidencePointer: textValue(event.EvidencePointer), PrevHash: textValue(event.PrevHash), EventHash: event.EventHash}); err != nil {
		return tickets.StepGrant{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return tickets.StepGrant{}, errors.Join(tickets.ErrGrantUnavailable, err)
	}
	return grant, nil
}

func grantVerificationEvidenceHashes(actor tickets.Actor, input tickets.VerifyStepGrantInput, grant tickets.StepGrant, verifiedAt time.Time) (string, string) {
	raw, _ := json.Marshal(struct {
		EnterpriseID, ActorUserID, CaseTicketID, StepGrantID, ResourceType, ResourceID, Action, Scope string
		VerifiedAt                                                                                    int64
	}{actor.EnterpriseID, actor.UserID, grant.CaseTicketID, grant.ID, input.ResourceType, input.ResourceID, input.Action, input.Scope, verifiedAt.UnixNano()})
	in := sha256.Sum256(raw)
	out := sha256.Sum256([]byte(grant.TokenHash + ":allow"))
	return hex.EncodeToString(in[:]), hex.EncodeToString(out[:])
}
