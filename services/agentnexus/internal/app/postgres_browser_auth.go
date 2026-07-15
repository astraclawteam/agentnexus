package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sort"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresBrowserDirectory struct {
	identityDB db.DBTX
	profileDB  browserProfileTxBeginner
}

type browserProfileTx interface {
	GetBrowserProfile(context.Context, db.GetBrowserProfileParams) (db.GetBrowserProfileRow, error)
	ListBrowserProfileOrgUnits(context.Context, db.ListBrowserProfileOrgUnitsParams) ([]db.OrgPolicySnapshotMembership, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type browserProfileTxBeginner interface {
	BeginBrowserProfileTx(context.Context, pgx.TxOptions) (browserProfileTx, error)
}

type postgresBrowserProfileDB struct{ pool *pgxpool.Pool }

func (d *postgresBrowserProfileDB) BeginBrowserProfileTx(ctx context.Context, options pgx.TxOptions) (browserProfileTx, error) {
	tx, err := d.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &postgresBrowserProfileTx{Tx: tx, queries: db.New(tx)}, nil
}

type postgresBrowserProfileTx struct {
	pgx.Tx
	queries *db.Queries
}

func (t *postgresBrowserProfileTx) GetBrowserProfile(ctx context.Context, params db.GetBrowserProfileParams) (db.GetBrowserProfileRow, error) {
	return t.queries.GetBrowserProfile(ctx, params)
}

func (t *postgresBrowserProfileTx) ListBrowserProfileOrgUnits(ctx context.Context, params db.ListBrowserProfileOrgUnitsParams) ([]db.OrgPolicySnapshotMembership, error) {
	return t.queries.ListBrowserProfileOrgUnits(ctx, params)
}

func NewPostgresBrowserDirectory(pool *pgxpool.Pool) *PostgresBrowserDirectory {
	directory := &PostgresBrowserDirectory{}
	if pool != nil {
		directory.identityDB = pool
		directory.profileDB = &postgresBrowserProfileDB{pool: pool}
	}
	return directory
}

func (d *PostgresBrowserDirectory) ResolveExternalIdentity(ctx context.Context, enterpriseID, issuer, subject string) (string, string, error) {
	if d == nil || d.identityDB == nil || enterpriseID == "" || issuer == "" || subject == "" {
		return "", "", ErrIdentityDirectoryUnavailable
	}
	record, err := db.New(d.identityDB).ResolveExternalIdentity(ctx, db.ResolveExternalIdentityParams{EnterpriseID: enterpriseID, Provider: issuer, ExternalSubject: subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrUnknownExternalIdentity
	}
	if err != nil {
		return "", "", errors.Join(ErrIdentityDirectoryUnavailable, err)
	}
	return record.EnterpriseID, record.EnterpriseUserID, nil
}

func (d *PostgresBrowserDirectory) ResolveBrowserProfile(ctx context.Context, enterpriseID, userID string) (profile BrowserProfile, resultErr error) {
	if d == nil || d.profileDB == nil || enterpriseID == "" || userID == "" {
		return BrowserProfile{}, errors.New("profile directory unavailable")
	}
	tx, err := d.profileDB.BeginBrowserProfileTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return BrowserProfile{}, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if cleanupErr := tx.Rollback(cleanupCtx); cleanupErr != nil && !errors.Is(cleanupErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	record, err := tx.GetBrowserProfile(ctx, db.GetBrowserProfileParams{EnterpriseID: enterpriseID, ID: userID})
	if err != nil {
		return BrowserProfile{}, err
	}
	if record.OrgVersion < 1 {
		return BrowserProfile{}, errors.New("invalid profile organization version")
	}
	rows, err := tx.ListBrowserProfileOrgUnits(ctx, db.ListBrowserProfileOrgUnitsParams{EnterpriseID: enterpriseID, EnterpriseUserID: userID, VersionNumber: record.OrgVersion})
	if err != nil {
		return BrowserProfile{}, err
	}
	if err := ctx.Err(); err != nil {
		return BrowserProfile{}, err
	}
	if len(rows) > policy.MaxSealedMemberships {
		return BrowserProfile{}, errors.New("profile membership limit exceeded")
	}
	unitSet := make(map[string]struct{}, len(rows))
	permissionSet := make(map[string]struct{}, len(rows))
	advancedModeAllowed := false
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return BrowserProfile{}, err
		}
		permission, known := policy.MembershipRolePermission(row.Role)
		if row.EnterpriseID != enterpriseID || row.VersionNumber != record.OrgVersion || row.EnterpriseUserID != userID || !canonicalAuthorizationValue(row.OrgUnitID) || !known {
			return BrowserProfile{}, errors.New("invalid profile membership row")
		}
		unitSet[row.OrgUnitID] = struct{}{}
		if permission != "" {
			permissionSet[string(permission)] = struct{}{}
		}
		if permission == policy.PermissionWorkflowAdvanced || permission == policy.PermissionServiceMode {
			advancedModeAllowed = true
		}
	}
	units := make([]string, 0, len(unitSet))
	for unitID := range unitSet {
		units = append(units, unitID)
	}
	sort.Strings(units)
	permissions := make([]string, 0, len(permissionSet))
	for permission := range permissionSet {
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	if err := tx.Commit(ctx); err != nil {
		return BrowserProfile{}, err
	}
	return BrowserProfile{EnterpriseID: enterpriseID, EnterpriseUserID: userID, DisplayName: record.DisplayName, OrgVersion: record.OrgVersion, OrgUnitIDs: units, Permissions: permissions, AdvancedModeAllowed: advancedModeAllowed}, nil
}

type PostgresBrowserAuditSink struct {
	pool       *pgxpool.Pool
	evidenceDB auditEvidenceTxBeginner
	random     io.Reader
	// signer, when wired, signs the high-risk action-transition sub-chain (GA
	// Task 0G). Nil ⇒ that path fails CLOSED (no unsigned high-risk audit).
	signer audit.AuditSigner
	logger *slog.Logger
	now    func() time.Time
}

type auditEvidenceTx interface {
	AcquireEnterpriseAuditLock(context.Context, string) (interface{}, error)
	GetLatestEnterpriseAuditHash(context.Context, string) (string, error)
	GetLatestSignedEnterpriseAuditHash(context.Context, string) (string, error)
	AllocateNextTenantSeq(context.Context, string) (int64, error)
	AppendAuditEvent(context.Context, db.AppendAuditEventParams) (db.AuditEvent, error)
	AppendSignedAuditEvent(context.Context, db.AppendSignedAuditEventParams) (db.AuditEvent, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type auditEvidenceTxBeginner interface {
	BeginAuditEvidenceTx(context.Context, pgx.TxOptions) (auditEvidenceTx, error)
}
type postgresAuditEvidenceDB struct{ pool *pgxpool.Pool }

func (d postgresAuditEvidenceDB) BeginAuditEvidenceTx(ctx context.Context, options pgx.TxOptions) (auditEvidenceTx, error) {
	tx, err := d.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &postgresAuditEvidenceTx{Tx: tx, Queries: db.New(tx)}, nil
}

type postgresAuditEvidenceTx struct {
	pgx.Tx
	*db.Queries
}

// AuditSinkOption configures the durable audit sink.
type AuditSinkOption func(*PostgresBrowserAuditSink)

// WithAuditSigner wires the GA Task 0G audit signer. When set, the high-risk
// action-transition sub-chain is signed and sequenced; when absent, that path
// fails closed (a nil signer never yields an unsigned high-risk audit record).
func WithAuditSigner(signer audit.AuditSigner) AuditSinkOption {
	return func(s *PostgresBrowserAuditSink) { s.signer = signer }
}

// WithAuditLogger wires the diagnostics logger for the signer-error seam.
func WithAuditLogger(logger *slog.Logger) AuditSinkOption {
	return func(s *PostgresBrowserAuditSink) {
		if logger != nil {
			s.logger = logger
		}
	}
}

func NewPostgresBrowserAuditSink(pool *pgxpool.Pool, opts ...AuditSinkOption) *PostgresBrowserAuditSink {
	sink := &PostgresBrowserAuditSink{pool: pool, evidenceDB: postgresAuditEvidenceDB{pool: pool}, random: rand.Reader, now: time.Now}
	for _, opt := range opts {
		opt(sink)
	}
	return sink
}

func newPostgresAuditEvidenceSinkWithDB(database auditEvidenceTxBeginner, random io.Reader, opts ...AuditSinkOption) *PostgresBrowserAuditSink {
	sink := &PostgresBrowserAuditSink{evidenceDB: database, random: random, now: time.Now}
	for _, opt := range opts {
		opt(sink)
	}
	return sink
}

func (s *PostgresBrowserAuditSink) AppendAuditEvidence(ctx context.Context, input AuditEvidenceInput) (id string, resultErr error) {
	if s == nil || s.evidenceDB == nil || s.random == nil || input.EnterpriseID == "" || input.ActorUserID == "" || input.CaseTicketID == "" || input.ResourceType == "" || input.ResourceID == "" || !ValidAuditEvidenceAction(input.Action) {
		return "", errors.New("invalid audit evidence")
	}
	tx, err := s.evidenceDB.BeginAuditEvidenceTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err := tx.AcquireEnterpriseAuditLock(ctx, input.EnterpriseID); err != nil {
		return "", err
	}
	previous, err := tx.GetLatestEnterpriseAuditHash(ctx, input.EnterpriseID)
	if err != nil {
		return "", err
	}
	id, err = randomAuditID(s.random)
	if err != nil {
		return "", err
	}
	details, err := json.Marshal(input.Details)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(details)
	decision := "recorded"
	if input.Action == AuditActionDreamPolicyCreateRequested {
		decision = "requested"
	}
	event := audit.NewEvent(audit.EventInput{ID: id, EnterpriseID: input.EnterpriseID, CaseTicketID: input.CaseTicketID, ActorUserID: input.ActorUserID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: string(input.Action), Decision: decision, InputHash: "sha256:" + hex.EncodeToString(sum[:]), EvidencePointer: input.TraceID}, previous)
	if _, err := tx.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: event.ID, EnterpriseID: event.EnterpriseID, CaseTicketID: textValue(event.CaseTicketID), ActorUserID: textValue(event.ActorUserID), ResourceType: textValue(event.ResourceType), ResourceID: textValue(event.ResourceID), Action: event.Action, Decision: event.Decision, InputHash: textValue(event.InputHash), EvidencePointer: textValue(event.EvidencePointer), PrevHash: textValue(event.PrevHash), EventHash: event.EventHash}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// AppendApprovalTransmissionAudit appends one hash-chained approval
// TRANSMISSION lineage event (internal vocabulary: approval.plan.transmit,
// approval.evidence.record, approval.transmission.revoke) and returns the
// audit event id. This is the internal audit ledger like the browser-session
// lineage — deliberately NOT the public /v1/audit/evidence surface, whose
// AuditEvidenceAction enum stays frozen (GA Task 0E; Task 0G chains the
// events further). The event carries the plan_ref binding and the bounded
// details hash; it never carries approver identity, because none exists on
// the transmission plane.
func (s *PostgresBrowserAuditSink) AppendApprovalTransmissionAudit(ctx context.Context, event approvaltransport.AuditEvent) (id string, resultErr error) {
	if s == nil || s.evidenceDB == nil || s.random == nil || event.TenantRef == "" || event.PrincipalRef == "" || event.Action == "" || event.PlanRef == "" || event.Decision == "" {
		return "", errors.New("invalid approval transmission audit event")
	}
	tx, err := s.evidenceDB.BeginAuditEvidenceTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err := tx.AcquireEnterpriseAuditLock(ctx, event.TenantRef); err != nil {
		return "", err
	}
	previous, err := tx.GetLatestEnterpriseAuditHash(ctx, event.TenantRef)
	if err != nil {
		return "", err
	}
	id, err = randomAuditID(s.random)
	if err != nil {
		return "", err
	}
	details, err := json.Marshal(event.Details)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(details)
	chained := audit.NewEvent(audit.EventInput{ID: id, EnterpriseID: event.TenantRef, ActorUserID: event.PrincipalRef, ResourceType: "approval_transmission", ResourceID: event.PlanRef, Action: event.Action, Decision: event.Decision, InputHash: "sha256:" + hex.EncodeToString(sum[:])}, previous)
	if _, err := tx.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: chained.ID, EnterpriseID: chained.EnterpriseID, ActorUserID: textValue(chained.ActorUserID), ResourceType: textValue(chained.ResourceType), ResourceID: textValue(chained.ResourceID), Action: chained.Action, Decision: chained.Decision, InputHash: textValue(chained.InputHash), PrevHash: textValue(chained.PrevHash), EventHash: chained.EventHash}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// AppendActionTransitionAudit appends one hash-chained action-transition lineage
// event (GA Task 0F; internal vocabulary: action.requested, action.granted,
// action.dispatched, action.completed, ...) and returns the audit event id. Like
// the approval-transmission lineage this is the internal audit ledger, not the
// public /v1/audit/evidence surface; Task 0G chains and signs the events. The
// event carries the action_ref, the status_from/status_to transition and a
// bounded details hash; it never carries a business Outcome.
func (s *PostgresBrowserAuditSink) AppendActionTransitionAudit(ctx context.Context, event actions.AuditEvent) (id string, resultErr error) {
	if s == nil || s.evidenceDB == nil || s.random == nil || event.TenantRef == "" || event.PrincipalRef == "" || event.Action == "" || event.ActionRef == "" || event.StatusTo == "" {
		return "", errors.New("invalid action transition audit event")
	}
	// High-risk audit integrity: the action-transition lineage gates side
	// effects, so a missing signer fails CLOSED. A nil signer never yields an
	// unsigned high-risk audit record (the observation.go doctrine).
	if s.signer == nil {
		return "", errors.Join(audit.ErrUnavailable, errors.New("action-transition audit requires a wired audit signer"))
	}
	tx, err := s.evidenceDB.BeginAuditEvidenceTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	if _, err := tx.AcquireEnterpriseAuditLock(ctx, event.TenantRef); err != nil {
		return "", err
	}
	// The signed sub-chain links signed->signed (its own prev_hash head) and
	// carries a per-tenant monotonic sequence allocated under this same lock.
	previous, err := tx.GetLatestSignedEnterpriseAuditHash(ctx, event.TenantRef)
	if err != nil {
		return "", err
	}
	seq, err := tx.AllocateNextTenantSeq(ctx, event.TenantRef)
	if err != nil {
		return "", err
	}
	id, err = randomAuditID(s.random)
	if err != nil {
		return "", err
	}
	detail := map[string]any{"status_from": string(event.StatusFrom), "status_to": string(event.StatusTo)}
	for key, value := range event.Details {
		detail[key] = value
	}
	details, err := json.Marshal(detail)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(details)
	unsigned := audit.NewSignedEvent(audit.EventInput{
		ID: id, EnterpriseID: event.TenantRef, ActorUserID: event.PrincipalRef,
		ResourceType: "action", ResourceID: event.ActionRef, Action: event.Action,
		Decision: string(event.StatusTo), InputHash: "sha256:" + hex.EncodeToString(sum[:]),
		// GA Task 0G first-class binding refs (recoverable, individually signed).
		StatusFrom: string(event.StatusFrom), Capability: event.Capability, ParameterHash: event.ParameterHash,
		GrantRef: event.GrantRef, ApprovalEvidenceRef: event.ApprovalEvidenceRef, ReceiptRef: event.ReceiptRef,
		RiskAuthority: event.RiskAuthority, AgentClientRef: event.AgentClientRef,
		AgentReleaseRef: event.AgentReleaseRef, OrgSnapshotRef: event.OrgSnapshotRef,
	}, previous, uint64(seq), s.now())
	signed, err := audit.SignEvent(ctx, s.signer, s.logger, unsigned)
	if err != nil {
		return "", err
	}
	if _, err := tx.AppendSignedAuditEvent(ctx, db.AppendSignedAuditEventParams{
		ID: signed.ID, EnterpriseID: signed.EnterpriseID, ActorUserID: textValue(signed.ActorUserID),
		ResourceType: textValue(signed.ResourceType), ResourceID: textValue(signed.ResourceID),
		Action: signed.Action, Decision: signed.Decision, InputHash: textValue(signed.InputHash),
		PrevHash: textValue(signed.PrevHash), EventHash: signed.EventHash,
		TenantSeq:          pgtype.Int8{Int64: seq, Valid: true},
		SignatureAlgorithm: textValue(signed.Signature.Algorithm), SignatureKeyID: textValue(signed.Signature.KeyID),
		SignatureValue: textValue(signed.Signature.Value), SignedAt: pgtype.Timestamptz{Time: signed.SignedAt, Valid: true},
		StatusFrom: textValue(signed.StatusFrom), Capability: textValue(signed.Capability), ParameterHash: textValue(signed.ParameterHash),
		GrantRef: textValue(signed.GrantRef), ApprovalEvidenceRef: textValue(signed.ApprovalEvidenceRef), ReceiptRef: textValue(signed.ReceiptRef),
		RiskAuthority: textValue(signed.RiskAuthority), AgentClientRef: textValue(signed.AgentClientRef),
		AgentReleaseRef: textValue(signed.AgentReleaseRef), OrgSnapshotRef: textValue(signed.OrgSnapshotRef),
	}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

func (s *PostgresBrowserAuditSink) AppendBrowserAudit(ctx context.Context, input BrowserAuditEvent) error {
	if s == nil || s.pool == nil || input.EnterpriseID == "" || input.ActorUserID == "" || input.Action == "" || input.Decision == "" {
		return errors.New("invalid browser audit event")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	queries := db.New(tx)
	if _, err := queries.AcquireEnterpriseAuditLock(ctx, input.EnterpriseID); err != nil {
		return err
	}
	previous, err := queries.GetLatestEnterpriseAuditHash(ctx, input.EnterpriseID)
	if err != nil {
		return err
	}
	id, err := randomAuditID(s.random)
	if err != nil {
		return err
	}
	event := audit.NewEvent(audit.EventInput{ID: id, EnterpriseID: input.EnterpriseID, ActorUserID: input.ActorUserID, ResourceType: "browser_session", ResourceID: input.ActorUserID, Action: input.Action, Decision: input.Decision}, previous)
	_, err = queries.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: event.ID, EnterpriseID: event.EnterpriseID, ActorUserID: textValue(event.ActorUserID), ResourceType: textValue(event.ResourceType), ResourceID: textValue(event.ResourceID), Action: event.Action, Decision: event.Decision, PrevHash: textValue(event.PrevHash), EventHash: event.EventHash})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresBrowserAuditSink) LogoutBrowserSession(ctx context.Context, token string, input BrowserAuditEvent) (result browserauth.BrowserSession, resultErr error) {
	idHash := browserauth.HashBrowserSessionToken(token)
	if s == nil || s.pool == nil || idHash == "" || input.EnterpriseID == "" || input.Action != "browser_session.logout" || input.Decision != "allow" {
		return browserauth.BrowserSession{}, browserauth.ErrInvalidSession
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), mandatoryCleanupTimeout)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanup); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && resultErr != nil {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	queries := db.New(tx)
	now := time.Now().UTC()
	record, err := queries.RevokeAndGetBrowserSession(ctx, db.RevokeAndGetBrowserSessionParams{IDHash: idHash, RevokedAt: pgtype.Timestamptz{Time: now, Valid: true}})
	if errors.Is(err, pgx.ErrNoRows) {
		return browserauth.BrowserSession{}, browserauth.ErrInvalidSession
	}
	if err != nil || record.EnterpriseID != input.EnterpriseID || record.EnterpriseUserID == "" {
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	if _, err = queries.AcquireEnterpriseAuditLock(ctx, record.EnterpriseID); err != nil {
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	previous, err := queries.GetLatestEnterpriseAuditHash(ctx, record.EnterpriseID)
	if err != nil {
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	id, err := randomAuditID(s.random)
	if err != nil {
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	event := audit.NewEvent(audit.EventInput{ID: id, EnterpriseID: record.EnterpriseID, ActorUserID: record.EnterpriseUserID, ResourceType: "browser_session", ResourceID: record.EnterpriseUserID, Action: input.Action, Decision: input.Decision}, previous)
	if _, err = queries.AppendAuditEvent(ctx, db.AppendAuditEventParams{ID: event.ID, EnterpriseID: event.EnterpriseID, ActorUserID: textValue(event.ActorUserID), ResourceType: textValue(event.ResourceType), ResourceID: textValue(event.ResourceID), Action: event.Action, Decision: event.Decision, PrevHash: textValue(event.PrevHash), EventHash: event.EventHash}); err != nil {
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return browserauth.BrowserSession{}, browserauth.ErrSessionUnavailable
	}
	return browserauth.BrowserSession{EnterpriseID: record.EnterpriseID, UserID: record.EnterpriseUserID, CreatedAt: record.CreatedAt.Time, LastSeenAt: record.LastSeenAt.Time, IdleExpiresAt: record.IdleExpiresAt.Time, AbsoluteExpiresAt: record.AbsoluteExpiresAt.Time}, nil
}

func randomAuditID(source io.Reader) (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", err
	}
	return "browseraudit_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
func textValue(value string) pgtype.Text { return pgtype.Text{String: value, Valid: value != ""} }
