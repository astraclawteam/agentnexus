package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sort"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
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
	if len(rows) > policy.MaxAtlasMemberships {
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
	pool   *pgxpool.Pool
	random io.Reader
}

func NewPostgresBrowserAuditSink(pool *pgxpool.Pool) *PostgresBrowserAuditSink {
	return &PostgresBrowserAuditSink{pool: pool, random: rand.Reader}
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
