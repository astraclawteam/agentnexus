package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresBrowserDirectory struct{ pool *pgxpool.Pool }

func NewPostgresBrowserDirectory(pool *pgxpool.Pool) *PostgresBrowserDirectory {
	return &PostgresBrowserDirectory{pool: pool}
}

func (d *PostgresBrowserDirectory) ResolveExternalIdentity(ctx context.Context, enterpriseID, issuer, subject string) (string, string, error) {
	if d == nil || d.pool == nil || enterpriseID == "" || issuer == "" || subject == "" {
		return "", "", errors.New("identity directory unavailable")
	}
	record, err := db.New(d.pool).ResolveExternalIdentity(ctx, db.ResolveExternalIdentityParams{EnterpriseID: enterpriseID, Provider: issuer, ExternalSubject: subject})
	if err != nil {
		return "", "", err
	}
	return record.EnterpriseID, record.EnterpriseUserID, nil
}

func (d *PostgresBrowserDirectory) ResolveBrowserProfile(ctx context.Context, enterpriseID, userID string) (BrowserProfile, error) {
	if d == nil || d.pool == nil || enterpriseID == "" || userID == "" {
		return BrowserProfile{}, errors.New("profile directory unavailable")
	}
	queries := db.New(d.pool)
	record, err := queries.GetBrowserProfile(ctx, db.GetBrowserProfileParams{EnterpriseID: enterpriseID, ID: userID})
	if err != nil {
		return BrowserProfile{}, err
	}
	units, err := queries.ListBrowserProfileOrgUnits(ctx, db.ListBrowserProfileOrgUnitsParams{EnterpriseID: enterpriseID, EnterpriseUserID: userID})
	if err != nil {
		return BrowserProfile{}, err
	}
	if units == nil {
		units = []string{}
	}
	return BrowserProfile{EnterpriseID: enterpriseID, EnterpriseUserID: userID, DisplayName: record.DisplayName, OrgVersion: record.OrgVersion, OrgUnitIDs: units, Permissions: []string{}, AdvancedModeAllowed: false}, nil
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

func randomAuditID(source io.Reader) (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", err
	}
	return "browseraudit_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
func textValue(value string) pgtype.Text { return pgtype.Text{String: value, Valid: value != ""} }
