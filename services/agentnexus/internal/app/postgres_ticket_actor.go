package app

import (
	"context"
	"errors"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresTicketActorAuthenticator verifies opaque Access Ticket (Case
// Ticket) credentials against PostgreSQL. It is a trust context source: it
// implements trust.AccessTicketVerifier and translates every failure onto
// the verifier sentinel contract (trust.ErrCredentialRejected /
// trust.ErrSourceUnavailable) without ever echoing the opaque token.
type PostgresTicketActorAuthenticator struct {
	enterpriseID string
	database     db.DBTX
	now          func() time.Time
}

func NewPostgresTicketActorAuthenticator(enterpriseID string, pool *pgxpool.Pool, now func() time.Time) *PostgresTicketActorAuthenticator {
	if pool == nil {
		return newPostgresTicketActorAuthenticatorWithDB(enterpriseID, nil, now)
	}
	return newPostgresTicketActorAuthenticatorWithDB(enterpriseID, pool, now)
}

func newPostgresTicketActorAuthenticatorWithDB(enterpriseID string, database db.DBTX, now func() time.Time) *PostgresTicketActorAuthenticator {
	return &PostgresTicketActorAuthenticator{enterpriseID: enterpriseID, database: database, now: now}
}

func (a *PostgresTicketActorAuthenticator) VerifyAccessTicket(ctx context.Context, opaqueID string) (trust.TicketIdentity, error) {
	if a == nil || a.database == nil || a.now == nil || !canonicalAuthorizationValue(a.enterpriseID) {
		return trust.TicketIdentity{}, trust.ErrSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return trust.TicketIdentity{}, errors.Join(trust.ErrSourceUnavailable, err)
	}
	if !canonicalAuthorizationValue(opaqueID) {
		return trust.TicketIdentity{}, trust.ErrCredentialRejected
	}
	expectedHash := tickets.HashCaseTicketToken(opaqueID)
	ticket, err := db.New(a.database).GetCaseTicket(ctx, db.GetCaseTicketParams{EnterpriseID: a.enterpriseID, TokenHash: expectedHash})
	if errors.Is(err, pgx.ErrNoRows) {
		return trust.TicketIdentity{}, trust.ErrCredentialRejected
	}
	if err != nil {
		return trust.TicketIdentity{}, trust.ErrSourceUnavailable
	}
	if ticket.TokenHash != expectedHash || ticket.EnterpriseID != a.enterpriseID || !canonicalAuthorizationValue(ticket.ID) || !canonicalAuthorizationValue(ticket.EnterpriseID) || !canonicalAuthorizationValue(ticket.ActorUserID) || !canonicalAuthorizationValue(ticket.RequestID) || (ticket.TraceID.Valid && !canonicalAuthorizationValue(ticket.TraceID.String)) || ticket.Status != "active" || !ticket.ExpiresAt.Valid || !ticket.ExpiresAt.Time.After(a.now().UTC()) {
		return trust.TicketIdentity{}, trust.ErrCredentialRejected
	}
	return trust.TicketIdentity{TenantRef: ticket.EnterpriseID, PrincipalRef: ticket.ActorUserID, TicketRef: ticket.ID, ExpiresAt: ticket.ExpiresAt.Time}, nil
}
