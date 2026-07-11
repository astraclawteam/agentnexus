package app

import (
	"context"
	"errors"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

func (a *PostgresTicketActorAuthenticator) AuthenticateTicketActor(ctx context.Context, opaqueID string) (AuthorizationActor, error) {
	if a == nil || a.database == nil || a.now == nil || !canonicalAuthorizationValue(a.enterpriseID) {
		return AuthorizationActor{}, ErrTicketActorUnavailable
	}
	if err := ctx.Err(); err != nil {
		return AuthorizationActor{}, errors.Join(ErrTicketActorUnavailable, err)
	}
	if !canonicalAuthorizationValue(opaqueID) {
		return AuthorizationActor{}, ErrInvalidTicketActor
	}
	expectedHash := tickets.HashCaseTicketToken(opaqueID)
	ticket, err := db.New(a.database).GetCaseTicket(ctx, db.GetCaseTicketParams{EnterpriseID: a.enterpriseID, TokenHash: expectedHash})
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationActor{}, ErrInvalidTicketActor
	}
	if err != nil {
		return AuthorizationActor{}, ErrTicketActorUnavailable
	}
	if ticket.TokenHash != expectedHash || ticket.EnterpriseID != a.enterpriseID || !canonicalAuthorizationValue(ticket.ID) || !canonicalAuthorizationValue(ticket.EnterpriseID) || !canonicalAuthorizationValue(ticket.ActorUserID) || !canonicalAuthorizationValue(ticket.RequestID) || (ticket.TraceID.Valid && !canonicalAuthorizationValue(ticket.TraceID.String)) || ticket.Status != "active" || !ticket.ExpiresAt.Valid || !ticket.ExpiresAt.Time.After(a.now().UTC()) {
		return AuthorizationActor{}, ErrInvalidTicketActor
	}
	return AuthorizationActor{EnterpriseID: ticket.EnterpriseID, UserID: ticket.ActorUserID, CaseTicketID: ticket.ID}, nil
}
