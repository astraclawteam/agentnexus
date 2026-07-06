package tickets

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreateCaseTicket(ticket CaseTicket) (CaseTicket, error) {
	row := s.pool.QueryRow(context.Background(), `
		INSERT INTO case_tickets (id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at
	`, ticket.ID, ticket.EnterpriseID, ticket.ActorUserID, ticket.RequestID, nullTicketText(ticket.TraceID), ticket.Status, ticket.ExpiresAt, ticket.CreatedAt)
	return scanCaseTicket(row)
}

func (s *PostgresStore) GetCaseTicket(enterpriseID, id string) (CaseTicket, error) {
	row := s.pool.QueryRow(context.Background(), `
		SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, created_at
		FROM case_tickets
		WHERE enterprise_id = $1 AND id = $2
	`, enterpriseID, id)
	return scanCaseTicket(row)
}

func (s *PostgresStore) CreateStepGrant(grant StepGrant) (StepGrant, error) {
	scopes, err := json.Marshal(grant.Scopes)
	if err != nil {
		return StepGrant{}, err
	}
	row := s.pool.QueryRow(context.Background(), `
		INSERT INTO step_grants (id, enterprise_id, case_ticket_id, resource_type, resource_id, action, scopes, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, enterprise_id, case_ticket_id, resource_type, resource_id, action, scopes, expires_at, created_at
	`, grant.ID, grant.EnterpriseID, grant.CaseTicketID, grant.ResourceType, grant.ResourceID, grant.Action, scopes, grant.ExpiresAt, grant.CreatedAt)
	return scanStepGrant(row)
}

type ticketScanner interface {
	Scan(dest ...any) error
}

func scanCaseTicket(row ticketScanner) (CaseTicket, error) {
	var ticket CaseTicket
	var traceID pgtype.Text
	if err := row.Scan(&ticket.ID, &ticket.EnterpriseID, &ticket.ActorUserID, &ticket.RequestID, &traceID, &ticket.Status, &ticket.ExpiresAt, &ticket.CreatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return CaseTicket{}, ErrTicketNotFound
		}
		return CaseTicket{}, err
	}
	if traceID.Valid {
		ticket.TraceID = traceID.String
	}
	return ticket, nil
}

func scanStepGrant(row ticketScanner) (StepGrant, error) {
	var grant StepGrant
	var scopes []byte
	if err := row.Scan(&grant.ID, &grant.EnterpriseID, &grant.CaseTicketID, &grant.ResourceType, &grant.ResourceID, &grant.Action, &scopes, &grant.ExpiresAt, &grant.CreatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return StepGrant{}, ErrTicketNotFound
		}
		return StepGrant{}, err
	}
	if len(scopes) > 0 {
		if err := json.Unmarshal(scopes, &grant.Scopes); err != nil {
			return StepGrant{}, err
		}
	}
	return grant, nil
}

func nullTicketText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

var _ Store = (*PostgresStore)(nil)
