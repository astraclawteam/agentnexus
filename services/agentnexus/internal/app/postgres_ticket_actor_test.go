package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type ticketActorDB struct {
	row  pgx.Row
	args []any
}

func (d *ticketActorDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected Exec")
}
func (d *ticketActorDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}
func (d *ticketActorDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	d.args = append([]any(nil), args...)
	return d.row
}

type ticketActorRow struct {
	ticket db.CaseTicket
	err    error
}

func (r ticketActorRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.ticket.ID
	*(dest[1].(*string)) = r.ticket.EnterpriseID
	*(dest[2].(*string)) = r.ticket.ActorUserID
	*(dest[3].(*string)) = r.ticket.RequestID
	*(dest[4].(*pgtype.Text)) = r.ticket.TraceID
	*(dest[5].(*string)) = r.ticket.Status
	*(dest[6].(*pgtype.Timestamptz)) = r.ticket.ExpiresAt
	*(dest[7].(*pgtype.Timestamptz)) = r.ticket.CreatedAt
	return nil
}

func TestPostgresTicketActorAuthenticatorValidatesEnterpriseStatusAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	valid := db.CaseTicket{ID: "opaque-ticket", EnterpriseID: "enterprise-1", ActorUserID: "user-1", RequestID: "request-1", Status: "active", ExpiresAt: pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true}}

	t.Run("active", func(t *testing.T) {
		database := &ticketActorDB{row: ticketActorRow{ticket: valid}}
		authenticator := newPostgresTicketActorAuthenticatorWithDB("enterprise-1", database, func() time.Time { return now })
		actor, err := authenticator.AuthenticateTicketActor(context.Background(), "opaque-ticket")
		if err != nil || actor != (AuthorizationActor{EnterpriseID: "enterprise-1", UserID: "user-1"}) {
			t.Fatalf("actor=%#v error=%v", actor, err)
		}
		if len(database.args) != 2 || database.args[0] != "enterprise-1" || database.args[1] != "opaque-ticket" {
			t.Fatalf("query args = %#v", database.args)
		}
	})

	for _, test := range []struct {
		name   string
		ticket db.CaseTicket
		rowErr error
		want   error
	}{
		{name: "unknown", rowErr: pgx.ErrNoRows, want: ErrInvalidTicketActor},
		{name: "expired", ticket: func() db.CaseTicket { v := valid; v.ExpiresAt.Time = now; return v }(), want: ErrInvalidTicketActor},
		{name: "inactive", ticket: func() db.CaseTicket { v := valid; v.Status = "revoked"; return v }(), want: ErrInvalidTicketActor},
		{name: "cross enterprise", ticket: func() db.CaseTicket { v := valid; v.EnterpriseID = "enterprise-2"; return v }(), want: ErrInvalidTicketActor},
		{name: "noncanonical actor", ticket: func() db.CaseTicket { v := valid; v.ActorUserID = " user-1"; return v }(), want: ErrInvalidTicketActor},
		{name: "noncanonical request", ticket: func() db.CaseTicket { v := valid; v.RequestID = " request-1"; return v }(), want: ErrInvalidTicketActor},
		{name: "noncanonical trace", ticket: func() db.CaseTicket { v := valid; v.TraceID = pgtype.Text{String: " trace-1", Valid: true}; return v }(), want: ErrInvalidTicketActor},
		{name: "database", rowErr: errors.New("database offline"), want: ErrTicketActorUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &ticketActorDB{row: ticketActorRow{ticket: test.ticket, err: test.rowErr}}
			_, err := newPostgresTicketActorAuthenticatorWithDB("enterprise-1", database, func() time.Time { return now }).AuthenticateTicketActor(context.Background(), "opaque-ticket")
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "opaque-ticket") {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}

	t.Run("nil database", func(t *testing.T) {
		_, err := newPostgresTicketActorAuthenticatorWithDB("enterprise-1", nil, func() time.Time { return now }).AuthenticateTicketActor(context.Background(), "opaque-ticket")
		if !errors.Is(err, ErrTicketActorUnavailable) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := newPostgresTicketActorAuthenticatorWithDB("enterprise-1", &ticketActorDB{row: ticketActorRow{ticket: valid}}, func() time.Time { return now }).AuthenticateTicketActor(ctx, "opaque-ticket")
		if !errors.Is(err, ErrTicketActorUnavailable) || !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestCaseTicketActorQueryIsEnterpriseScopedAndUserBound(t *testing.T) {
	t.Parallel()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "db", "queries", "tickets.sql"))
	if err != nil {
		t.Fatal(err)
	}
	query := strings.ToLower(strings.Join(strings.Fields(string(raw)), " "))
	for _, required := range []string{"from case_tickets as tickets", "join enterprise_users as users on users.enterprise_id = tickets.enterprise_id and users.id = tickets.actor_user_id", "where tickets.enterprise_id = $1 and tickets.id = $2"} {
		if !strings.Contains(query, required) {
			t.Errorf("ticket actor query missing %q", required)
		}
	}
}
