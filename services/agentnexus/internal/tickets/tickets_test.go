package tickets

import (
	"context"
	"testing"
	"time"
)

func TestTicketAndStepGrantLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service := NewService(NewMemoryStore(), WithClock(func() time.Time { return now }), WithIDGenerator(sequenceIDs("ticket_1", "grant_1", "audit_1")))

	actor := Actor{EnterpriseID: "ent_1", UserID: "user_1", OrgVersion: 7}
	ticket, err := service.IssueCaseTicket(context.Background(), actor, IssueCaseTicketInput{
		RequestID: "req_1",
		TraceID:   "trace_1",
		TTL:       30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueCaseTicket returned error: %v", err)
	}
	if ticket.ExpiresAt != now.Add(30*time.Minute) {
		t.Fatalf("ticket ExpiresAt = %s, want %s", ticket.ExpiresAt, now.Add(30*time.Minute))
	}
	if ticket.EnterpriseID != "ent_1" || ticket.ActorUserID != "user_1" {
		t.Fatalf("ticket identity = %q/%q, want the verified actor", ticket.EnterpriseID, ticket.ActorUserID)
	}

	authorizer := GrantAuthorizerFunc(func(_ context.Context, grantActor Actor, _ CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: grantActor.EnterpriseID, OrgVersion: grantActor.OrgVersion, OrgUnitID: "research"}, nil
	})
	service = NewService(NewMemoryStore(), WithClock(func() time.Time { return now }), WithIDGenerator(sequenceIDs("grant_1", "audit_1")), WithGrantAuthorizer(authorizer))
	grant, err := service.AuthorizeAndCreateGrant(context.Background(), actor, CreateStepGrantInput{
		CaseTicketID: ticket.ID,
		ResourceType: "dream_evidence",
		ResourceID:   "res_legal",
		Action:       "read",
		TTL:          10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("AuthorizeAndCreateGrant returned error: %v", err)
	}
	if grant.CaseTicketID != ticket.ID {
		t.Fatalf("grant CaseTicketID = %q, want %q", grant.CaseTicketID, ticket.ID)
	}
	if service.IsGrantExpired(grant, now.Add(4*time.Minute)) {
		t.Fatal("grant expired too early")
	}
	if !service.IsGrantExpired(grant, now.Add(11*time.Minute)) {
		t.Fatal("grant did not expire after its capped TTL")
	}
}

func TestCaseTicketPersistsOnlyOpaqueTokenHash(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithIDGenerator(sequenceIDs("ticket_internal")), WithTokenGenerator(func() (string, error) { return "opaque-case-ticket-token", nil }))
	ticket, err := svc.IssueCaseTicket(context.Background(), Actor{EnterpriseID: "ent_1", UserID: "user_1"}, IssueCaseTicketInput{RequestID: "req_1", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Token != "opaque-case-ticket-token" {
		t.Fatalf("token=%q", ticket.Token)
	}
	if store.RawCaseTicketTokenStored(ticket.Token) {
		t.Fatal("raw case ticket token persisted")
	}
}

func sequenceIDs(ids ...string) func() string {
	index := 0
	return func() string {
		if index >= len(ids) {
			return "extra_id"
		}
		id := ids[index]
		index++
		return id
	}
}
