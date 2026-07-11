package tickets

import (
	"testing"
	"time"
)

func TestTicketAndStepGrantLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service := NewService(NewMemoryStore(), WithClock(func() time.Time { return now }), WithIDGenerator(sequenceIDs("ticket_1", "grant_1")))

	ticket, err := service.CreateCaseTicket(CreateCaseTicketInput{
		EnterpriseID: "ent_1",
		ActorUserID:  "user_1",
		RequestID:    "req_1",
		TraceID:      "trace_1",
		TTL:          30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateCaseTicket returned error: %v", err)
	}
	if ticket.ExpiresAt != now.Add(30*time.Minute) {
		t.Fatalf("ticket ExpiresAt = %s, want %s", ticket.ExpiresAt, now.Add(30*time.Minute))
	}

	grant, err := service.CreateStepGrant(CreateStepGrantInput{
		EnterpriseID: "ent_1",
		CaseTicketID: ticket.ID,
		ResourceType: "knowledge_space",
		ResourceID:   "ks_legal",
		Action:       "read",
		Scopes:       []string{"department:legal"},
		TTL:          10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateStepGrant returned error: %v", err)
	}
	if grant.CaseTicketID != ticket.ID {
		t.Fatalf("grant CaseTicketID = %q, want %q", grant.CaseTicketID, ticket.ID)
	}
	if service.IsGrantExpired(grant, now.Add(5*time.Minute)) {
		t.Fatal("grant expired too early")
	}
	if !service.IsGrantExpired(grant, now.Add(11*time.Minute)) {
		t.Fatal("grant did not expire after its TTL")
	}
}

func TestCaseTicketPersistsOnlyOpaqueTokenHash(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithIDGenerator(sequenceIDs("ticket_internal")), WithTokenGenerator(func() (string, error) { return "opaque-case-ticket-token", nil }))
	ticket, err := svc.CreateCaseTicket(CreateCaseTicketInput{EnterpriseID: "ent_1", ActorUserID: "user_1", RequestID: "req_1", TTL: time.Minute})
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
