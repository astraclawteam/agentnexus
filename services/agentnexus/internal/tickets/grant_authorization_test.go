package tickets

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func grantActor() Actor {
	return Actor{EnterpriseID: "ent_1", UserID: "user_1", OrgVersion: 7}
}

func TestGrantAuthorizationCapsDreamEvidenceTTLAndUsesExactScope(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	authorizer := GrantAuthorizerFunc(func(_ context.Context, actor Actor, input CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: actor.EnterpriseID, OrgVersion: actor.OrgVersion, OrgUnitID: "research"}, nil
	})
	svc := NewService(store,
		WithGrantAuthorizer(authorizer),
		WithClock(func() time.Time { return now }),
		WithTokenGenerator(func() (string, error) { return "opaque-step-grant-token", nil }),
		WithIDGenerator(sequenceIDs("grant_1", "audit_1")),
	)

	grant, err := svc.AuthorizeAndCreateGrant(context.Background(), grantActor(), CreateStepGrantInput{
		CaseTicketID: "ticket_1",
		ResourceType: "dream_evidence",
		ResourceID:   "ev-1",
		Action:       "read",
		TTL:          10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.ExpiresAt.Sub(now) != 5*time.Minute {
		t.Fatalf("ttl=%s", grant.ExpiresAt.Sub(now))
	}
	if !slices.Contains(grant.Scopes, "dream:evidence:read") || len(grant.Scopes) != 1 {
		t.Fatal(grant.Scopes)
	}
	if grant.OrgUnitID != "research" || grant.OrgVersion != 7 {
		t.Fatalf("grant org binding = %q/%d, want the server-resolved placement at the sealed version", grant.OrgUnitID, grant.OrgVersion)
	}
	if grant.Token != "opaque-step-grant-token" {
		t.Fatalf("token=%q", grant.Token)
	}
	if store.RawGrantTokenStored("opaque-step-grant-token") {
		t.Fatal("raw opaque grant token was persisted")
	}
}

func TestGrantAuthorizationFailsClosedAndNeverPersistsOnAuditFailure(t *testing.T) {
	base := CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute}
	actor := grantActor()
	for _, tc := range []struct {
		name string
		auth GrantAuthorizer
		fail GrantRecordStage
		want error
	}{
		{name: "policy unavailable", auth: GrantAuthorizerFunc(func(context.Context, Actor, CreateStepGrantInput) (GrantAuthorization, error) {
			return GrantAuthorization{}, errors.New("down")
		}), want: ErrGrantUnavailable},
		{name: "policy denied", auth: GrantAuthorizerFunc(func(context.Context, Actor, CreateStepGrantInput) (GrantAuthorization, error) {
			return GrantAuthorization{EnterpriseID: "ent_1", OrgVersion: 7, OrgUnitID: "research"}, nil
		}), want: ErrGrantDenied},
		{name: "missing resolved placement", auth: GrantAuthorizerFunc(func(context.Context, Actor, CreateStepGrantInput) (GrantAuthorization, error) {
			return GrantAuthorization{Allowed: true, EnterpriseID: "ent_1", OrgVersion: 7}, nil
		}), want: ErrGrantDenied},
		{name: "audit unavailable", auth: allowGrantAuthorizer(), fail: GrantRecordAudit, want: ErrGrantUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryStore()
			store.FailGrantRecordAt(tc.fail)
			svc := NewService(store, WithGrantAuthorizer(tc.auth), WithTokenGenerator(func() (string, error) { return "opaque-step-grant-token", nil }))
			_, err := svc.AuthorizeAndCreateGrant(context.Background(), actor, base)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
			if store.GrantCount() != 0 {
				t.Fatalf("persisted grants=%d", store.GrantCount())
			}
		})
	}
}

func TestGrantAuthorizationRejectsTicketSubstitutionAndUnknownAction(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, WithGrantAuthorizer(allowGrantAuthorizer()))
	input := CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute}
	actor := grantActor()
	actor.CaseTicketID = "ticket_2"
	if _, err := svc.AuthorizeAndCreateGrant(context.Background(), actor, input); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("ticket substitution err=%v", err)
	}
	actor.CaseTicketID = "ticket_1"
	input.Action = "write"
	if _, err := svc.AuthorizeAndCreateGrant(context.Background(), actor, input); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("unknown action err=%v", err)
	}
	if store.GrantCount() != 0 {
		t.Fatalf("persisted=%d", store.GrantCount())
	}
}

func TestGrantVerificationEnforcesExactBindingAndExpiry(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return now }), WithGrantAuthorizer(allowGrantAuthorizer()), WithTokenGenerator(func() (string, error) { return "opaque-step-grant-token", nil }))
	_, err := svc.AuthorizeAndCreateGrant(context.Background(), grantActor(), CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	valid := VerifyStepGrantInput{Token: "opaque-step-grant-token", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scope: "dream:evidence:read"}
	if _, err := svc.VerifyGrant(context.Background(), grantActor(), valid); err != nil {
		t.Fatalf("valid verify: %v", err)
	}
	for _, mutate := range []func(*VerifyStepGrantInput){
		func(v *VerifyStepGrantInput) { v.ResourceID = "ev-2" },
		func(v *VerifyStepGrantInput) { v.Action = "write" },
		func(v *VerifyStepGrantInput) { v.Scope = "dream:*" },
	} {
		candidate := valid
		mutate(&candidate)
		if _, err := svc.VerifyGrant(context.Background(), grantActor(), candidate); !errors.Is(err, ErrGrantDenied) {
			t.Fatalf("binding err=%v", err)
		}
	}
	foreignActor := Actor{EnterpriseID: "ent_2", UserID: "user_1", OrgVersion: 7}
	if _, err := svc.VerifyGrant(context.Background(), foreignActor, valid); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("cross-tenant actor err=%v", err)
	}
	now = now.Add(time.Minute)
	if _, err := svc.VerifyGrant(context.Background(), grantActor(), valid); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("expiry err=%v", err)
	}
}

func TestGrantVerificationAuditsEverySuccessfulExactTenantBoundUse(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	svc := NewService(store, WithClock(func() time.Time { return now }), WithGrantAuthorizer(allowGrantAuthorizer()), WithTokenGenerator(func() (string, error) { return "opaque-step-grant-token", nil }), WithIDGenerator(sequenceIDs("grant_1", "issue_audit", "verify_audit_1", "verify_audit_2", "verify_audit_3")))
	_, err := svc.AuthorizeAndCreateGrant(context.Background(), grantActor(), CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	valid := VerifyStepGrantInput{Token: "opaque-step-grant-token", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scope: "dream:evidence:read"}
	for i := 1; i <= 2; i++ {
		if _, err := svc.VerifyGrant(context.Background(), grantActor(), valid); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
		if got := store.AuditCount(); got != 1+i {
			t.Fatalf("audit count=%d after verify %d", got, i)
		}
	}
	store.FailGrantRecordAt(GrantRecordAudit)
	if _, err := svc.VerifyGrant(context.Background(), grantActor(), valid); !errors.Is(err, ErrGrantUnavailable) {
		t.Fatalf("audit failure err=%v", err)
	}
	if got := store.AuditCount(); got != 3 {
		t.Fatalf("failed verify appended audit: %d", got)
	}
	otherTenant := Actor{EnterpriseID: "ent_2", UserID: "user_1", OrgVersion: 7}
	if _, err := svc.VerifyGrant(context.Background(), otherTenant, valid); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("cross-tenant verify err=%v", err)
	}
}

func TestGrantVerificationUsesOneAtomicVerificationTimestamp(t *testing.T) {
	base := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		switch clockCalls {
		case 1:
			return base
		case 2:
			return base.Add(30 * time.Second)
		default:
			return base.Add(2 * time.Minute)
		}
	}
	store := NewMemoryStore()
	svc := NewService(store, WithClock(clock), WithGrantAuthorizer(allowGrantAuthorizer()), WithTokenGenerator(func() (string, error) { return "opaque-step-grant-token", nil }), WithIDGenerator(sequenceIDs("grant_1", "issue_audit", "verify_audit")))
	_, err := svc.AuthorizeAndCreateGrant(context.Background(), grantActor(), CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	input := VerifyStepGrantInput{Token: "opaque-step-grant-token", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scope: "dream:evidence:read"}
	if _, err := svc.VerifyGrant(context.Background(), grantActor(), input); err != nil {
		t.Fatalf("atomically valid verification denied after audit: %v", err)
	}
	if clockCalls != 2 || store.AuditCount() != 2 {
		t.Fatalf("clock calls=%d audit count=%d", clockCalls, store.AuditCount())
	}
}

func TestCredentialHashesAreDomainSeparated(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	tokens := []string{"same-opaque-credential", "same-opaque-credential"}
	i := 0
	svc := NewService(store, WithClock(func() time.Time { return now }), WithIDGenerator(sequenceIDs("ticket_1", "grant_1", "audit_1")), WithTokenGenerator(func() (string, error) { v := tokens[i]; i++; return v, nil }), WithGrantAuthorizer(allowGrantAuthorizer()))
	ticket, err := svc.IssueCaseTicket(context.Background(), grantActor(), IssueCaseTicketInput{RequestID: "req_1", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := svc.AuthorizeAndCreateGrant(context.Background(), grantActor(), CreateStepGrantInput{CaseTicketID: ticket.ID, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if ticket.TokenHash == grant.TokenHash {
		t.Fatalf("cross-type credential hashes collide: %s", ticket.TokenHash)
	}
	if ticket.TokenHash != HashCaseTicketToken(ticket.Token) || grant.TokenHash != HashStepGrantToken(grant.Token) {
		t.Fatal("stored hashes are not canonical domain hashes")
	}
}

func allowGrantAuthorizer() GrantAuthorizer {
	return GrantAuthorizerFunc(func(_ context.Context, actor Actor, _ CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: actor.EnterpriseID, OrgVersion: actor.OrgVersion, OrgUnitID: "research"}, nil
	})
}
