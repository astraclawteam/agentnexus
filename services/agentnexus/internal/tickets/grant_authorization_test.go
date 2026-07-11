package tickets

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestGrantAuthorizationCapsDreamEvidenceTTLAndUsesExactScope(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	authorizer := GrantAuthorizerFunc(func(_ context.Context, actor Actor, input CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: actor.EnterpriseID, OrgVersion: 7, OrgUnitIDs: []string{"research"}}, nil
	})
	svc := NewService(store,
		WithGrantAuthorizer(authorizer),
		WithClock(func() time.Time { return now }),
		WithTokenGenerator(func() (string, error) { return "opaque-step-grant-token", nil }),
		WithIDGenerator(sequenceIDs("grant_1", "audit_1")),
	)

	grant, err := svc.AuthorizeAndCreateGrant(context.Background(), Actor{EnterpriseID: "ent_1", UserID: "user_1"}, CreateStepGrantInput{
		CaseTicketID: "ticket_1",
		OrgUnitID:    "research",
		OrgVersion:   7,
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
	if grant.Token != "opaque-step-grant-token" {
		t.Fatalf("token=%q", grant.Token)
	}
	if store.RawGrantTokenStored("opaque-step-grant-token") {
		t.Fatal("raw opaque grant token was persisted")
	}
}

func TestGrantAuthorizationFailsClosedAndNeverPersistsOnAuditFailure(t *testing.T) {
	base := CreateStepGrantInput{CaseTicketID: "ticket_1", OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute}
	actor := Actor{EnterpriseID: "ent_1", UserID: "user_1"}
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
			return GrantAuthorization{EnterpriseID: "ent_1", OrgVersion: 7}, nil
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
	input := CreateStepGrantInput{CaseTicketID: "ticket_1", OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute}
	actor := Actor{EnterpriseID: "ent_1", UserID: "user_1", CaseTicketID: "ticket_2"}
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
	_, err := svc.AuthorizeAndCreateGrant(context.Background(), Actor{EnterpriseID: "ent_1", UserID: "user_1"}, CreateStepGrantInput{CaseTicketID: "ticket_1", OrgUnitID: "research", OrgVersion: 7, ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	valid := VerifyStepGrantInput{Token: "opaque-step-grant-token", EnterpriseID: "ent_1", ActorUserID: "user_1", ResourceType: "dream_evidence", ResourceID: "ev-1", Action: "read", Scope: "dream:evidence:read"}
	if _, err := svc.VerifyGrant(context.Background(), valid); err != nil {
		t.Fatalf("valid verify: %v", err)
	}
	for _, mutate := range []func(*VerifyStepGrantInput){
		func(v *VerifyStepGrantInput) { v.EnterpriseID = "ent_2" },
		func(v *VerifyStepGrantInput) { v.ResourceID = "ev-2" },
		func(v *VerifyStepGrantInput) { v.Action = "write" },
		func(v *VerifyStepGrantInput) { v.Scope = "dream:*" },
	} {
		candidate := valid
		mutate(&candidate)
		if _, err := svc.VerifyGrant(context.Background(), candidate); !errors.Is(err, ErrGrantDenied) {
			t.Fatalf("binding err=%v", err)
		}
	}
	now = now.Add(time.Minute)
	if _, err := svc.VerifyGrant(context.Background(), valid); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("expiry err=%v", err)
	}
}

func allowGrantAuthorizer() GrantAuthorizer {
	return GrantAuthorizerFunc(func(_ context.Context, actor Actor, _ CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: actor.EnterpriseID, OrgVersion: 7, OrgUnitIDs: []string{"research"}}, nil
	})
}
