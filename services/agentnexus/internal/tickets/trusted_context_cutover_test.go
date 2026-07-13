package tickets

import (
	"context"
	"errors"
	"testing"
	"time"
)

// verifiedActor is the credential-derived actor the trust layer produces at
// ingress; the tickets service must accept identity ONLY through it.
func verifiedActor() Actor {
	return Actor{EnterpriseID: "ent_1", UserID: "user_1", CaseTicketID: "ticket_1", OrgVersion: 7}
}

func newCutoverService(store Store, opts ...Option) *Service {
	ids := sequenceIDs("id_1", "id_2", "id_3", "id_4", "id_5", "id_6")
	base := []Option{WithClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }), WithIDGenerator(ids)}
	return NewService(store, append(base, opts...)...)
}

// TestIdentityCutoverCaseTicketIdentityComesOnlyFromVerifiedActor proves case
// tickets can no longer be minted from caller-supplied envelope identity: the
// issuing input carries correlation only, and the tenant/actor pair comes from
// the verified actor.
func TestIdentityCutoverCaseTicketIdentityComesOnlyFromVerifiedActor(t *testing.T) {
	t.Parallel()
	service := newCutoverService(NewMemoryStore())
	ticket, err := service.IssueCaseTicket(context.Background(), verifiedActor(), IssueCaseTicketInput{RequestID: "req_1", TraceID: "trace_1", TTL: time.Minute})
	if err != nil {
		t.Fatalf("IssueCaseTicket: %v", err)
	}
	if ticket.EnterpriseID != "ent_1" || ticket.ActorUserID != "user_1" || ticket.RequestID != "req_1" || ticket.TraceID != "trace_1" {
		t.Fatalf("ticket=%+v: identity must equal the verified actor", ticket)
	}
	if ticket.Token == "" || ticket.TokenHash != HashCaseTicketToken(ticket.Token) {
		t.Fatalf("ticket token binding broken: %+v", ticket)
	}

	for name, actor := range map[string]Actor{
		"zero actor":               {},
		"missing user":             {EnterpriseID: "ent_1"},
		"non-canonical enterprise": {EnterpriseID: " ent_1", UserID: "user_1"},
		"non-canonical user":       {EnterpriseID: "ent_1", UserID: "user_1 "},
	} {
		if _, err := service.IssueCaseTicket(context.Background(), actor, IssueCaseTicketInput{RequestID: "req_2", TTL: time.Minute}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("%s: err=%v want ErrInvalidGrant", name, err)
		}
	}
	if _, err := service.IssueCaseTicket(context.Background(), verifiedActor(), IssueCaseTicketInput{RequestID: "", TTL: time.Minute}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("missing request id: err=%v want ErrInvalidGrant", err)
	}
}

// TestIdentityCutoverStepGrantsBindSealedOrgVersion proves step grants take
// their tenant, actor and organization version from the verified actor: the
// caller input has no identity or org-fact fields left, and an authorizer
// answering for a different sealed version is refused.
func TestIdentityCutoverStepGrantsBindSealedOrgVersion(t *testing.T) {
	t.Parallel()
	input := CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "res_9", Action: "read", TTL: time.Minute}

	authorized := GrantAuthorizerFunc(func(_ context.Context, actor Actor, _ CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: actor.EnterpriseID, OrgVersion: actor.OrgVersion, OrgUnitID: "research"}, nil
	})
	service := newCutoverService(NewMemoryStore(), WithGrantAuthorizer(authorized))
	grant, err := service.AuthorizeAndCreateGrant(context.Background(), verifiedActor(), input)
	if err != nil {
		t.Fatalf("AuthorizeAndCreateGrant: %v", err)
	}
	if grant.EnterpriseID != "ent_1" || grant.ActorUserID != "user_1" || grant.OrgVersion != 7 || grant.OrgUnitID != "research" {
		t.Fatalf("grant=%+v: tenant/actor/org version must be credential-derived", grant)
	}

	staleAuthorizer := GrantAuthorizerFunc(func(_ context.Context, actor Actor, _ CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: actor.EnterpriseID, OrgVersion: actor.OrgVersion + 1, OrgUnitID: "research"}, nil
	})
	service = newCutoverService(NewMemoryStore(), WithGrantAuthorizer(staleAuthorizer))
	if _, err := service.AuthorizeAndCreateGrant(context.Background(), verifiedActor(), input); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("stale sealed version: err=%v want ErrGrantDenied", err)
	}

	unversionedActor := verifiedActor()
	unversionedActor.OrgVersion = 0
	service = newCutoverService(NewMemoryStore(), WithGrantAuthorizer(authorized))
	if _, err := service.AuthorizeAndCreateGrant(context.Background(), unversionedActor, input); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("actor without sealed org version: err=%v want ErrInvalidGrant", err)
	}
}

// TestIdentityCutoverVerifyGrantBindsCredentialActor proves grant verification
// takes the tenant/actor pair from the verified actor instead of request
// fields, and refuses a different actor replaying a stolen token.
func TestIdentityCutoverVerifyGrantBindsCredentialActor(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	authorized := GrantAuthorizerFunc(func(_ context.Context, actor Actor, _ CreateStepGrantInput) (GrantAuthorization, error) {
		return GrantAuthorization{Allowed: true, EnterpriseID: actor.EnterpriseID, OrgVersion: actor.OrgVersion, OrgUnitID: "research"}, nil
	})
	service := newCutoverService(store, WithGrantAuthorizer(authorized))
	grant, err := service.AuthorizeAndCreateGrant(context.Background(), verifiedActor(), CreateStepGrantInput{CaseTicketID: "ticket_1", ResourceType: "dream_evidence", ResourceID: "res_9", Action: "read", TTL: time.Minute})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	binding := VerifyStepGrantInput{Token: grant.Token, ResourceType: "dream_evidence", ResourceID: "res_9", Action: "read", Scope: "dream:evidence:read"}
	verified, err := service.VerifyGrant(context.Background(), verifiedActor(), binding)
	if err != nil {
		t.Fatalf("VerifyGrant: %v", err)
	}
	if verified.EnterpriseID != "ent_1" || verified.ActorUserID != "user_1" || verified.Token != "" {
		t.Fatalf("verified=%+v", verified)
	}

	thief := Actor{EnterpriseID: "ent_1", UserID: "user_2", OrgVersion: 7}
	if _, err := service.VerifyGrant(context.Background(), thief, binding); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("stolen token replay by another actor: err=%v want ErrGrantDenied", err)
	}
	crossTenant := Actor{EnterpriseID: "ent_2", UserID: "user_1", OrgVersion: 7}
	if _, err := service.VerifyGrant(context.Background(), crossTenant, binding); !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("cross-tenant replay: err=%v want ErrGrantDenied", err)
	}
}
