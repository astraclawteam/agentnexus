package tickets

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

const MaxStepGrantTTL = 5 * time.Minute

// MaxActionGrantTTL caps the lifetime of a GA Task 0F Action one-use grant.
// An Action grant is short-lived by contract, like a Step Grant.
const MaxActionGrantTTL = 5 * time.Minute

// Errors of the GA Task 0F Action one-use grant primitive.
var (
	// ErrInvalidActionGrant marks an Action grant that is not bound to one exact
	// operation, not one-use, or expired.
	ErrInvalidActionGrant = errors.New("invalid action grant")
	// ErrActionGrantConsumed marks a second attempt to consume a one-use Action
	// grant.
	ErrActionGrantConsumed = errors.New("action grant already consumed")
)

// ActionGrantInput binds one exact side-effecting operation for a one-use
// Action grant: a business-semantic CAPABILITY (never a resource selector), the
// exact parameter hash and the business context. This is deliberately a
// DIFFERENT shape from the legacy resource-scoped StepGrant above
// (dream_evidence:read); the two grant mechanisms are not conflated.
type ActionGrantInput struct {
	GrantRef           string
	BusinessContextRef string
	Capability         string
	ParameterHash      string
	TTL                time.Duration
}

// MintActionGrant builds the one-use runtime.StepGrant an Action is dispatched
// under (GA Task 0F). It binds capability + parameter_hash + business_context,
// is one-use by contract and is TTL-capped at MaxActionGrantTTL. The returned
// grant is canonically valid (runtime.StepGrant.Validate rejects a non-one-use
// or unbound grant). The durable persistence and atomic consumption live in
// internal/actions; this is the shared minting authority.
func MintActionGrant(input ActionGrantInput, issuedAt time.Time) (runtime.StepGrant, error) {
	ttl := input.TTL
	if ttl <= 0 || ttl > MaxActionGrantTTL {
		ttl = MaxActionGrantTTL
	}
	issued := issuedAt.UTC()
	grant := runtime.StepGrant{
		GrantRef:           input.GrantRef,
		BusinessContextRef: input.BusinessContextRef,
		Capability:         input.Capability,
		ParameterHash:      input.ParameterHash,
		OneUse:             true,
		IssuedAt:           issued,
		ExpiresAt:          issued.Add(ttl),
	}
	if err := grant.Validate(); err != nil {
		return runtime.StepGrant{}, errors.Join(ErrInvalidActionGrant, err)
	}
	return grant, nil
}

// ConsumeActionGrant is the one-use consumption rule of an Action grant: a grant
// may transition unconsumed -> consumed EXACTLY once, and only while unexpired.
// A grant already consumed fails ErrActionGrantConsumed; an expired or non-
// one-use grant fails ErrInvalidActionGrant. The durable store additionally
// enforces the single NULL->NOT-NULL consumed_at update by trigger — this
// primitive is the in-process authority the memory store and the actions
// service share so the one-use rule is expressed in exactly one place.
func ConsumeActionGrant(grant runtime.StepGrant, consumedAt time.Time, alreadyConsumed bool) error {
	if !grant.OneUse {
		return ErrInvalidActionGrant
	}
	if alreadyConsumed {
		return ErrActionGrantConsumed
	}
	if !consumedAt.UTC().Before(grant.ExpiresAt) {
		return errors.Join(ErrInvalidActionGrant, errors.New("action grant expired"))
	}
	return nil
}

type GrantRecordStage string

const GrantRecordAudit GrantRecordStage = "audit"

type GovernedGrantStore interface {
	CreateStepGrantAndAudit(context.Context, StepGrant, string) (StepGrant, error)
	VerifyStepGrantAndAudit(context.Context, Actor, VerifyStepGrantInput, string, string, time.Time) (StepGrant, error)
}

// AuthorizeAndCreateGrant mints a step grant for a verified actor. The
// tenant, actor and sealed organization version come exclusively from the
// Actor; the organization placement comes from the authorizer's server-side
// resource owner resolution. Caller input binds only the exact operation.
func (s *Service) AuthorizeAndCreateGrant(ctx context.Context, actor Actor, input CreateStepGrantInput) (StepGrant, error) {
	if s == nil || s.store == nil || s.authorizer == nil || !canonical(actor.EnterpriseID) || !canonical(actor.UserID) || actor.OrgVersion < 1 ||
		!canonical(input.CaseTicketID) ||
		!canonical(input.ResourceType) || !canonical(input.ResourceID) || !canonical(input.Action) || input.TTL <= 0 {
		return StepGrant{}, ErrInvalidGrant
	}
	if actor.CaseTicketID != "" && actor.CaseTicketID != input.CaseTicketID {
		return StepGrant{}, ErrGrantDenied
	}
	authorization, err := s.authorizer.AuthorizeGrant(ctx, actor, input)
	if err != nil {
		if errors.Is(err, ErrGrantDenied) {
			return StepGrant{}, ErrGrantDenied
		}
		return StepGrant{}, ErrGrantUnavailable
	}
	if !authorization.Allowed || authorization.EnterpriseID != actor.EnterpriseID || authorization.OrgVersion != actor.OrgVersion || !canonical(authorization.OrgUnitID) {
		return StepGrant{}, ErrGrantDenied
	}
	scope, ok := exactGrantScope(input.ResourceType, input.Action)
	if !ok {
		return StepGrant{}, ErrGrantDenied
	}
	ttl := input.TTL
	if ttl > MaxStepGrantTTL {
		ttl = MaxStepGrantTTL
	}
	token, err := s.newToken()
	if err != nil || !canonical(token) {
		return StepGrant{}, ErrGrantUnavailable
	}
	now := s.now()
	grantID := s.newID()
	auditID := s.newID()
	if !canonical(grantID) || !canonical(auditID) {
		return StepGrant{}, ErrGrantUnavailable
	}
	grant := StepGrant{ID: grantID, Token: token, TokenHash: HashStepGrantToken(token), EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, CaseTicketID: input.CaseTicketID, OrgUnitID: authorization.OrgUnitID, OrgVersion: actor.OrgVersion, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scopes: []string{scope}, ExpiresAt: now.Add(ttl), CreatedAt: now}
	governedStore, ok := s.store.(GovernedGrantStore)
	if !ok {
		return StepGrant{}, ErrGrantUnavailable
	}
	persisted := grant
	persisted.Token = ""
	stored, err := governedStore.CreateStepGrantAndAudit(ctx, persisted, auditID)
	if err != nil {
		if errors.Is(err, ErrGrantDenied) {
			return StepGrant{}, ErrGrantDenied
		}
		return StepGrant{}, ErrGrantUnavailable
	}
	stored.Token = token
	return stored, nil
}

// VerifyGrant checks one exact operation binding for a verified actor. The
// tenant/actor pair comes only from the Actor; a different actor replaying a
// stolen token is denied.
func (s *Service) VerifyGrant(ctx context.Context, actor Actor, input VerifyStepGrantInput) (StepGrant, error) {
	if s == nil || !canonical(actor.EnterpriseID) || !canonical(actor.UserID) || !canonical(input.Token) || !canonical(input.ResourceType) || !canonical(input.ResourceID) || !canonical(input.Action) || !canonical(input.Scope) {
		return StepGrant{}, ErrInvalidGrant
	}
	store, ok := s.store.(GovernedGrantStore)
	if !ok {
		return StepGrant{}, ErrGrantUnavailable
	}
	auditID := s.newID()
	if !canonical(auditID) {
		return StepGrant{}, ErrGrantUnavailable
	}
	grant, err := store.VerifyStepGrantAndAudit(ctx, actor, input, HashStepGrantToken(input.Token), auditID, s.now())
	if err != nil {
		if errors.Is(err, ErrGrantUnavailable) {
			return StepGrant{}, ErrGrantUnavailable
		}
		return StepGrant{}, ErrGrantDenied
	}
	if grant.EnterpriseID != actor.EnterpriseID || grant.ActorUserID != actor.UserID || grant.ResourceType != input.ResourceType || grant.ResourceID != input.ResourceID || grant.Action != input.Action || len(grant.Scopes) != 1 || grant.Scopes[0] != input.Scope {
		return StepGrant{}, ErrGrantDenied
	}
	grant.Token = ""
	return grant, nil
}

func exactGrantScope(resourceType, action string) (string, bool) {
	if resourceType == "dream_evidence" && action == "read" {
		return "dream:evidence:read", true
	}
	return "", false
}

func canonical(value string) bool { return value != "" && strings.TrimSpace(value) == value }

func (s *Service) IsGrantExpired(grant StepGrant, at time.Time) bool {
	return !at.Before(grant.ExpiresAt)
}

// Store is the persistence port. CreateStepGrant is store-level persistence
// used by governed implementations and in-memory fixtures; the ONLY minting
// paths of the service are IssueCaseTicket and AuthorizeAndCreateGrant,
// which take identity from the verified Actor.
type Store interface {
	CreateCaseTicket(CaseTicket) (CaseTicket, error)
	CreateStepGrant(StepGrant) (StepGrant, error)
}

type MemoryStore struct {
	mu             sync.RWMutex
	tickets        map[string]CaseTicket
	grants         map[string]StepGrant
	audits         []string
	failGrantStage GrantRecordStage
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tickets: map[string]CaseTicket{},
		grants:  map[string]StepGrant{},
	}
}

func (s *MemoryStore) CreateCaseTicket(ticket CaseTicket) (CaseTicket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickets[ticketKey(ticket.EnterpriseID, ticket.ID)] = ticket
	return ticket, nil
}

func (s *MemoryStore) CreateStepGrant(grant StepGrant) (StepGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[ticketKey(grant.EnterpriseID, grant.ID)] = grant
	return grant, nil
}

func (s *MemoryStore) CreateStepGrantAndAudit(_ context.Context, grant StepGrant, auditID string) (StepGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failGrantStage == GrantRecordAudit {
		return StepGrant{}, ErrGrantUnavailable
	}
	if _, exists := s.grants[ticketKey(grant.EnterpriseID, grant.ID)]; exists {
		return StepGrant{}, ErrGrantUnavailable
	}
	for _, existing := range s.grants {
		if existing.TokenHash == grant.TokenHash {
			return StepGrant{}, ErrGrantUnavailable
		}
	}
	s.grants[ticketKey(grant.EnterpriseID, grant.ID)] = grant
	s.audits = append(s.audits, auditID)
	return grant, nil
}

func (s *MemoryStore) VerifyStepGrantAndAudit(_ context.Context, actor Actor, input VerifyStepGrantInput, tokenHash, auditID string, now time.Time) (StepGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, grant := range s.grants {
		if grant.EnterpriseID == actor.EnterpriseID && grant.TokenHash == tokenHash {
			if grant.ActorUserID != actor.UserID || grant.ResourceType != input.ResourceType || grant.ResourceID != input.ResourceID || grant.Action != input.Action || len(grant.Scopes) != 1 || grant.Scopes[0] != input.Scope || !now.Before(grant.ExpiresAt) {
				return StepGrant{}, ErrGrantDenied
			}
			if s.failGrantStage == GrantRecordAudit {
				return StepGrant{}, ErrGrantUnavailable
			}
			s.audits = append(s.audits, auditID)
			return grant, nil
		}
	}
	return StepGrant{}, ErrGrantDenied
}

func (s *MemoryStore) FailGrantRecordAt(stage GrantRecordStage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failGrantStage = stage
}
func (s *MemoryStore) GrantCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.grants) }
func (s *MemoryStore) AuditCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.audits) }

func (s *MemoryStore) RawCaseTicketTokenStored(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ticket := range s.tickets {
		if ticket.Token == token || ticket.TokenHash == token {
			return true
		}
	}
	return false
}

func (s *MemoryStore) RawGrantTokenStored(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, grant := range s.grants {
		if grant.Token == token || grant.TokenHash == token {
			return true
		}
	}
	return false
}

func ticketKey(enterpriseID, id string) string {
	return enterpriseID + ":" + id
}
