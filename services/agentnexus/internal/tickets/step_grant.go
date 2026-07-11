package tickets

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

const MaxStepGrantTTL = 5 * time.Minute

type GrantRecordStage string

const GrantRecordAudit GrantRecordStage = "audit"

type GovernedGrantStore interface {
	CreateStepGrantAndAudit(context.Context, StepGrant, string) (StepGrant, error)
	VerifyStepGrantAndAudit(context.Context, VerifyStepGrantInput, string, string, time.Time) (StepGrant, error)
}

func (s *Service) CreateStepGrant(input CreateStepGrantInput) (StepGrant, error) {
	now := s.now()
	grant := StepGrant{
		ID:           s.newID(),
		EnterpriseID: input.EnterpriseID,
		CaseTicketID: input.CaseTicketID,
		OrgUnitID:    input.OrgUnitID,
		OrgVersion:   input.OrgVersion,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		Action:       input.Action,
		Scopes:       append([]string(nil), input.Scopes...),
		ExpiresAt:    now.Add(input.TTL),
		CreatedAt:    now,
	}
	return s.store.CreateStepGrant(grant)
}

func (s *Service) AuthorizeAndCreateGrant(ctx context.Context, actor Actor, input CreateStepGrantInput) (StepGrant, error) {
	if s == nil || s.store == nil || s.authorizer == nil || !canonical(actor.EnterpriseID) || !canonical(actor.UserID) || input.EnterpriseID != "" || input.Scopes != nil ||
		!canonical(input.CaseTicketID) || !canonical(input.OrgUnitID) || input.OrgVersion < 1 ||
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
	if !authorization.Allowed || authorization.EnterpriseID != actor.EnterpriseID || authorization.OrgVersion != input.OrgVersion || !slices.Contains(authorization.OrgUnitIDs, input.OrgUnitID) {
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
	grant := StepGrant{ID: grantID, Token: token, TokenHash: HashStepGrantToken(token), EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, CaseTicketID: input.CaseTicketID, OrgUnitID: input.OrgUnitID, OrgVersion: input.OrgVersion, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scopes: []string{scope}, ExpiresAt: now.Add(ttl), CreatedAt: now}
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

func (s *Service) VerifyGrant(ctx context.Context, input VerifyStepGrantInput) (StepGrant, error) {
	if s == nil || !canonical(input.Token) || !canonical(input.EnterpriseID) || !canonical(input.ActorUserID) || !canonical(input.ResourceType) || !canonical(input.ResourceID) || !canonical(input.Action) || !canonical(input.Scope) {
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
	grant, err := store.VerifyStepGrantAndAudit(ctx, input, HashStepGrantToken(input.Token), auditID, s.now())
	if err != nil {
		if errors.Is(err, ErrGrantUnavailable) {
			return StepGrant{}, ErrGrantUnavailable
		}
		return StepGrant{}, ErrGrantDenied
	}
	if grant.EnterpriseID != input.EnterpriseID || grant.ActorUserID != input.ActorUserID || grant.ResourceType != input.ResourceType || grant.ResourceID != input.ResourceID || grant.Action != input.Action || len(grant.Scopes) != 1 || grant.Scopes[0] != input.Scope {
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

func (s *MemoryStore) VerifyStepGrantAndAudit(_ context.Context, input VerifyStepGrantInput, tokenHash, auditID string, now time.Time) (StepGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, grant := range s.grants {
		if grant.EnterpriseID == input.EnterpriseID && grant.TokenHash == tokenHash {
			if grant.ActorUserID != input.ActorUserID || grant.ResourceType != input.ResourceType || grant.ResourceID != input.ResourceID || grant.Action != input.Action || len(grant.Scopes) != 1 || grant.Scopes[0] != input.Scope || !now.Before(grant.ExpiresAt) {
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
