package tickets

import "time"

func (s *Service) GetCaseTicket(enterpriseID, id string) (CaseTicket, error) {
	return s.store.GetCaseTicket(enterpriseID, id)
}

func (s *Service) CreateStepGrant(input CreateStepGrantInput) (StepGrant, error) {
	now := s.now()
	grant := StepGrant{
		ID:           s.newID(),
		EnterpriseID: input.EnterpriseID,
		CaseTicketID: input.CaseTicketID,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		Action:       input.Action,
		Scopes:       append([]string(nil), input.Scopes...),
		ExpiresAt:    now.Add(input.TTL),
		CreatedAt:    now,
	}
	return s.store.CreateStepGrant(grant)
}

func (s *Service) IsGrantExpired(grant StepGrant, at time.Time) bool {
	return !at.Before(grant.ExpiresAt)
}

type Store interface {
	CreateCaseTicket(CaseTicket) (CaseTicket, error)
	GetCaseTicket(string, string) (CaseTicket, error)
	CreateStepGrant(StepGrant) (StepGrant, error)
}

type MemoryStore struct {
	tickets map[string]CaseTicket
	grants  map[string]StepGrant
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tickets: map[string]CaseTicket{},
		grants:  map[string]StepGrant{},
	}
}

func (s *MemoryStore) CreateCaseTicket(ticket CaseTicket) (CaseTicket, error) {
	s.tickets[ticketKey(ticket.EnterpriseID, ticket.ID)] = ticket
	return ticket, nil
}

func (s *MemoryStore) GetCaseTicket(enterpriseID, id string) (CaseTicket, error) {
	ticket, ok := s.tickets[ticketKey(enterpriseID, id)]
	if !ok {
		return CaseTicket{}, ErrTicketNotFound
	}
	return ticket, nil
}

func (s *MemoryStore) CreateStepGrant(grant StepGrant) (StepGrant, error) {
	s.grants[ticketKey(grant.EnterpriseID, grant.ID)] = grant
	return grant, nil
}

func ticketKey(enterpriseID, id string) string {
	return enterpriseID + ":" + id
}
