package tickets

import "time"

const (
	TicketStatusActive = "active"
	GrantStatusActive  = "active"
)

type CaseTicket struct {
	ID           string
	EnterpriseID string
	ActorUserID  string
	RequestID    string
	TraceID      string
	Status       string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type StepGrant struct {
	ID           string
	EnterpriseID string
	CaseTicketID string
	ResourceType string
	ResourceID   string
	Action       string
	Scopes       []string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type CreateCaseTicketInput struct {
	EnterpriseID string
	ActorUserID  string
	RequestID    string
	TraceID      string
	TTL          time.Duration
}

type CreateStepGrantInput struct {
	EnterpriseID string
	CaseTicketID string
	ResourceType string
	ResourceID   string
	Action       string
	Scopes       []string
	TTL          time.Duration
}

type Service struct {
	store Store
	now   func() time.Time
	newID func() string
}

type Option func(*Service)

func NewService(store Store, opts ...Option) *Service {
	service := &Service{
		store: store,
		now:   func() time.Time { return time.Now().UTC() },
		newID: func() string { return "generated_id" },
	}
	for _, opt := range opts {
		opt(service)
	}
	return service
}

func WithClock(clock func() time.Time) Option {
	return func(service *Service) {
		service.now = clock
	}
}

func WithIDGenerator(newID func() string) Option {
	return func(service *Service) {
		service.newID = newID
	}
}

func (s *Service) CreateCaseTicket(input CreateCaseTicketInput) (CaseTicket, error) {
	now := s.now()
	ticket := CaseTicket{
		ID:           s.newID(),
		EnterpriseID: input.EnterpriseID,
		ActorUserID:  input.ActorUserID,
		RequestID:    input.RequestID,
		TraceID:      input.TraceID,
		Status:       TicketStatusActive,
		ExpiresAt:    now.Add(input.TTL),
		CreatedAt:    now,
	}
	return s.store.CreateCaseTicket(ticket)
}
