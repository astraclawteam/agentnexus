package tickets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

const (
	caseTicketHashDomain = "agentnexus:case-ticket:v1:"
	stepGrantHashDomain  = "agentnexus:step-grant:v1:"
)

func HashCaseTicketToken(token string) string { return credentialHash(caseTicketHashDomain, token) }
func HashStepGrantToken(token string) string  { return credentialHash(stepGrantHashDomain, token) }
func credentialHash(domain, token string) string {
	sum := sha256.Sum256([]byte(domain + token))
	return hex.EncodeToString(sum[:])
}

const (
	TicketStatusActive = "active"
	GrantStatusActive  = "active"
)

type CaseTicket struct {
	ID           string
	Token        string
	TokenHash    string
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
	Token        string
	TokenHash    string
	EnterpriseID string
	ActorUserID  string
	CaseTicketID string
	OrgUnitID    string
	OrgVersion   int64
	ResourceType string
	ResourceID   string
	Action       string
	Scopes       []string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type VerifyStepGrantInput struct {
	Token        string
	EnterpriseID string
	ActorUserID  string
	ResourceType string
	ResourceID   string
	Action       string
	Scope        string
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
	OrgUnitID    string
	OrgVersion   int64
	ResourceType string
	ResourceID   string
	Action       string
	Scopes       []string
	TTL          time.Duration
}

type Actor struct {
	EnterpriseID string
	UserID       string
	CaseTicketID string
}

type GrantAuthorization struct {
	Allowed      bool
	EnterpriseID string
	OrgVersion   int64
	OrgUnitIDs   []string
}

type GrantAuthorizer interface {
	AuthorizeGrant(context.Context, Actor, CreateStepGrantInput) (GrantAuthorization, error)
}

type GrantAuthorizerFunc func(context.Context, Actor, CreateStepGrantInput) (GrantAuthorization, error)

func (f GrantAuthorizerFunc) AuthorizeGrant(ctx context.Context, actor Actor, input CreateStepGrantInput) (GrantAuthorization, error) {
	return f(ctx, actor, input)
}

var (
	ErrGrantDenied      = errors.New("step grant denied")
	ErrGrantUnavailable = errors.New("step grant unavailable")
	ErrInvalidGrant     = errors.New("invalid step grant")
)

type Service struct {
	store      Store
	now        func() time.Time
	newID      func() string
	newToken   func() (string, error)
	authorizer GrantAuthorizer
}

type Option func(*Service)

func NewService(store Store, opts ...Option) *Service {
	service := &Service{
		store:    store,
		now:      func() time.Time { return time.Now().UTC() },
		newID:    randomOpaqueID,
		newToken: randomOpaqueToken,
	}
	for _, opt := range opts {
		opt(service)
	}
	return service
}

func randomOpaqueID() string {
	token, err := randomOpaqueToken()
	if err != nil {
		return ""
	}
	return token
}

func WithGrantAuthorizer(authorizer GrantAuthorizer) Option {
	return func(service *Service) { service.authorizer = authorizer }
}

func WithTokenGenerator(newToken func() (string, error)) Option {
	return func(service *Service) { service.newToken = newToken }
}

func randomOpaqueToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
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
	token, err := s.newToken()
	if err != nil || !canonical(token) {
		return CaseTicket{}, ErrGrantUnavailable
	}
	ticket := CaseTicket{
		ID:           s.newID(),
		TokenHash:    HashCaseTicketToken(token),
		EnterpriseID: input.EnterpriseID,
		ActorUserID:  input.ActorUserID,
		RequestID:    input.RequestID,
		TraceID:      input.TraceID,
		Status:       TicketStatusActive,
		ExpiresAt:    now.Add(input.TTL),
		CreatedAt:    now,
	}
	stored, err := s.store.CreateCaseTicket(ticket)
	if err != nil {
		return CaseTicket{}, err
	}
	stored.Token = token
	return stored, nil
}
