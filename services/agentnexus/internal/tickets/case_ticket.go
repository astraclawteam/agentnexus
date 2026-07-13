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

// VerifyStepGrantInput binds one exact operation. It carries NO identity:
// the tenant/actor pair comes exclusively from the verified Actor.
type VerifyStepGrantInput struct {
	Token        string
	ResourceType string
	ResourceID   string
	Action       string
	Scope        string
}

// IssueCaseTicketInput carries correlation only. Identity (tenant, actor)
// comes exclusively from the credential-derived Actor: the legacy
// CreateCaseTicketInput envelope with caller-supplied EnterpriseID and
// ActorUserID is retired.
type IssueCaseTicketInput struct {
	RequestID string
	TraceID   string
	TTL       time.Duration
}

// CreateStepGrantInput binds one exact operation request. It carries no
// tenant, actor or organization facts: those derive from the verified Actor
// and the server-side resource owner resolution.
type CreateStepGrantInput struct {
	CaseTicketID string
	ResourceType string
	ResourceID   string
	Action       string
	TTL          time.Duration
}

// Actor is the credential-derived internal actor: the trust layer resolves
// it at ingress and it is the ONLY identity input this package accepts.
type Actor struct {
	EnterpriseID string
	UserID       string
	CaseTicketID string
	// OrgVersion is the sealed organization snapshot version pinned at
	// ingress. Step grants are bound to it.
	OrgVersion int64
}

// GrantAuthorization is the server-side authorization answer: the placement
// (OrgUnitID) is resolved from the governed resource owner registry, never
// from the caller.
type GrantAuthorization struct {
	Allowed      bool
	EnterpriseID string
	OrgVersion   int64
	OrgUnitID    string
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

// IssueCaseTicket mints a Case Ticket for a verified actor. Identity comes
// only from the actor; the input carries correlation and lifetime.
func (s *Service) IssueCaseTicket(ctx context.Context, actor Actor, input IssueCaseTicketInput) (CaseTicket, error) {
	if s == nil || s.store == nil || !canonical(actor.EnterpriseID) || !canonical(actor.UserID) || !canonical(input.RequestID) || (input.TraceID != "" && !canonical(input.TraceID)) || input.TTL <= 0 {
		return CaseTicket{}, ErrInvalidGrant
	}
	if err := ctx.Err(); err != nil {
		return CaseTicket{}, errors.Join(ErrGrantUnavailable, err)
	}
	now := s.now()
	token, err := s.newToken()
	if err != nil || !canonical(token) {
		return CaseTicket{}, ErrGrantUnavailable
	}
	ticket := CaseTicket{
		ID:           s.newID(),
		TokenHash:    HashCaseTicketToken(token),
		EnterpriseID: actor.EnterpriseID,
		ActorUserID:  actor.UserID,
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
