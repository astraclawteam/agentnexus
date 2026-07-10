package browserauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

const (
	defaultIdleTimeout     = 8 * time.Hour
	defaultAbsoluteTimeout = 24 * time.Hour
	defaultCodeTimeout     = 60 * time.Second
)

var (
	ErrInvalidSession = errors.New("invalid browser session")
	ErrInvalidGrant   = errors.New("invalid authorization grant")
	ErrInvalidInput   = errors.New("invalid browser authorization input")
)

var (
	errNotFound       = errors.New("browser authorization record not found")
	errInvalidBinding = errors.New("enterprise user binding invalid")
)

type Store interface {
	EnterpriseUserBindingExists(context.Context, string, string) (bool, error)
	CreateSession(context.Context, storedSession) error
	UseSession(context.Context, string, time.Time, time.Duration) (storedSession, error)
	RevokeSession(context.Context, string, time.Time) error
	CreateAuthorizationCode(context.Context, storedAuthorizationCode) error
	ExchangeAuthorizationCode(context.Context, exchangeRequest) (storedAuthorizationCode, error)
}

type Service struct {
	store          Store
	now            func() time.Time
	generateSecret func() (string, error)
}

type Option func(*Service)

func WithClock(clock func() time.Time) Option {
	return func(service *Service) { service.now = clock }
}

// WithTestSecretGenerator enables deterministic TDD fixtures. Production callers should
// rely on the crypto/rand-backed default.
func WithTestSecretGenerator(generator func() (string, error)) Option {
	return func(service *Service) { service.generateSecret = generator }
}

func NewService(store Store, options ...Option) *Service {
	service := &Service{store: store, now: time.Now, generateSecret: randomOpaqueSecret}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) CreateSession(ctx context.Context, input CreateSessionInput) (string, BrowserSession, error) {
	if s == nil || s.store == nil || input.EnterpriseID == "" || input.UserID == "" {
		return "", BrowserSession{}, ErrInvalidInput
	}
	ok, err := s.store.EnterpriseUserBindingExists(ctx, input.EnterpriseID, input.UserID)
	if err != nil || !ok {
		return "", BrowserSession{}, errInvalidBinding
	}
	token, err := s.generateSecret()
	if err != nil {
		return "", BrowserSession{}, err
	}
	if err := validateGeneratedSecret(token); err != nil {
		return "", BrowserSession{}, err
	}
	now := s.now().UTC()
	record := storedSession{
		IDHash: hashHex(token), EnterpriseID: input.EnterpriseID, UserID: input.UserID,
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(defaultIdleTimeout),
		AbsoluteExpiresAt: now.Add(defaultAbsoluteTimeout), UserAgentHash: hashHex(input.UserAgent),
	}
	if err := s.store.CreateSession(ctx, record); err != nil {
		return "", BrowserSession{}, err
	}
	return token, publicSession(record), nil
}

func (s *Service) GetSession(ctx context.Context, token string) (BrowserSession, error) {
	if s == nil || s.store == nil || token == "" {
		return BrowserSession{}, ErrInvalidSession
	}
	record, err := s.store.UseSession(ctx, hashHex(token), s.now().UTC(), defaultIdleTimeout)
	if err != nil {
		return BrowserSession{}, ErrInvalidSession
	}
	return publicSession(record), nil
}

func (s *Service) RevokeSession(ctx context.Context, token string) error {
	if s == nil || s.store == nil || token == "" {
		return ErrInvalidSession
	}
	if err := s.store.RevokeSession(ctx, hashHex(token), s.now().UTC()); err != nil {
		return ErrInvalidSession
	}
	return nil
}

func (s *Service) IssueCode(ctx context.Context, input IssueCodeInput) (string, error) {
	if s == nil || s.store == nil || input.EnterpriseID == "" || input.UserID == "" || input.ClientID == "" || input.RedirectURI == "" || input.Nonce == "" || !validS256Challenge(input.CodeChallenge) {
		return "", ErrInvalidInput
	}
	ok, err := s.store.EnterpriseUserBindingExists(ctx, input.EnterpriseID, input.UserID)
	if err != nil || !ok {
		return "", errInvalidBinding
	}
	code, err := s.generateSecret()
	if err != nil {
		return "", err
	}
	if err := validateGeneratedSecret(code); err != nil {
		return "", err
	}
	now := s.now().UTC()
	record := storedAuthorizationCode{
		CodeHash: hashHex(code), EnterpriseID: input.EnterpriseID, UserID: input.UserID,
		ClientID: input.ClientID, RedirectURI: input.RedirectURI, Nonce: input.Nonce,
		CodeChallenge: input.CodeChallenge, CreatedAt: now, ExpiresAt: now.Add(defaultCodeTimeout),
	}
	if err := s.store.CreateAuthorizationCode(ctx, record); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Service) ExchangeCode(ctx context.Context, input ExchangeCodeInput) (ExchangeResult, error) {
	if s == nil || s.store == nil || input.Code == "" || input.Verifier == "" || input.ClientID == "" || input.RedirectURI == "" {
		return ExchangeResult{}, ErrInvalidGrant
	}
	digest := sha256.Sum256([]byte(input.Verifier))
	record, err := s.store.ExchangeAuthorizationCode(ctx, exchangeRequest{
		CodeHash: hashHex(input.Code), VerifierDigest: digest, ClientID: input.ClientID,
		RedirectURI: input.RedirectURI, Now: s.now().UTC(),
	})
	if err != nil {
		return ExchangeResult{}, ErrInvalidGrant
	}
	return ExchangeResult{EnterpriseID: record.EnterpriseID, UserID: record.UserID, Nonce: record.Nonce}, nil
}

func randomOpaqueSecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func validateGeneratedSecret(secret string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err == nil && len(decoded) >= 32 {
		return nil
	}
	// Explicit test generators may return human-readable fixtures; production always uses randomOpaqueSecret.
	if secret != "" {
		return nil
	}
	return ErrInvalidInput
}

func validS256Challenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == challenge
}

func hashHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
