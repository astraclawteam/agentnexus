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
	defaultIdleTimeout                 = 8 * time.Hour
	defaultAbsoluteTimeout             = 24 * time.Hour
	defaultCodeTimeout                 = 60 * time.Second
	defaultLoginTimeout                = 5 * time.Minute
	defaultPerBrowserLoginAttemptLimit = 8
	defaultGlobalLoginAttemptLimit     = 65536
	maxPerBrowserLoginAttemptLimit     = 64
	maxGlobalLoginAttemptLimit         = 1000000
	maxClientIDLength                  = 256
	maxRedirectURILength               = 2048
	maxConsoleStateLength              = 1024
	maxNonceLength                     = 512
)

var (
	ErrInvalidSession          = errors.New("invalid browser session")
	ErrInvalidGrant            = errors.New("invalid authorization grant")
	ErrInvalidInput            = errors.New("invalid browser authorization input")
	ErrInvalidLoginAttempt     = errors.New("invalid OIDC login attempt")
	ErrSessionUnavailable      = errors.New("browser session store unavailable")
	ErrGrantUnavailable        = errors.New("authorization grant store unavailable")
	ErrLoginAttemptUnavailable = errors.New("OIDC login attempt store unavailable")
	ErrLoginAttemptLimited     = errors.New("too many outstanding OIDC login attempts")
	ErrInvalidAccessToken      = errors.New("invalid browser access token")
	ErrAccessTokenUnavailable  = errors.New("browser access token store unavailable")
)

var (
	errNotFound            = errors.New("browser authorization record not found")
	errInvalidBinding      = errors.New("enterprise user binding invalid")
	errDuplicate           = errors.New("browser authorization record already exists")
	errStoreUnavailable    = errors.New("browser authorization store unavailable")
	errStoreInvariant      = errors.New("browser authorization store invariant violated")
	errLoginAttemptLimited = errors.New("outstanding OIDC login attempt limit reached")
)

type Store interface {
	EnterpriseUserBindingExists(context.Context, string, string) (bool, error)
	CreateSession(context.Context, storedSession) error
	UseSession(context.Context, string, time.Time, time.Duration) (storedSession, error)
	RevokeSession(context.Context, string, time.Time) error
	RevokeAndGetSession(context.Context, string, time.Time) (storedSession, error)
	CreateAuthorizationCode(context.Context, storedAuthorizationCode) error
	ExchangeAuthorizationCode(context.Context, exchangeRequest) (storedAuthorizationCode, error)
	UseAccessToken(context.Context, string, string, string, time.Time) (storedAccessToken, error)
	RevokeSessionByAccessToken(context.Context, string, string, string, time.Time) (storedSession, error)
	CreateLoginAttempt(context.Context, storedLoginAttempt, LoginAttemptLimits) error
	ConsumeLoginAttempt(context.Context, string, string, time.Time) (storedLoginAttempt, error)
}

type LoginAttemptLimits struct {
	PerBrowser int
	Global     int
}

func DefaultLoginAttemptLimits() LoginAttemptLimits {
	return LoginAttemptLimits{PerBrowser: defaultPerBrowserLoginAttemptLimit, Global: defaultGlobalLoginAttemptLimit}
}

func NewLoginAttemptLimits(perBrowser, global int) (LoginAttemptLimits, error) {
	limits := LoginAttemptLimits{PerBrowser: perBrowser, Global: global}
	if !limits.valid() {
		return LoginAttemptLimits{}, ErrInvalidInput
	}
	return limits, nil
}

func (l LoginAttemptLimits) valid() bool {
	return l.PerBrowser >= 1 && l.PerBrowser <= maxPerBrowserLoginAttemptLimit && l.Global >= l.PerBrowser && l.Global <= maxGlobalLoginAttemptLimit
}

func (s *Service) LogoutSession(ctx context.Context, token string) (BrowserSession, error) {
	if s == nil || s.store == nil || validateGeneratedSecret(token) != nil {
		return BrowserSession{}, ErrInvalidSession
	}
	record, err := s.store.RevokeAndGetSession(ctx, hashHex(token), s.now().UTC())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return BrowserSession{}, ErrInvalidSession
		}
		return BrowserSession{}, ErrSessionUnavailable
	}
	return publicSession(record), nil
}

func (s *Service) CreateLoginAttempt(ctx context.Context, input CreateLoginAttemptInput) (string, string, LoginAttempt, error) {
	if s == nil || s.store == nil || !s.loginAttemptLimits.valid() || input.EnterpriseID == "" || !validOpaqueSecret(input.BrowserID) || !validBounded(input.ClientID, maxClientIDLength) || !validBounded(input.RedirectURI, maxRedirectURILength) || !validBounded(input.ConsoleState, maxConsoleStateLength) || !validBounded(input.ConsoleNonce, maxNonceLength) || !validS256Challenge(input.CodeChallenge) {
		return "", "", LoginAttempt{}, ErrInvalidInput
	}
	state, err := s.generateSecret()
	if err != nil {
		return "", "", LoginAttempt{}, err
	}
	nonce, err := s.generateSecret()
	if err != nil {
		return "", "", LoginAttempt{}, err
	}
	binding, err := s.generateSecret()
	if err != nil {
		return "", "", LoginAttempt{}, err
	}
	if !validOpaqueSecret(state) || !validOpaqueSecret(nonce) || !validOpaqueSecret(binding) {
		return "", "", LoginAttempt{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Second)
	attempt := LoginAttempt{EnterpriseID: input.EnterpriseID, ClientID: input.ClientID, RedirectURI: input.RedirectURI, ConsoleState: input.ConsoleState, ConsoleNonce: input.ConsoleNonce, CodeChallenge: input.CodeChallenge, UpstreamNonce: nonce, CreatedAt: now, ExpiresAt: now.Add(defaultLoginTimeout)}
	if err := s.store.CreateLoginAttempt(ctx, storedLoginAttempt{StateHash: hashHex(state), BindingHash: hashHex(binding), BrowserIDHash: hashHex(input.BrowserID), LoginAttempt: attempt}, s.loginAttemptLimits); err != nil {
		if errors.Is(err, errLoginAttemptLimited) {
			return "", "", LoginAttempt{}, ErrLoginAttemptLimited
		}
		return "", "", LoginAttempt{}, ErrLoginAttemptUnavailable
	}
	return state, binding, attempt, nil
}

func (s *Service) ConsumeLoginAttempt(ctx context.Context, state, binding string) (LoginAttempt, error) {
	if s == nil || s.store == nil || !validOpaqueSecret(state) || !validOpaqueSecret(binding) {
		return LoginAttempt{}, ErrInvalidLoginAttempt
	}
	record, err := s.store.ConsumeLoginAttempt(ctx, hashHex(state), hashHex(binding), s.now().UTC())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return LoginAttempt{}, ErrInvalidLoginAttempt
		}
		return LoginAttempt{}, ErrLoginAttemptUnavailable
	}
	return record.LoginAttempt, nil
}

func validBounded(value string, max int) bool { return value != "" && len(value) <= max }
func validOpaqueSecret(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && len(value) == 43 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

type Service struct {
	store              Store
	now                func() time.Time
	generateSecret     func() (string, error)
	loginAttemptLimits LoginAttemptLimits
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

func WithLoginAttemptLimits(limits LoginAttemptLimits) Option {
	return func(service *Service) { service.loginAttemptLimits = limits }
}

func NewService(store Store, options ...Option) *Service {
	service := &Service{store: store, now: time.Now, generateSecret: randomOpaqueSecret, loginAttemptLimits: DefaultLoginAttemptLimits()}
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
		if errors.Is(err, errNotFound) {
			return BrowserSession{}, ErrInvalidSession
		}
		return BrowserSession{}, ErrSessionUnavailable
	}
	return publicSession(record), nil
}

func (s *Service) RevokeSession(ctx context.Context, token string) error {
	if s == nil || s.store == nil || token == "" {
		return ErrInvalidSession
	}
	if err := s.store.RevokeSession(ctx, hashHex(token), s.now().UTC()); err != nil {
		if errors.Is(err, errNotFound) {
			return ErrInvalidSession
		}
		return ErrSessionUnavailable
	}
	return nil
}

func (s *Service) IssueCode(ctx context.Context, input IssueCodeInput) (string, error) {
	if s == nil || s.store == nil || input.EnterpriseID == "" || input.UserID == "" || validateGeneratedSecret(input.BrowserSessionToken) != nil || !validBounded(input.ClientID, maxClientIDLength) || !validBounded(input.RedirectURI, maxRedirectURILength) || !validBounded(input.Nonce, maxNonceLength) || !validS256Challenge(input.CodeChallenge) {
		return "", ErrInvalidInput
	}
	session, err := s.store.UseSession(ctx, hashHex(input.BrowserSessionToken), s.now().UTC(), defaultIdleTimeout)
	if err != nil || session.EnterpriseID != input.EnterpriseID || session.UserID != input.UserID {
		return "", errInvalidBinding
	}
	code, err := s.generateSecret()
	if err != nil {
		return "", err
	}
	if !validOpaqueSecret(code) {
		return "", ErrInvalidInput
	}
	now := s.now().UTC()
	record := storedAuthorizationCode{
		CodeHash: hashHex(code), EnterpriseID: input.EnterpriseID, UserID: input.UserID,
		ClientID: input.ClientID, RedirectURI: input.RedirectURI, Nonce: input.Nonce,
		CodeChallenge: input.CodeChallenge, CreatedAt: now, ExpiresAt: now.Add(defaultCodeTimeout),
		BrowserSessionIDHash: hashHex(input.BrowserSessionToken),
	}
	if err := s.store.CreateAuthorizationCode(ctx, record); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Service) ExchangeCode(ctx context.Context, input ExchangeCodeInput) (ExchangeResult, error) {
	if s == nil || s.store == nil || !validOpaqueSecret(input.Code) || !validPKCEVerifier(input.Verifier) || !validBounded(input.ClientID, maxClientIDLength) || !validBounded(input.RedirectURI, maxRedirectURILength) {
		return ExchangeResult{}, ErrInvalidGrant
	}
	digest := sha256.Sum256([]byte(input.Verifier))
	accessToken, err := s.generateSecret()
	if err != nil || validateGeneratedSecret(accessToken) != nil {
		return ExchangeResult{}, ErrGrantUnavailable
	}
	record, err := s.store.ExchangeAuthorizationCode(ctx, exchangeRequest{
		CodeHash: hashHex(input.Code), VerifierDigest: digest, ClientID: input.ClientID,
		RedirectURI: input.RedirectURI, Now: s.now().UTC(), AccessTokenHash: hashHex(accessToken), Audience: input.ClientID,
	})
	if err != nil {
		if errors.Is(err, errNotFound) {
			return ExchangeResult{}, ErrInvalidGrant
		}
		return ExchangeResult{}, ErrGrantUnavailable
	}
	return ExchangeResult{EnterpriseID: record.EnterpriseID, UserID: record.UserID, Nonce: record.Nonce, AccessToken: accessToken, AccessTokenExpiresAt: record.AccessTokenExpiresAt, AccessTokenExpiresIn: record.AccessTokenExpiresAt.Sub(s.now().UTC())}, nil
}

func (s *Service) GetAccessTokenSession(ctx context.Context, token, clientID, audience string) (BrowserSession, error) {
	if s == nil || s.store == nil || validateGeneratedSecret(token) != nil || !validBounded(clientID, maxClientIDLength) || !validBounded(audience, maxClientIDLength) {
		return BrowserSession{}, ErrInvalidAccessToken
	}
	record, err := s.store.UseAccessToken(ctx, hashHex(token), clientID, audience, s.now().UTC())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return BrowserSession{}, ErrInvalidAccessToken
		}
		return BrowserSession{}, ErrAccessTokenUnavailable
	}
	return BrowserSession{EnterpriseID: record.EnterpriseID, UserID: record.UserID, CreatedAt: record.SessionCreatedAt, LastSeenAt: record.SessionLastSeenAt, IdleExpiresAt: record.SessionIdleExpiresAt, AbsoluteExpiresAt: record.SessionAbsoluteExpiresAt}, nil
}

func (s *Service) LogoutAccessTokenSession(ctx context.Context, token, clientID, audience string) (BrowserSession, error) {
	if s == nil || s.store == nil || validateGeneratedSecret(token) != nil {
		return BrowserSession{}, ErrInvalidAccessToken
	}
	record, err := s.store.RevokeSessionByAccessToken(ctx, hashHex(token), clientID, audience, s.now().UTC())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return BrowserSession{}, ErrInvalidAccessToken
		}
		return BrowserSession{}, ErrSessionUnavailable
	}
	return publicSession(record), nil
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
	if err == nil && len(decoded) >= 32 && base64.RawURLEncoding.EncodeToString(decoded) == secret {
		return nil
	}
	return ErrInvalidInput
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := range len(verifier) {
		char := verifier[i]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '.' || char == '_' || char == '~' {
			continue
		}
		return false
	}
	return true
}

func validS256Challenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == challenge
}

func hashHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func HashBrowserSessionToken(token string) string {
	if validateGeneratedSecret(token) != nil {
		return ""
	}
	return hashHex(token)
}

func HashBrowserAccessToken(token string) string { return HashBrowserSessionToken(token) }
