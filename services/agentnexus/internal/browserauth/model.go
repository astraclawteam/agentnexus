package browserauth

import "time"

type BrowserSession struct {
	EnterpriseID      string
	UserID            string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

type CreateSessionInput struct {
	EnterpriseID string
	UserID       string
	UserAgent    string
}

type IssueCodeInput struct {
	EnterpriseID        string
	UserID              string
	ClientID            string
	RedirectURI         string
	Nonce               string
	CodeChallenge       string
	BrowserSessionToken string
}

type ExchangeCodeInput struct {
	Code        string
	Verifier    string
	ClientID    string
	RedirectURI string
}

type ExchangeResult struct {
	EnterpriseID         string
	UserID               string
	Nonce                string
	AccessToken          string
	AccessTokenExpiresAt time.Time
	AccessTokenExpiresIn time.Duration
}

type CreateLoginAttemptInput struct {
	EnterpriseID  string
	ClientID      string
	BrowserID     string
	RedirectURI   string
	ConsoleState  string
	ConsoleNonce  string
	CodeChallenge string
}

type LoginAttempt struct {
	EnterpriseID  string
	ClientID      string
	RedirectURI   string
	ConsoleState  string
	ConsoleNonce  string
	CodeChallenge string
	UpstreamNonce string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type storedLoginAttempt struct {
	StateHash     string
	BindingHash   string
	BrowserIDHash string
	LoginAttempt
}

type storedSession struct {
	IDHash            string
	EnterpriseID      string
	UserID            string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	UserAgentHash     string
}

type storedAuthorizationCode struct {
	CodeHash             string
	EnterpriseID         string
	UserID               string
	ClientID             string
	RedirectURI          string
	Nonce                string
	CodeChallenge        string
	CreatedAt            time.Time
	ExpiresAt            time.Time
	ConsumedAt           *time.Time
	BrowserSessionIDHash string
	AccessTokenExpiresAt time.Time
}

type storedAccessToken struct {
	TokenHash                string
	BrowserSessionIDHash     string
	EnterpriseID             string
	UserID                   string
	ClientID                 string
	Audience                 string
	CreatedAt                time.Time
	ExpiresAt                time.Time
	RevokedAt                *time.Time
	SessionCreatedAt         time.Time
	SessionLastSeenAt        time.Time
	SessionIdleExpiresAt     time.Time
	SessionAbsoluteExpiresAt time.Time
}

type exchangeRequest struct {
	CodeHash        string
	VerifierDigest  [32]byte
	ClientID        string
	RedirectURI     string
	Now             time.Time
	AccessTokenHash string
	Audience        string
}

func publicSession(session storedSession) BrowserSession {
	return BrowserSession{
		EnterpriseID:      session.EnterpriseID,
		UserID:            session.UserID,
		CreatedAt:         session.CreatedAt,
		LastSeenAt:        session.LastSeenAt,
		IdleExpiresAt:     session.IdleExpiresAt,
		AbsoluteExpiresAt: session.AbsoluteExpiresAt,
	}
}
