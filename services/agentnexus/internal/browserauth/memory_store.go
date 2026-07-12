package browserauth

import (
	"container/heap"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

type MemoryStore struct {
	mu                     sync.Mutex
	users                  map[string]struct{}
	sessions               map[string]storedSession
	codes                  map[string]storedAuthorizationCode
	accessTokens           map[string]storedAccessToken
	loginAttempts          map[string]storedLoginAttempt
	loginAttemptGeneration map[string]uint64
	nextAttemptGeneration  uint64
	scopeCounts            map[loginAttemptScope]int
	browserCounts          map[loginAttemptBrowserScope]int
	loginAttemptExpiry     loginAttemptExpiryHeap
	err                    error
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:                  map[string]struct{}{},
		sessions:               map[string]storedSession{},
		codes:                  map[string]storedAuthorizationCode{},
		accessTokens:           map[string]storedAccessToken{},
		loginAttempts:          map[string]storedLoginAttempt{},
		loginAttemptGeneration: map[string]uint64{},
		scopeCounts:            map[loginAttemptScope]int{},
		browserCounts:          map[loginAttemptBrowserScope]int{},
	}
}

func (s *MemoryStore) CreateLoginAttempt(ctx context.Context, attempt storedLoginAttempt, limits LoginAttemptLimits) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !attempt.ExpiresAt.After(attempt.CreatedAt) || attempt.ExpiresAt.Sub(attempt.CreatedAt) > defaultLoginTimeout {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	s.expireLoginAttempts(attempt.CreatedAt)
	if _, ok := s.loginAttempts[attempt.StateHash]; ok {
		return errDuplicate
	}
	scope := loginAttemptScope{EnterpriseID: attempt.EnterpriseID, ClientID: attempt.ClientID}
	browser := loginAttemptBrowserScope{loginAttemptScope: scope, BrowserIDHash: attempt.BrowserIDHash}
	if s.scopeCounts[scope] >= limits.Global || s.browserCounts[browser] >= limits.PerBrowser {
		return errLoginAttemptLimited
	}
	s.loginAttempts[attempt.StateHash] = attempt
	s.nextAttemptGeneration++
	s.loginAttemptGeneration[attempt.StateHash] = s.nextAttemptGeneration
	s.scopeCounts[scope]++
	s.browserCounts[browser]++
	heap.Push(&s.loginAttemptExpiry, loginAttemptExpiryItem{ExpiresAt: attempt.ExpiresAt, StateHash: attempt.StateHash, Generation: s.nextAttemptGeneration})
	return nil
}

func (s *MemoryStore) ConsumeLoginAttempt(ctx context.Context, stateHash, bindingHash string, now time.Time) (storedLoginAttempt, error) {
	if err := ctx.Err(); err != nil {
		return storedLoginAttempt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return storedLoginAttempt{}, err
	}
	if s.err != nil {
		return storedLoginAttempt{}, s.err
	}
	record, ok := s.loginAttempts[stateHash]
	if !ok {
		return storedLoginAttempt{}, errNotFound
	}
	if !now.Before(record.ExpiresAt) {
		s.deleteLoginAttempt(record)
		return storedLoginAttempt{}, errNotFound
	}
	if len(record.BindingHash) != len(bindingHash) || subtle.ConstantTimeCompare([]byte(record.BindingHash), []byte(bindingHash)) != 1 {
		return storedLoginAttempt{}, errNotFound
	}
	s.deleteLoginAttempt(record)
	return record, nil
}

type loginAttemptScope struct {
	EnterpriseID string
	ClientID     string
}

type loginAttemptBrowserScope struct {
	loginAttemptScope
	BrowserIDHash string
}

type loginAttemptExpiryItem struct {
	ExpiresAt  time.Time
	StateHash  string
	Generation uint64
}

type loginAttemptExpiryHeap []loginAttemptExpiryItem

func (h loginAttemptExpiryHeap) Len() int { return len(h) }
func (h loginAttemptExpiryHeap) Less(i, j int) bool {
	if h[i].ExpiresAt.Equal(h[j].ExpiresAt) {
		return h[i].StateHash < h[j].StateHash
	}
	return h[i].ExpiresAt.Before(h[j].ExpiresAt)
}
func (h loginAttemptExpiryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *loginAttemptExpiryHeap) Push(value any) {
	*h = append(*h, value.(loginAttemptExpiryItem))
}
func (h *loginAttemptExpiryHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func (s *MemoryStore) expireLoginAttempts(now time.Time) {
	for s.loginAttemptExpiry.Len() > 0 && !now.Before(s.loginAttemptExpiry[0].ExpiresAt) {
		item := heap.Pop(&s.loginAttemptExpiry).(loginAttemptExpiryItem)
		record, ok := s.loginAttempts[item.StateHash]
		if !ok || s.loginAttemptGeneration[item.StateHash] != item.Generation || !record.ExpiresAt.Equal(item.ExpiresAt) {
			continue
		}
		s.deleteLoginAttempt(record)
	}
}

func (s *MemoryStore) deleteLoginAttempt(record storedLoginAttempt) {
	delete(s.loginAttempts, record.StateHash)
	delete(s.loginAttemptGeneration, record.StateHash)
	scope := loginAttemptScope{EnterpriseID: record.EnterpriseID, ClientID: record.ClientID}
	browser := loginAttemptBrowserScope{loginAttemptScope: scope, BrowserIDHash: record.BrowserIDHash}
	decrementLoginAttemptCount(s.scopeCounts, scope)
	decrementLoginAttemptCount(s.browserCounts, browser)
}

func decrementLoginAttemptCount[K comparable](counts map[K]int, key K) {
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key]--
}

func (s *MemoryStore) loginAttemptSnapshot() map[string]storedLoginAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]storedLoginAttempt, len(s.loginAttempts))
	for k, v := range s.loginAttempts {
		out[k] = v
	}
	return out
}

func (s *MemoryStore) AddEnterpriseUser(enterpriseID, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[bindingKey(enterpriseID, userID)] = struct{}{}
}

func (s *MemoryStore) EnterpriseUserBindingExists(ctx context.Context, enterpriseID, userID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.users[bindingKey(enterpriseID, userID)]
	return ok, nil
}

func (s *MemoryStore) CreateSession(ctx context.Context, session storedSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	if _, ok := s.users[bindingKey(session.EnterpriseID, session.UserID)]; !ok {
		return errInvalidBinding
	}
	if _, ok := s.sessions[session.IDHash]; ok {
		return errDuplicate
	}
	s.sessions[session.IDHash] = session
	return nil
}

func (s *MemoryStore) UseSession(ctx context.Context, idHash string, now time.Time, idleTimeout time.Duration) (storedSession, error) {
	if err := ctx.Err(); err != nil {
		return storedSession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return storedSession{}, err
	}
	if s.err != nil {
		return storedSession{}, s.err
	}
	record, ok := s.sessions[idHash]
	if !ok || record.RevokedAt != nil || !now.Before(record.IdleExpiresAt) || !now.Before(record.AbsoluteExpiresAt) {
		return storedSession{}, errNotFound
	}
	record.LastSeenAt = now
	record.IdleExpiresAt = minTime(now.Add(idleTimeout), record.AbsoluteExpiresAt)
	s.sessions[idHash] = record
	return record, nil
}

func (s *MemoryStore) RevokeSession(ctx context.Context, idHash string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	record, ok := s.sessions[idHash]
	if !ok {
		return errNotFound
	}
	if record.RevokedAt == nil {
		revoked := now
		record.RevokedAt = &revoked
		s.sessions[idHash] = record
	}
	return nil
}

func (s *MemoryStore) RevokeAndGetSession(ctx context.Context, idHash string, now time.Time) (storedSession, error) {
	if err := ctx.Err(); err != nil {
		return storedSession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return storedSession{}, err
	}
	if s.err != nil {
		return storedSession{}, s.err
	}
	record, ok := s.sessions[idHash]
	if !ok || record.RevokedAt != nil || !now.Before(record.IdleExpiresAt) || !now.Before(record.AbsoluteExpiresAt) {
		return storedSession{}, errNotFound
	}
	revoked := now
	record.RevokedAt = &revoked
	s.sessions[idHash] = record
	return record, nil
}

func (s *MemoryStore) CreateAuthorizationCode(ctx context.Context, code storedAuthorizationCode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.err != nil {
		return s.err
	}
	if _, ok := s.users[bindingKey(code.EnterpriseID, code.UserID)]; !ok {
		return errInvalidBinding
	}
	session, ok := s.sessions[code.BrowserSessionIDHash]
	if !ok || session.RevokedAt != nil || session.EnterpriseID != code.EnterpriseID || session.UserID != code.UserID {
		return errInvalidBinding
	}
	if _, ok := s.codes[code.CodeHash]; ok {
		return errDuplicate
	}
	s.codes[code.CodeHash] = code
	return nil
}

func (s *MemoryStore) ExchangeAuthorizationCode(ctx context.Context, request exchangeRequest) (storedAuthorizationCode, error) {
	if err := ctx.Err(); err != nil {
		return storedAuthorizationCode{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return storedAuthorizationCode{}, err
	}
	if s.err != nil {
		return storedAuthorizationCode{}, s.err
	}
	record, ok := s.codes[request.CodeHash]
	if !ok || record.ConsumedAt != nil || !request.Now.Before(record.ExpiresAt) || record.ClientID != request.ClientID || record.RedirectURI != request.RedirectURI {
		return storedAuthorizationCode{}, errNotFound
	}
	if _, exists := s.accessTokens[request.AccessTokenHash]; exists {
		return storedAuthorizationCode{}, errDuplicate
	}
	session, ok := s.sessions[record.BrowserSessionIDHash]
	if !ok || session.RevokedAt != nil || !request.Now.Before(session.IdleExpiresAt) || !request.Now.Before(session.AbsoluteExpiresAt) {
		return storedAuthorizationCode{}, errNotFound
	}
	expiresAt := session.AbsoluteExpiresAt
	if !expiresAt.After(request.Now) || request.AccessTokenHash == "" || request.Audience == "" {
		return storedAuthorizationCode{}, errNotFound
	}
	challenge, err := base64.RawURLEncoding.DecodeString(record.CodeChallenge)
	if err != nil || len(challenge) != len(request.VerifierDigest) || subtle.ConstantTimeCompare(challenge, request.VerifierDigest[:]) != 1 {
		return storedAuthorizationCode{}, errNotFound
	}
	consumed := request.Now
	record.ConsumedAt = &consumed
	s.codes[request.CodeHash] = record
	s.accessTokens[request.AccessTokenHash] = storedAccessToken{TokenHash: request.AccessTokenHash, BrowserSessionIDHash: record.BrowserSessionIDHash, EnterpriseID: record.EnterpriseID, UserID: record.UserID, ClientID: record.ClientID, Audience: request.Audience, CreatedAt: request.Now, ExpiresAt: expiresAt}
	record.AccessTokenExpiresAt = expiresAt
	return record, nil
}

func (s *MemoryStore) UseAccessToken(ctx context.Context, tokenHash, clientID, audience, enterpriseID string, now time.Time) (storedAccessToken, error) {
	if err := ctx.Err(); err != nil {
		return storedAccessToken{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return storedAccessToken{}, s.err
	}
	record, ok := s.accessTokens[tokenHash]
	session, sessionOK := s.sessions[record.BrowserSessionIDHash]
	if !ok || !sessionOK || record.RevokedAt != nil || session.RevokedAt != nil || record.ClientID != clientID || record.Audience != audience || record.EnterpriseID != enterpriseID || record.EnterpriseID != session.EnterpriseID || record.UserID != session.UserID || !now.Before(record.ExpiresAt) || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		return storedAccessToken{}, errNotFound
	}
	session.LastSeenAt = now
	session.IdleExpiresAt = minTime(now.Add(defaultIdleTimeout), session.AbsoluteExpiresAt)
	s.sessions[session.IDHash] = session
	record.SessionCreatedAt = session.CreatedAt
	record.SessionLastSeenAt = session.LastSeenAt
	record.SessionIdleExpiresAt = session.IdleExpiresAt
	record.SessionAbsoluteExpiresAt = session.AbsoluteExpiresAt
	return record, nil
}

func (s *MemoryStore) RevokeSessionByAccessToken(ctx context.Context, tokenHash, clientID, audience, enterpriseID string, now time.Time) (storedSession, error) {
	if err := ctx.Err(); err != nil {
		return storedSession{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return storedSession{}, s.err
	}
	token, ok := s.accessTokens[tokenHash]
	session, sessionOK := s.sessions[token.BrowserSessionIDHash]
	if !ok || !sessionOK || token.ClientID != clientID || token.Audience != audience || token.EnterpriseID != enterpriseID || token.RevokedAt != nil || !now.Before(token.ExpiresAt) || (session.RevokedAt == nil && (!now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt))) {
		return storedSession{}, errNotFound
	}
	if session.RevokedAt == nil {
		revoked := now
		session.RevokedAt = &revoked
	}
	s.sessions[session.IDHash] = session
	return session, nil
}

func (s *MemoryStore) accessTokenSnapshot() map[string]storedAccessToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]storedAccessToken, len(s.accessTokens))
	for k, v := range s.accessTokens {
		out[k] = v
	}
	return out
}

func (s *MemoryStore) sessionSnapshot() map[string]storedSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]storedSession, len(s.sessions))
	for k, v := range s.sessions {
		out[k] = v
	}
	return out
}
func (s *MemoryStore) codeSnapshot() map[string]storedAuthorizationCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]storedAuthorizationCode, len(s.codes))
	for k, v := range s.codes {
		out[k] = v
	}
	return out
}
func bindingKey(enterpriseID, userID string) string { return enterpriseID + "\x00" + userID }
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
