package browserauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

type MemoryStore struct {
	mu            sync.Mutex
	users         map[string]struct{}
	sessions      map[string]storedSession
	codes         map[string]storedAuthorizationCode
	loginAttempts map[string]storedLoginAttempt
	err           error
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: map[string]struct{}{}, sessions: map[string]storedSession{}, codes: map[string]storedAuthorizationCode{}, loginAttempts: map[string]storedLoginAttempt{}}
}

func (s *MemoryStore) CreateLoginAttempt(ctx context.Context, attempt storedLoginAttempt) error {
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
	for key, record := range s.loginAttempts {
		if !attempt.CreatedAt.Before(record.ExpiresAt) {
			delete(s.loginAttempts, key)
		}
	}
	count := 0
	for _, record := range s.loginAttempts {
		if record.EnterpriseID == attempt.EnterpriseID && record.ClientID == attempt.ClientID {
			count++
		}
	}
	if count >= maxLoginAttempts {
		return errLoginAttemptLimited
	}
	if _, ok := s.loginAttempts[attempt.StateHash]; ok {
		return errDuplicate
	}
	s.loginAttempts[attempt.StateHash] = attempt
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
		delete(s.loginAttempts, stateHash)
		return storedLoginAttempt{}, errNotFound
	}
	if len(record.BindingHash) != len(bindingHash) || subtle.ConstantTimeCompare([]byte(record.BindingHash), []byte(bindingHash)) != 1 {
		return storedLoginAttempt{}, errNotFound
	}
	delete(s.loginAttempts, stateHash)
	return record, nil
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
	challenge, err := base64.RawURLEncoding.DecodeString(record.CodeChallenge)
	if err != nil || len(challenge) != len(request.VerifierDigest) || subtle.ConstantTimeCompare(challenge, request.VerifierDigest[:]) != 1 {
		return storedAuthorizationCode{}, errNotFound
	}
	consumed := request.Now
	record.ConsumedAt = &consumed
	s.codes[request.CodeHash] = record
	return record, nil
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
