package browserauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

type MemoryStore struct {
	mu       sync.Mutex
	users    map[string]struct{}
	sessions map[string]storedSession
	codes    map[string]storedAuthorizationCode
	err      error
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: map[string]struct{}{}, sessions: map[string]storedSession{}, codes: map[string]storedAuthorizationCode{}}
}

func (s *MemoryStore) AddEnterpriseUser(enterpriseID, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[bindingKey(enterpriseID, userID)] = struct{}{}
}

func (s *MemoryStore) EnterpriseUserBindingExists(_ context.Context, enterpriseID, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	_, ok := s.users[bindingKey(enterpriseID, userID)]
	return ok, nil
}

func (s *MemoryStore) CreateSession(_ context.Context, session storedSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if _, ok := s.users[bindingKey(session.EnterpriseID, session.UserID)]; !ok {
		return errInvalidBinding
	}
	s.sessions[session.IDHash] = session
	return nil
}

func (s *MemoryStore) UseSession(_ context.Context, idHash string, now time.Time, idleTimeout time.Duration) (storedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *MemoryStore) RevokeSession(_ context.Context, idHash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *MemoryStore) CreateAuthorizationCode(_ context.Context, code storedAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if _, ok := s.users[bindingKey(code.EnterpriseID, code.UserID)]; !ok {
		return errInvalidBinding
	}
	s.codes[code.CodeHash] = code
	return nil
}

func (s *MemoryStore) ExchangeAuthorizationCode(_ context.Context, request exchangeRequest) (storedAuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
