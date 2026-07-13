// Package agenttrust is the GA Task 0C Agent-client trust registry. It records
// registered Agent clients, immutable certification revisions and append-only,
// hash-chained certification status changes, and resolves the effective trust
// class and capability ceiling of a presented release.
//
// Trust layering. This registry is the TRUST-REGISTRY layer that composes with
// the credential-derived trust context (internal/trust, GA Task 0B) and the
// neutral capability policy (internal/policy, GA Task 0B):
//
//   - an unknown Agent defaults to untrusted and may only exercise an
//     explicitly-opened low-risk READ; an untrusted or uncertified decision can
//     never reach a side effect;
//   - first-party status requires BOTH a signed build manifest AND enterprise
//     registration — a name-only claim never yields first_party_trusted;
//   - a customer policy may NARROW the certified capability ceiling but never
//     raise it;
//   - AstraClaw/Xiaozhi clients receive ZERO enterprise connector capability
//     even when first-party signed (the connector class is stripped from the
//     effective ceiling using the single source of truth,
//     policy.IsConnectorCapability);
//   - a certified third party requires a certified Policy Decision Provider to
//     reach a side effect (the provider persistence/decision flow itself is GA
//     Task 0F; 0C models the trust-class requirement and capability ceiling).
package agenttrust

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// Origin classifications mirror internal/trust: AstraClaw/Xiaozhi origins can
// only LOWER capability and never carry enterprise connector capability.
const (
	OriginAstraClaw = "astraclaw"
	OriginXiaozhi   = "xiaozhi"
)

// certificationStatusHashDomain domain-separates the append-only status hash
// chain (mirrors the credential hash domains in internal/tickets).
const certificationStatusHashDomain = "agentnexus:agent-certification-status:v1:"

// Errors.
var (
	// ErrUntrusted is not an error path of Assess (which returns an untrusted
	// assessment); it names the untrusted default for callers that want a
	// sentinel.
	ErrUntrusted = errors.New("agent client untrusted")
	// ErrCertificationRejected marks a certification that fails its issuance
	// preconditions (missing signed manifest, missing enterprise registration
	// for first party, unregistered client, invalid binding, or an attempt to
	// mutate an immutable revision).
	ErrCertificationRejected = errors.New("certification rejected")
	// ErrInvalidInput marks malformed registry input.
	ErrInvalidInput = errors.New("invalid trust registry input")
	// ErrNotFound marks a missing certification.
	ErrNotFound = errors.New("certification not found")
	// ErrRegistryUnavailable marks a persistence outage; callers fail closed.
	ErrRegistryUnavailable = errors.New("trust registry unavailable")
)

// AgentClient is a registered Agent client. Enterprise registration and the
// AstraClaw/Xiaozhi origin are recorded at registration time.
type AgentClient struct {
	ID                   string
	TenantRef            string
	Publisher            string
	Product              string
	Origin               string
	EnterpriseRegistered bool
	CreatedAt            time.Time
}

// Certification is an IMMUTABLE certification revision. Its status evolves only
// through append-only StatusChange rows.
type Certification struct {
	ID            string
	TenantRef     string
	AgentClientID string
	// Origin is FROZEN from the client at certify time. Assess strips connector
	// capabilities when this OR the live/presented origin is AstraClaw/Xiaozhi,
	// so a later re-registration can only ever STRENGTHEN the denial.
	Origin   string
	Revision int64
	Binding  runtime.CertificationBinding
	// SignedBuildManifest records that a signed build manifest was attested for
	// this certification. In the wired gateway it is set true only AFTER the
	// handler verifies the manifest_signature against the certified signing_key
	// (that verification is a later handler task); the trust registry treats it
	// as the attested fact, not as proof it re-verifies here.
	SignedBuildManifest       bool
	EnterpriseRegistered      bool
	CertifiedDecisionProvider bool
	IssuedAt                  time.Time
	ExpiresAt                 time.Time
	CreatedAt                 time.Time
}

// CertificationStatus is the append-only status vocabulary.
type CertificationStatus string

const (
	StatusActive     CertificationStatus = "active"
	StatusRevoked    CertificationStatus = "revoked"
	StatusExpired    CertificationStatus = "expired"
	StatusSuperseded CertificationStatus = "superseded"
)

func (s CertificationStatus) valid() bool {
	switch s {
	case StatusActive, StatusRevoked, StatusExpired, StatusSuperseded:
		return true
	}
	return false
}

// StatusChange is one append-only, hash-chained certification status row. Seq
// is the store-assigned strictly monotonic order used to resolve "latest".
type StatusChange struct {
	ID              string
	TenantRef       string
	CertificationID string
	Status          CertificationStatus
	Reason          string
	PrevHash        string
	EventHash       string
	Seq             int64
	CreatedAt       time.Time
}

// hashStatusChange computes the tamper-evident event hash of a status change
// chained onto prevHash. Every field is LENGTH-PREFIXED (not delimiter-joined)
// so no field's content — including a stray delimiter or, historically, a NUL
// in a caller-supplied reason — can shift a field boundary and forge a
// colliding preimage.
func hashStatusChange(tenantRef, certificationID string, status CertificationStatus, reason, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(certificationStatusHashDomain))
	for _, field := range []string{tenantRef, certificationID, string(status), reason, prevHash} {
		var lengthPrefix [8]byte
		binary.BigEndian.PutUint64(lengthPrefix[:], uint64(len(field)))
		h.Write(lengthPrefix[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hasControlBytes reports whether s contains any ASCII control byte (0x00-0x1f
// or 0x7f). A control byte in a persisted reason is rejected in Go and by a DB
// CHECK: it is both a NUL hazard and a hash-preimage/log-injection vector.
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// Store is the persistence port of the trust registry. The store OWNS the
// hash-chain and revision integrity: it assigns each revision number, chains
// every status hash and supersedes prior active revisions inside one atomic
// unit, so concurrent certification and revocation stay linearizable.
type Store interface {
	CreateAgentClient(ctx context.Context, client AgentClient) (AgentClient, error)
	GetAgentClient(ctx context.Context, tenantRef, publisher, product string) (AgentClient, error)
	// CreateCertification persists an immutable revision atomically: it assigns
	// the next revision number, writes the initial active status (a fresh hash
	// chain) and supersedes every prior active revision of the same
	// (tenant, publisher, product). statusID mints one opaque id per status row.
	// Re-creating an existing revision id is rejected.
	CreateCertification(ctx context.Context, cert Certification, statusID func() string, now time.Time) (Certification, error)
	ListCertifications(ctx context.Context, tenantRef, publisher, product string) ([]Certification, error)
	LatestStatus(ctx context.Context, tenantRef, certificationID string) (StatusChange, error)
	// AppendStatus atomically chains a status change onto a certification: it
	// reads the latest event hash under a lock, computes the chained hash and
	// inserts the new row. A missing certification yields ErrNotFound.
	AppendStatus(ctx context.Context, tenantRef, certificationID string, status CertificationStatus, reason, statusID string, now time.Time) (StatusChange, error)
}

func canonical(value string) bool { return value != "" && strings.TrimSpace(value) == value }

func randomOpaqueID(prefix string) string {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}

// MemoryStore is the in-memory Store used by unit tests and harnesses.
type MemoryStore struct {
	mu       sync.RWMutex
	clients  map[string]AgentClient
	certs    map[string]Certification
	statuses map[string][]StatusChange
	seq      int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:  map[string]AgentClient{},
		certs:    map[string]Certification{},
		statuses: map[string][]StatusChange{},
	}
}

func clientKey(tenantRef, publisher, product string) string {
	return tenantRef + "\x00" + publisher + "\x00" + product
}

func certKey(tenantRef, certificationID string) string {
	return tenantRef + "\x00" + certificationID
}

func (s *MemoryStore) CreateAgentClient(_ context.Context, client AgentClient) (AgentClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := clientKey(client.TenantRef, client.Publisher, client.Product)
	if existing, ok := s.clients[key]; ok {
		// Re-registration keeps the stable identity and creation time.
		client.ID = existing.ID
		client.CreatedAt = existing.CreatedAt
	}
	s.clients[key] = client
	return client, nil
}

func (s *MemoryStore) GetAgentClient(_ context.Context, tenantRef, publisher, product string) (AgentClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[clientKey(tenantRef, publisher, product)]
	if !ok {
		return AgentClient{}, ErrNotFound
	}
	return client, nil
}

func (s *MemoryStore) CreateCertification(_ context.Context, cert Certification, statusID func() string, now time.Time) (Certification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := certKey(cert.TenantRef, cert.ID)
	if _, exists := s.certs[key]; exists {
		return Certification{}, ErrCertificationRejected
	}
	// Assign the next revision and supersede prior active revisions of the same
	// (tenant, publisher, product), all in one critical section.
	var priorActive []string
	maxRevision := int64(0)
	for otherKey, other := range s.certs {
		if other.TenantRef != cert.TenantRef || other.Binding.Publisher != cert.Binding.Publisher || other.Binding.Product != cert.Binding.Product {
			continue
		}
		if other.Revision > maxRevision {
			maxRevision = other.Revision
		}
		if log := s.statuses[otherKey]; len(log) > 0 && log[len(log)-1].Status == StatusActive {
			priorActive = append(priorActive, otherKey)
		}
	}
	cert.Revision = maxRevision + 1
	for _, otherKey := range priorActive {
		log := s.statuses[otherKey]
		prev := log[len(log)-1]
		s.statuses[otherKey] = append(log, s.chained(prev.TenantRef, prev.CertificationID, StatusSuperseded, "superseded by "+cert.ID, statusID(), now))
	}
	s.certs[key] = cert
	s.statuses[key] = []StatusChange{s.chained(cert.TenantRef, cert.ID, StatusActive, "certified", statusID(), now)}
	return cert, nil
}

// chained builds a hash-chained status change onto the current log tail. The
// caller holds s.mu; PrevHash is read from the persisted tail, never from a
// stale external value.
func (s *MemoryStore) chained(tenantRef, certificationID string, status CertificationStatus, reason, statusID string, now time.Time) StatusChange {
	prev := ""
	if log := s.statuses[certKey(tenantRef, certificationID)]; len(log) > 0 {
		prev = log[len(log)-1].EventHash
	}
	s.seq++
	return StatusChange{
		ID:              statusID,
		TenantRef:       tenantRef,
		CertificationID: certificationID,
		Status:          status,
		Reason:          reason,
		PrevHash:        prev,
		EventHash:       hashStatusChange(tenantRef, certificationID, status, reason, prev),
		Seq:             s.seq,
		CreatedAt:       now,
	}
}

func (s *MemoryStore) ListCertifications(_ context.Context, tenantRef, publisher, product string) ([]Certification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Certification
	for _, cert := range s.certs {
		if cert.TenantRef == tenantRef && cert.Binding.Publisher == publisher && cert.Binding.Product == product {
			out = append(out, cert)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Revision > out[j].Revision })
	return out, nil
}

func (s *MemoryStore) LatestStatus(_ context.Context, tenantRef, certificationID string) (StatusChange, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	log := s.statuses[certKey(tenantRef, certificationID)]
	if len(log) == 0 {
		return StatusChange{}, ErrNotFound
	}
	return log[len(log)-1], nil
}

func (s *MemoryStore) AppendStatus(_ context.Context, tenantRef, certificationID string, status CertificationStatus, reason, statusID string, now time.Time) (StatusChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !status.valid() {
		return StatusChange{}, ErrInvalidInput
	}
	key := certKey(tenantRef, certificationID)
	if _, ok := s.certs[key]; !ok {
		return StatusChange{}, ErrNotFound
	}
	change := s.chained(tenantRef, certificationID, status, reason, statusID, now)
	s.statuses[key] = append(s.statuses[key], change)
	return change, nil
}

// StatusChanges returns the append-only status log of a certification (test
// observability; the log is never mutated in place).
func (s *MemoryStore) StatusChanges(tenantRef, certificationID string) []StatusChange {
	s.mu.RLock()
	defer s.mu.RUnlock()
	log := s.statuses[certKey(tenantRef, certificationID)]
	return append([]StatusChange(nil), log...)
}
