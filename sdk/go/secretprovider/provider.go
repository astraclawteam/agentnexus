package secretprovider

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
)

// MaxHandleTTL bounds how long any Secret Handle can live. Handles are
// short-lived by contract; a longer requested TTL is clamped, never honored.
const MaxHandleTTL = 15 * time.Minute

// handleMaterialDomain domain-separates derived operation material so it can
// never collide with hashes computed for another purpose.
const handleMaterialDomain = "agentnexus:secret-handle:v1:"

// Provider is the authenticated local Secret Provider protocol. The same
// contract is satisfied by the in-process reference LocalProvider and by a
// transport client that speaks it over an authenticated local socket, named
// pipe or loopback connection: the interface abstracts the transport.
type Provider interface {
	// AcquireHandle authenticates the caller and issues an operation-scoped,
	// short-lived Secret Handle for the referenced master credential. It never
	// returns a master credential.
	AcquireHandle(ctx context.Context, req AcquireRequest) (Handle, error)
	// Redeem authenticates the caller and exchanges a handle for its derived,
	// operation-scoped material, enforcing scope, version, expiry and single-use.
	Redeem(ctx context.Context, req RedeemRequest) (Secret, error)
	// Ping reports provider reachability so a client can fail closed on outage.
	Ping(ctx context.Context) error
}

// AcquireRequest asks the provider to mint a handle. CallerToken is the local
// authentication secret; it is never stored in the issued handle.
type AcquireRequest struct {
	CallerToken   string        `json:"caller_token"`
	Scope         Scope         `json:"scope"`
	CredentialRef string        `json:"credential_ref"`
	TTL           time.Duration `json:"ttl"`
	SingleUse     bool          `json:"single_use"`
}

// RedeemRequest asks the provider to reveal a handle's material. Scope must
// match the handle's issued scope exactly.
type RedeemRequest struct {
	CallerToken string `json:"caller_token"`
	HandleID    string `json:"handle_id"`
	Scope       Scope  `json:"scope"`
}

// LocalProvider is the reference in-process Secret Provider. It holds master
// credentials, authenticates callers, mints operation-scoped handles, derives
// non-reversible material, and supports rotation and revocation. The master
// credentials never leave it: neither a Handle nor a redeemed Secret carries a
// master value.
type LocalProvider struct {
	mu          sync.Mutex
	callerToken string
	now         func() time.Time
	masters     map[string]*masterRecord
	handles     map[string]*handleRecord
}

type masterRecord struct {
	versions  []*versionRecord
	currentID string
}

type versionRecord struct {
	id      string
	value   string
	revoked bool
}

type handleRecord struct {
	scope         Scope
	credentialRef string
	versionID     string
	material      string
	expiresAt     time.Time
	singleUse     bool
	consumed      bool
}

// LocalOption configures a LocalProvider.
type LocalOption func(*LocalProvider)

// WithCallerToken sets the local authentication token callers must present.
func WithCallerToken(token string) LocalOption {
	return func(p *LocalProvider) { p.callerToken = token }
}

// WithClock overrides the provider clock (for deterministic tests).
func WithClock(clock func() time.Time) LocalOption {
	return func(p *LocalProvider) { p.now = clock }
}

// NewLocalProvider builds an in-process reference provider.
func NewLocalProvider(opts ...LocalOption) *LocalProvider {
	p := &LocalProvider{
		now:     func() time.Time { return time.Now().UTC() },
		masters: map[string]*masterRecord{},
		handles: map[string]*handleRecord{},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// SetMaster seeds an initial master credential and returns its version id. Use
// Rotate to replace an existing credential; SetMaster refuses to overwrite one.
func (p *LocalProvider) SetMaster(credentialRef, master string) (string, error) {
	if !canonical(credentialRef) || master == "" {
		return "", ErrInvalidRequest
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.masters[credentialRef]; exists {
		return "", ErrInvalidRequest
	}
	versionID, err := randomToken()
	if err != nil {
		return "", ErrProviderUnavailable
	}
	version := &versionRecord{id: versionID, value: master}
	p.masters[credentialRef] = &masterRecord{versions: []*versionRecord{version}, currentID: versionID}
	return versionID, nil
}

// Rotate installs a new master version and revokes every prior version. Handles
// bound to a retired version fail closed on redeem; new handles bind the new
// version.
func (p *LocalProvider) Rotate(credentialRef, master string) (string, error) {
	if !canonical(credentialRef) || master == "" {
		return "", ErrInvalidRequest
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	record, ok := p.masters[credentialRef]
	if !ok {
		return "", ErrUnknownCredential
	}
	versionID, err := randomToken()
	if err != nil {
		return "", ErrProviderUnavailable
	}
	for _, version := range record.versions {
		version.revoked = true
	}
	record.versions = append(record.versions, &versionRecord{id: versionID, value: master})
	record.currentID = versionID
	return versionID, nil
}

// Revoke marks one master version revoked. Outstanding handles bound to it fail
// closed on redeem.
func (p *LocalProvider) Revoke(credentialRef, versionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	record, ok := p.masters[credentialRef]
	if !ok {
		return ErrUnknownCredential
	}
	for _, version := range record.versions {
		if version.id == versionID {
			version.revoked = true
			if record.currentID == versionID {
				record.currentID = latestLiveVersion(record)
			}
			return nil
		}
	}
	return ErrInvalidRequest
}

// AcquireHandle implements Provider.
func (p *LocalProvider) AcquireHandle(ctx context.Context, req AcquireRequest) (Handle, error) {
	if err := ctx.Err(); err != nil {
		return Handle{}, ErrProviderUnavailable
	}
	if !p.authenticate(req.CallerToken) {
		return Handle{}, ErrUnauthenticated
	}
	if !req.Scope.valid() || !canonical(req.CredentialRef) || req.TTL <= 0 {
		return Handle{}, ErrInvalidRequest
	}
	ttl := req.TTL
	if ttl > MaxHandleTTL {
		ttl = MaxHandleTTL
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	// Lazy reclamation: drop every expired (and expired-consumed) record so the
	// store can never grow unbounded across acquisitions that are never redeemed.
	p.sweepExpired(now)
	record, ok := p.masters[req.CredentialRef]
	if !ok {
		return Handle{}, ErrUnknownCredential
	}
	// A known credential whose every version has been revoked (or rotated away)
	// is a revocation, not an unknown credential: report it distinctly.
	current := record.version(record.currentID)
	if record.currentID == "" || current == nil || current.revoked {
		return Handle{}, ErrRevokedVersion
	}
	handleID, err := randomToken()
	if err != nil {
		return Handle{}, ErrProviderUnavailable
	}
	nonce, err := randomToken()
	if err != nil {
		return Handle{}, ErrProviderUnavailable
	}
	material, err := deriveMaterial(current.value, req.CredentialRef, current.id, req.Scope, nonce)
	if err != nil {
		return Handle{}, ErrProviderUnavailable
	}
	handle, err := newHandle(handleID, req.Scope, current.id, now, now.Add(ttl), req.SingleUse)
	if err != nil {
		return Handle{}, err
	}
	p.handles[handleID] = &handleRecord{
		scope:         req.Scope,
		credentialRef: req.CredentialRef,
		versionID:     current.id,
		material:      material,
		expiresAt:     now.Add(ttl),
		singleUse:     req.SingleUse,
	}
	return handle, nil
}

// Redeem implements Provider.
func (p *LocalProvider) Redeem(ctx context.Context, req RedeemRequest) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, ErrProviderUnavailable
	}
	if !p.authenticate(req.CallerToken) {
		return Secret{}, ErrUnauthenticated
	}
	if !canonical(req.HandleID) || !req.Scope.valid() {
		return Secret{}, ErrInvalidRequest
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	record, ok := p.handles[req.HandleID]
	if !ok {
		return Secret{}, ErrInvalidHandle
	}
	// Connector identity + operation scope must match exactly. A handle issued
	// for connector A replayed under connector B is rejected here.
	if !record.scope.equal(req.Scope) {
		return Secret{}, ErrScopeMismatch
	}
	// The bound master version must still be live (not revoked or rotated away).
	if master, ok := p.masters[record.credentialRef]; !ok {
		return Secret{}, ErrRevokedVersion
	} else if version := master.version(record.versionID); version == nil || version.revoked {
		return Secret{}, ErrRevokedVersion
	}
	if !p.now().Before(record.expiresAt) {
		delete(p.handles, req.HandleID)
		return Secret{}, ErrHandleExpired
	}
	if record.singleUse {
		if record.consumed {
			return Secret{}, ErrHandleConsumed
		}
		// Consume once: drop the derived material immediately so it never
		// lingers in the store, and leave a material-free consumed tombstone so
		// a replay is reported as ErrHandleConsumed (not indistinguishable from
		// an unknown handle). The tombstone is reclaimed by sweepExpired at TTL.
		record.consumed = true
		material := record.material
		record.material = ""
		return newSecret(material), nil
	}
	return newSecret(record.material), nil
}

// sweepExpired drops every handle record whose TTL has elapsed. Callers must
// hold p.mu. It bounds the handle store to the acquisitions made within one TTL
// window even when handles are acquired but never redeemed (the wired connector
// runtime path acquires only), and clears any derived material those records
// still hold.
func (p *LocalProvider) sweepExpired(now time.Time) {
	for id, record := range p.handles {
		if !now.Before(record.expiresAt) {
			delete(p.handles, id)
		}
	}
}

// OutstandingHandles reports the number of handle records currently retained. It
// exists for tests and operational introspection; it exposes no secret material.
func (p *LocalProvider) OutstandingHandles() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.handles)
}

// Ping implements Provider: the in-process reference provider is always
// reachable.
func (p *LocalProvider) Ping(ctx context.Context) error {
	return ctx.Err()
}

func (p *LocalProvider) authenticate(token string) bool {
	return p.callerToken != "" && constantTimeEqual(token, p.callerToken)
}

func (r *masterRecord) version(id string) *versionRecord {
	for _, version := range r.versions {
		if version.id == id {
			return version
		}
	}
	return nil
}

func latestLiveVersion(record *masterRecord) string {
	for i := len(record.versions) - 1; i >= 0; i-- {
		if !record.versions[i].revoked {
			return record.versions[i].id
		}
	}
	return ""
}

// deriveMaterial produces operation-scoped material by using the master as the
// HKDF key (never as a hashed input) and binding the output to the credential
// reference, the exact master version, the scope and a per-handle nonce through
// a structured, length-prefixed context. The master is the key material; the
// output is a fresh 32-byte key that is a one-way function of the master and
// cannot be reversed to it.
func deriveMaterial(master, credentialRef, versionID string, scope Scope, nonce string) (string, error) {
	key, err := hkdf.Key(
		sha256.New,
		[]byte(master),
		[]byte(handleMaterialDomain),
		string(kdfContext(credentialRef, versionID, scope, nonce)),
		32,
	)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// kdfContext frames the derivation context with an unambiguous, length-prefixed
// encoding (4-byte big-endian length before each field). Length-prefixing keeps
// the binding injective regardless of the field contents, so no two distinct
// (credential, version, scope, nonce) tuples can ever produce the same context.
func kdfContext(credentialRef, versionID string, scope Scope, nonce string) []byte {
	var buf bytes.Buffer
	for _, field := range []string{credentialRef, versionID, scope.ConnectorRef, scope.Resource, scope.Operation, scope.Action, nonce} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		buf.Write(length[:])
		buf.WriteString(field)
	}
	return buf.Bytes()
}

func randomToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// UnavailableProvider returns a Provider that fails closed on every call. It
// models a configured-but-unreachable Secret Provider so callers can prove they
// never fall back to plaintext or cached-master credentials.
func UnavailableProvider() Provider { return unavailableProvider{} }

type unavailableProvider struct{}

func (unavailableProvider) AcquireHandle(context.Context, AcquireRequest) (Handle, error) {
	return Handle{}, ErrProviderUnavailable
}

func (unavailableProvider) Redeem(context.Context, RedeemRequest) (Secret, error) {
	return Secret{}, ErrProviderUnavailable
}

func (unavailableProvider) Ping(context.Context) error { return ErrProviderUnavailable }
