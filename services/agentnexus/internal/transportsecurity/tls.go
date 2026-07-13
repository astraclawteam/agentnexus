// Package transportsecurity is the runtime plane of the AgentNexus mTLS
// lifecycle. It loads the PKI-produced material (identity certificate and
// key, signed trust bundle, signed CRL, pinned bundle-authority key),
// enforces the single public TLS profile from
// sdk/go/transportsecurity on every listener and client, hot-reloads
// material with anti-rollback, and rebuilds connection pools on every trust
// rotation so that a revoked identity is never silently kept alive.
//
// Anti-rollback state (last accepted trust-bundle sequence and CRL number)
// is tracked per process against the currently loaded material: a reload
// that presents an older signed artifact is rejected and the current
// material stays in force. Across restarts the deployed files themselves are
// the anchor; distributing stale files is prevented by the signed sequence
// check at the management plane and audited operationally.
package transportsecurity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
)

// Mode is the resolved transport mode of a service at startup.
type Mode int

const (
	// ModePlaintext is the development default when no TLS material is
	// configured. Production never runs in this mode.
	ModePlaintext Mode = iota
	// ModeMutualTLS serves and dials under the single mTLS profile.
	ModeMutualTLS
)

var (
	// ErrProductionRequiresMTLS is returned when AGENTNEXUS_ENV=production
	// starts without complete TLS material: production fails closed.
	ErrProductionRequiresMTLS = errors.New("transportsecurity: production requires complete mTLS material")
	// ErrIncompleteTLSMaterial is returned when TLS material is partially
	// configured in any environment: never silently downgrade to plaintext.
	ErrIncompleteTLSMaterial = errors.New("transportsecurity: TLS material is partially configured")
	// ErrPlaintextRefused is returned by the pooled HTTP client for any
	// non-https request.
	ErrPlaintextRefused = errors.New("transportsecurity: refusing plaintext (non-https) request under the mTLS profile")
)

// ResolveStartupMode decides the transport mode from the environment and the
// configured TLS material. Complete material always activates mTLS; partial
// material is always a startup error; production without complete material
// fails closed.
func ResolveStartupMode(environment string, settings config.TLSSettings) (Mode, error) {
	if settings.Complete() {
		return ModeMutualTLS, nil
	}
	if environment == "production" {
		return ModePlaintext, fmt.Errorf("%w: set %s", ErrProductionRequiresMTLS, strings.Join(settings.Missing(), ", "))
	}
	if settings.Configured() {
		return ModePlaintext, fmt.Errorf("%w: set %s", ErrIncompleteTLSMaterial, strings.Join(settings.Missing(), ", "))
	}
	return ModePlaintext, nil
}

// Settings locates this service's mTLS material and declares its identity.
type Settings struct {
	CertFile           string
	KeyFile            string
	TrustBundleFile    string
	TrustAuthorityFile string
	CRLFile            string
	// Identity is the identity this service claims. The loaded certificate's
	// URI SAN must match it exactly (installed agents include Installation).
	Identity sdk.Identity
}

// SettingsFromConfig maps the service configuration onto runtime settings.
// The service name and enterprise form the identity; installed agents (the
// Connector Agent) additionally set Identity.Installation before building
// the manager.
func SettingsFromConfig(cfg config.Config) Settings {
	return Settings{
		CertFile:           cfg.TLS.CertFile,
		KeyFile:            cfg.TLS.KeyFile,
		TrustBundleFile:    cfg.TLS.TrustBundleFile,
		TrustAuthorityFile: cfg.TLS.TrustAuthorityFile,
		CRLFile:            cfg.TLS.CRLFile,
		Identity:           sdk.Identity{Enterprise: cfg.EnterpriseID, Service: cfg.ServiceName},
	}
}

// authorizedClientServices is the canonical map of which client services may
// connect to each serving component. Every component has a unique identity,
// so authorization is per service, never a shared certificate.
var authorizedClientServices = map[string][]string{
	"gateway-api":      {"gateway-agent", "connector-worker", "connector-agent"},
	"gateway-agent":    {"gateway-api"},
	"connector-worker": {"gateway-api", "gateway-agent"},
	"connector-agent":  {"gateway-api", "connector-worker"},
}

// AuthorizedClients returns the canonical peer authorization for a serving
// core component within an enterprise.
func AuthorizedClients(service, enterprise string) (sdk.PeerAuthorization, error) {
	clients, ok := authorizedClientServices[service]
	if !ok {
		return sdk.PeerAuthorization{}, fmt.Errorf("transportsecurity: no authorized client set is defined for service %q", service)
	}
	return sdk.PeerAuthorization{Enterprise: enterprise, Services: append([]string(nil), clients...)}, nil
}

// material is one immutable, fully validated generation of trust material.
type material struct {
	certificate    tls.Certificate
	leaf           *x509.Certificate
	roots          *x509.CertPool
	rootCerts      []*x509.Certificate
	revocation     *sdk.RevocationSet
	bundleSequence uint64
	crlNumber      *big.Int
	certRaw        []byte
	keyRaw         []byte
	bundleRaw      []byte
	crlRaw         []byte
	generation     uint64
}

// Manager owns the mTLS material of one service instance: it validates and
// atomically swaps material generations, enforces anti-rollback on trust
// bundle and CRL updates, and notifies pool owners on every rotation.
type Manager struct {
	settings    Settings
	authority   *ecdsa.PublicKey
	identityURI string

	// reloadMu serializes entire reload passes (read files -> verify ->
	// swap) so concurrent Reload() calls can never interleave and swap
	// material out of order — without it, an older-but-valid artifact whose
	// anti-rollback floor was read moments before a newer reload swapped
	// could win the race and become current.
	reloadMu sync.Mutex

	mu       sync.RWMutex
	current  *material
	onRotate []func()
}

// NewManager loads and validates the initial material. It fails closed on
// any inconsistency: missing paths, an invalid or unbound identity, a bundle
// that does not verify under the pinned authority, a certificate outside the
// bundled roots, or a certificate that is already revoked.
func NewManager(settings Settings) (*Manager, error) {
	var missing []string
	for _, entry := range []struct{ name, value string }{
		{"certificate file", settings.CertFile},
		{"key file", settings.KeyFile},
		{"trust bundle file", settings.TrustBundleFile},
		{"trust authority file", settings.TrustAuthorityFile},
		{"CRL file", settings.CRLFile},
	} {
		if entry.value == "" {
			missing = append(missing, entry.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("transportsecurity: incomplete TLS settings: missing %s", strings.Join(missing, ", "))
	}
	if err := settings.Identity.Validate(); err != nil {
		return nil, err
	}
	identityURI, err := settings.Identity.URI()
	if err != nil {
		return nil, err
	}
	authority, err := loadBundleAuthority(settings.TrustAuthorityFile)
	if err != nil {
		return nil, err
	}
	m := &Manager{settings: settings, authority: authority, identityURI: identityURI}
	if _, err := m.reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func loadBundleAuthority(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("transportsecurity: read bundle authority key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("transportsecurity: bundle authority key is not a PUBLIC KEY PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("transportsecurity: parse bundle authority key: %w", err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("transportsecurity: bundle authority key is %T, want *ecdsa.PublicKey", pub)
	}
	return key, nil
}

// Reload re-reads the material files. Identical material is a no-op; changed
// material must pass full validation and strict anti-rollback before it
// atomically replaces the current generation and rotation callbacks fire.
// On any error the current material stays in force.
func (m *Manager) Reload() error {
	_, err := m.reload()
	return err
}

func (m *Manager) reload() (bool, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	certRaw, err := os.ReadFile(m.settings.CertFile)
	if err != nil {
		return false, fmt.Errorf("transportsecurity: read certificate: %w", err)
	}
	keyRaw, err := os.ReadFile(m.settings.KeyFile)
	if err != nil {
		return false, fmt.Errorf("transportsecurity: read key: %w", err)
	}
	bundleRaw, err := os.ReadFile(m.settings.TrustBundleFile)
	if err != nil {
		return false, fmt.Errorf("transportsecurity: read trust bundle: %w", err)
	}
	crlRaw, err := os.ReadFile(m.settings.CRLFile)
	if err != nil {
		return false, fmt.Errorf("transportsecurity: read CRL: %w", err)
	}

	cur := m.snapshot()
	if cur != nil && bytes.Equal(certRaw, cur.certRaw) && bytes.Equal(keyRaw, cur.keyRaw) &&
		bytes.Equal(bundleRaw, cur.bundleRaw) && bytes.Equal(crlRaw, cur.crlRaw) {
		return false, nil
	}

	// Anti-rollback applies to artifacts that CHANGED; unchanged artifacts
	// re-verify against their own accepted state.
	var lastSequence uint64
	var lastNumber *big.Int
	if cur != nil {
		if !bytes.Equal(bundleRaw, cur.bundleRaw) {
			lastSequence = cur.bundleSequence
		}
		if !bytes.Equal(crlRaw, cur.crlRaw) {
			lastNumber = cur.crlNumber
		}
	}

	bundle, rootCerts, err := sdk.VerifyTrustBundle(bundleRaw, m.authority, lastSequence)
	if err != nil {
		return false, fmt.Errorf("transportsecurity: trust bundle rejected: %w", err)
	}
	roots := x509.NewCertPool()
	for _, root := range rootCerts {
		roots.AddCert(root)
	}
	crl, err := sdk.VerifyCRL(crlRaw, rootCerts, lastNumber, time.Now())
	if err != nil {
		return false, fmt.Errorf("transportsecurity: CRL rejected: %w", err)
	}
	revocation := sdk.NewRevocationSet(crl)

	certificate, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		return false, fmt.Errorf("transportsecurity: load identity keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("transportsecurity: parse identity certificate: %w", err)
	}
	certificate.Leaf = leaf
	certIdentity, err := sdk.CertificateIdentity(leaf)
	if err != nil {
		return false, fmt.Errorf("transportsecurity: identity certificate rejected: %w", err)
	}
	if certIdentity != m.settings.Identity {
		gotURI, _ := certIdentity.URI()
		return false, fmt.Errorf("transportsecurity: certificate identity %q does not match the declared identity %q", gotURI, m.identityURI)
	}
	intermediates := x509.NewCertPool()
	for _, der := range certificate.Certificate[1:] {
		if cert, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(cert)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return false, fmt.Errorf("transportsecurity: identity certificate does not chain to the trust bundle: %w", err)
	}
	if err := revocation.CheckRevocation(leaf); err != nil {
		return false, fmt.Errorf("transportsecurity: own identity certificate is revoked, refusing to serve: %w", err)
	}

	m.mu.Lock()
	generation := uint64(1)
	if m.current != nil {
		generation = m.current.generation + 1
	}
	m.current = &material{
		certificate:    certificate,
		leaf:           leaf,
		roots:          roots,
		rootCerts:      rootCerts,
		revocation:     revocation,
		bundleSequence: bundle.Sequence,
		crlNumber:      crl.Number,
		certRaw:        certRaw,
		keyRaw:         keyRaw,
		bundleRaw:      bundleRaw,
		crlRaw:         crlRaw,
		generation:     generation,
	}
	callbacks := append([]func(){}, m.onRotate...)
	m.mu.Unlock()
	for _, fn := range callbacks {
		fn()
	}
	return true, nil
}

func (m *Manager) snapshot() *material {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Generation returns the current material generation (starts at 1 and
// increments on every accepted rotation).
func (m *Manager) Generation() uint64 {
	if mat := m.snapshot(); mat != nil {
		return mat.generation
	}
	return 0
}

// IdentityURI returns this service's bound identity URI.
func (m *Manager) IdentityURI() string { return m.identityURI }

// OnRotate registers a callback fired synchronously after every accepted
// material rotation. Pool owners use it to rebuild connections so a revoked
// identity is never silently kept alive.
func (m *Manager) OnRotate(fn func()) {
	if fn == nil {
		return
	}
	m.mu.Lock()
	m.onRotate = append(m.onRotate, fn)
	m.mu.Unlock()
}

func (m *Manager) buildServerConfig(peers sdk.PeerAuthorization) (*tls.Config, error) {
	mat := m.snapshot()
	if mat == nil {
		return nil, errors.New("transportsecurity: no material loaded")
	}
	return sdk.ServerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &mat.certificate, nil
	}, sdk.VerifyOptions{Roots: mat.roots, Peer: peers, Revocation: mat.revocation})
}

// ServerTLSConfig builds the profile server configuration. Every new
// handshake resolves the CURRENT material generation via GetConfigForClient,
// so listeners pick up rotations and revocations without restarting.
func (m *Manager) ServerTLSConfig(peers sdk.PeerAuthorization) (*tls.Config, error) {
	base, err := m.buildServerConfig(peers)
	if err != nil {
		return nil, err
	}
	cfg := base.Clone()
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return m.buildServerConfig(peers)
	}
	return cfg, nil
}

// ClientTLSConfig builds the profile client configuration pinned to the
// CURRENT material generation. Long-lived pools must rebuild on rotation;
// use NewHTTPClient which does exactly that.
func (m *Manager) ClientTLSConfig(peers sdk.PeerAuthorization, serverName string) (*tls.Config, error) {
	mat := m.snapshot()
	if mat == nil {
		return nil, errors.New("transportsecurity: no material loaded")
	}
	return sdk.ClientTLSConfig(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &mat.certificate, nil
	}, serverName, sdk.VerifyOptions{Roots: mat.roots, Peer: peers, Revocation: mat.revocation})
}

// HTTPClient is an https-only pooled client bound to a Manager. On every
// material rotation the underlying transport is replaced and the previous
// pool's idle connections are closed, so connections established under
// retired or revoked trust are never reused.
type HTTPClient struct {
	manager    *Manager
	peers      sdk.PeerAuthorization
	serverName string

	mu         sync.Mutex
	transport  *http.Transport
	generation uint64
	rebuildErr error
}

// NewHTTPClient builds a pooled HTTP client that follows this manager's
// material rotations.
func (m *Manager) NewHTTPClient(peers sdk.PeerAuthorization, serverName string) (*HTTPClient, error) {
	c := &HTTPClient{manager: m, peers: peers, serverName: serverName}
	if err := c.rebuild(); err != nil {
		return nil, err
	}
	m.OnRotate(func() { _ = c.rebuild() })
	return c, nil
}

func (c *HTTPClient) rebuild() error {
	cfg, err := c.manager.ClientTLSConfig(c.peers, c.serverName)
	c.mu.Lock()
	old := c.transport
	if err != nil {
		// Fail closed: a client that cannot express the current trust
		// material must not keep using the previous pool.
		c.transport = nil
		c.rebuildErr = err
	} else {
		c.transport = &http.Transport{TLSClientConfig: cfg}
		c.generation = c.manager.Generation()
		c.rebuildErr = nil
	}
	c.mu.Unlock()
	if old != nil {
		old.CloseIdleConnections()
	}
	return err
}

func (c *HTTPClient) currentTransport() (*http.Transport, error) {
	c.mu.Lock()
	transport, generation, rebuildErr := c.transport, c.generation, c.rebuildErr
	c.mu.Unlock()
	if rebuildErr == nil && transport != nil && generation == c.manager.Generation() {
		return transport, nil
	}
	// Defense in depth: if the rotation callback was missed or failed, the
	// generation check forces a rebuild before any request proceeds.
	if err := c.rebuild(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rebuildErr != nil {
		return nil, c.rebuildErr
	}
	if c.transport == nil {
		// Never pair a nil transport with a nil error: handing http.Client
		// a nil Transport silently falls back to http.DefaultTransport (no
		// client certificate, system trust roots), which is fail-open.
		// Fail closed instead.
		return nil, errors.New("transportsecurity: no usable mTLS transport; failing closed")
	}
	return c.transport, nil
}

// Do performs an https request under the mTLS profile. Any non-https request
// (including redirects) is refused: the profile has no plaintext mode.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, fmt.Errorf("%w: %v", ErrPlaintextRefused, req.URL)
	}
	transport, err := c.currentTransport()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return ErrPlaintextRefused
			}
			return nil
		},
	}
	return client.Do(req)
}

// CloseIdleConnections closes the current pool's idle connections.
func (c *HTTPClient) CloseIdleConnections() {
	c.mu.Lock()
	transport := c.transport
	c.mu.Unlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
}

// connTracker tracks a server's accepted connections so a trust rotation can
// terminate every connection established under the previous material.
type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (t *connTracker) track(conn net.Conn) {
	t.mu.Lock()
	t.conns[conn] = struct{}{}
	t.mu.Unlock()
}

func (t *connTracker) forget(conn net.Conn) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	conns := make([]net.Conn, 0, len(t.conns))
	for conn := range t.conns {
		conns = append(conns, conn)
	}
	t.conns = map[net.Conn]struct{}{}
	t.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// InstrumentServer makes an http.Server close ALL established connections on
// every material rotation. Peers immediately re-handshake against the new
// material, so an identity revoked by the rotation has no pooled connection
// left to reuse and its new handshakes are rejected per the CRL. The cost is
// deliberate: every rotation forces every peer — including benign ones — to
// re-handshake once; that reconnect stampede is the intentional fail-safe
// price of leaving no revoked-identity window.
func (m *Manager) InstrumentServer(srv *http.Server) {
	tracker := &connTracker{conns: map[net.Conn]struct{}{}}
	previous := srv.ConnState
	srv.ConnState = func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			tracker.track(conn)
		case http.StateClosed, http.StateHijacked:
			tracker.forget(conn)
		}
		if previous != nil {
			previous(conn, state)
		}
	}
	m.OnRotate(tracker.closeAll)
}
