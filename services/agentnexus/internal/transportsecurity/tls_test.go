// Runtime-plane tests for the AgentNexus mTLS profile: every handshake below
// is a real crypto/tls exchange over a loopback TCP socket (no mocks). All PKI
// material is generated at runtime; nothing is committed as a fixture.
package transportsecurity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
)

// --- runtime-generated test PKI -------------------------------------------

type testRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type testPKI struct {
	t         *testing.T
	roots     []testRoot // current trust set; roots[len-1] is the issuing root
	signer    *ecdsa.PrivateKey
	revoked   []x509.RevocationListEntry
	crlNumber int64
	bundleSeq uint64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &testPKI{t: t, signer: signer}
	p.roots = []testRoot{p.newRoot("agentnexus-test-root-1")}
	return p
}

func (p *testPKI) newRoot(cn string) testRoot {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(p.t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		p.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	return testRoot{cert: cert, key: key}
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

type issuedLeaf struct {
	certPEM []byte
	keyPEM  []byte
	leaf    *x509.Certificate
}

type issueOverride struct {
	notAfter time.Time
	noURI    bool
}

func (p *testPKI) issue(id sdk.Identity, override issueOverride) issuedLeaf {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	notAfter := override.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: newSerial(p.t),
		Subject:      pkix.Name{CommonName: id.Service},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if !override.noURI {
		raw, err := id.URI()
		if err != nil {
			p.t.Fatal(err)
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			p.t.Fatal(err)
		}
		template.URIs = []*url.URL{parsed}
	}
	issuer := p.roots[len(p.roots)-1]
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		p.t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		p.t.Fatal(err)
	}
	return issuedLeaf{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		leaf:    leaf,
	}
}

func (p *testPKI) tlsCertificate(leaf issuedLeaf) tls.Certificate {
	p.t.Helper()
	cert, err := tls.X509KeyPair(leaf.certPEM, leaf.keyPEM)
	if err != nil {
		p.t.Fatal(err)
	}
	return cert
}

func (p *testPKI) rootsPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, root := range p.roots {
		pool.AddCert(root.cert)
	}
	return pool
}

func (p *testPKI) rootsPEM() string {
	p.t.Helper()
	var b strings.Builder
	for _, root := range p.roots {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}); err != nil {
			p.t.Fatal(err)
		}
	}
	return b.String()
}

func (p *testPKI) signedBundle(sequence uint64) []byte {
	p.t.Helper()
	bundle := sdk.TrustBundle{
		Format:       sdk.TrustBundleFormat,
		Sequence:     sequence,
		IssuedAt:     time.Now().UTC(),
		RootsPEM:     p.rootsPEM(),
		SigningKeyID: "test-authority",
	}
	digest := sha256.Sum256(bundle.SigningPayload())
	sig, err := ecdsa.SignASN1(rand.Reader, p.signer, digest[:])
	if err != nil {
		p.t.Fatal(err)
	}
	bundle.Signature = sig
	raw, err := json.Marshal(bundle)
	if err != nil {
		p.t.Fatal(err)
	}
	p.bundleSeq = sequence
	return raw
}

func (p *testPKI) revoke(leaf *x509.Certificate) {
	p.revoked = append(p.revoked, x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now()})
}

func (p *testPKI) signedCRL(number int64) []byte {
	p.t.Helper()
	issuer := p.roots[len(p.roots)-1]
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: p.revoked,
	}, issuer.cert, issuer.key)
	if err != nil {
		p.t.Fatal(err)
	}
	p.crlNumber = number
	return der
}

func (p *testPKI) authorityPublicPEM() []byte {
	p.t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&p.signer.PublicKey)
	if err != nil {
		p.t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// materialDir lays PKI material out on disk the way operators deploy it and
// returns runtime settings pointing at it.
type materialDir struct {
	dir      string
	settings transportsecurity.Settings
}

func newMaterialDir(t *testing.T, p *testPKI, id sdk.Identity, leaf issuedLeaf, bundle, crl []byte) materialDir {
	t.Helper()
	dir := t.TempDir()
	m := materialDir{dir: dir, settings: transportsecurity.Settings{
		CertFile:           filepath.Join(dir, "tls.crt"),
		KeyFile:            filepath.Join(dir, "tls.key"),
		TrustBundleFile:    filepath.Join(dir, "trust-bundle.json"),
		TrustAuthorityFile: filepath.Join(dir, "bundle-authority.pub"),
		CRLFile:            filepath.Join(dir, "revocations.crl"),
		Identity:           id,
	}}
	writeFile(t, m.settings.CertFile, leaf.certPEM)
	writeFile(t, m.settings.KeyFile, leaf.keyPEM)
	writeFile(t, m.settings.TrustBundleFile, bundle)
	writeFile(t, m.settings.TrustAuthorityFile, p.authorityPublicPEM())
	writeFile(t, m.settings.CRLFile, crl)
	return m
}

func (m materialDir) replaceCert(t *testing.T, leaf issuedLeaf) {
	t.Helper()
	writeFile(t, m.settings.CertFile, leaf.certPEM)
	writeFile(t, m.settings.KeyFile, leaf.keyPEM)
}

func (m materialDir) replaceBundle(t *testing.T, bundle []byte) {
	t.Helper()
	writeFile(t, m.settings.TrustBundleFile, bundle)
}

func (m materialDir) replaceCRL(t *testing.T, crl []byte) {
	t.Helper()
	writeFile(t, m.settings.CRLFile, crl)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- startup mode: fail closed in production -------------------------------

func completeTLSSettings() config.TLSSettings {
	return config.TLSSettings{
		CertFile:           "tls.crt",
		KeyFile:            "tls.key",
		TrustBundleFile:    "trust-bundle.json",
		TrustAuthorityFile: "bundle-authority.pub",
		CRLFile:            "revocations.crl",
	}
}

func TestResolveStartupModeFailsClosedInProduction(t *testing.T) {
	if _, err := transportsecurity.ResolveStartupMode("production", config.TLSSettings{}); !errors.Is(err, transportsecurity.ErrProductionRequiresMTLS) {
		t.Errorf("production without TLS material: err = %v, want ErrProductionRequiresMTLS", err)
	}
	partial := config.TLSSettings{CertFile: "tls.crt"}
	if _, err := transportsecurity.ResolveStartupMode("production", partial); !errors.Is(err, transportsecurity.ErrProductionRequiresMTLS) {
		t.Errorf("production with partial TLS material: err = %v, want ErrProductionRequiresMTLS", err)
	}
	mode, err := transportsecurity.ResolveStartupMode("production", completeTLSSettings())
	if err != nil || mode != transportsecurity.ModeMutualTLS {
		t.Errorf("production with complete material: mode = %v err = %v, want ModeMutualTLS", mode, err)
	}

	mode, err = transportsecurity.ResolveStartupMode("dev", config.TLSSettings{})
	if err != nil || mode != transportsecurity.ModePlaintext {
		t.Errorf("dev without material: mode = %v err = %v, want ModePlaintext", mode, err)
	}
	if _, err := transportsecurity.ResolveStartupMode("dev", partial); !errors.Is(err, transportsecurity.ErrIncompleteTLSMaterial) {
		t.Errorf("dev with partial material must not silently downgrade: err = %v, want ErrIncompleteTLSMaterial", err)
	}
	mode, err = transportsecurity.ResolveStartupMode("dev", completeTLSSettings())
	if err != nil || mode != transportsecurity.ModeMutualTLS {
		t.Errorf("dev with complete material: mode = %v err = %v, want ModeMutualTLS", mode, err)
	}
}

func TestTLSSettingsCompleteness(t *testing.T) {
	if (config.TLSSettings{}).Configured() {
		t.Error("empty settings must not report configured")
	}
	if !completeTLSSettings().Complete() || !completeTLSSettings().Configured() {
		t.Error("complete settings must report configured and complete")
	}
	partial := config.TLSSettings{KeyFile: "tls.key"}
	if !partial.Configured() || partial.Complete() {
		t.Error("partial settings must report configured but not complete")
	}
}

func TestSettingsFromConfigCarriesIdentityAndPaths(t *testing.T) {
	cfg := config.Config{ServiceName: "gateway-agent", EnterpriseID: "acme", TLS: completeTLSSettings()}
	settings := transportsecurity.SettingsFromConfig(cfg)
	if settings.Identity != (sdk.Identity{Enterprise: "acme", Service: "gateway-agent"}) {
		t.Errorf("identity = %+v", settings.Identity)
	}
	if settings.CertFile != "tls.crt" || settings.KeyFile != "tls.key" || settings.TrustBundleFile != "trust-bundle.json" ||
		settings.TrustAuthorityFile != "bundle-authority.pub" || settings.CRLFile != "revocations.crl" {
		t.Errorf("paths not carried over: %+v", settings)
	}
}

// --- unique service identities and their authorization sets -----------------

func TestAuthorizedClientsCoversEveryCoreService(t *testing.T) {
	want := map[string][]string{
		"gateway-api":      {"connector-agent", "connector-worker", "gateway-agent"},
		"gateway-agent":    {"gateway-api"},
		"connector-worker": {"gateway-api", "gateway-agent"},
		"connector-agent":  {"connector-worker", "gateway-api"},
	}
	for service, wantClients := range want {
		auth, err := transportsecurity.AuthorizedClients(service, "acme")
		if err != nil {
			t.Fatalf("AuthorizedClients(%q): %v", service, err)
		}
		if auth.Enterprise != "acme" {
			t.Errorf("%s enterprise = %q", service, auth.Enterprise)
		}
		got := map[string]bool{}
		for _, s := range auth.Services {
			got[s] = true
		}
		if len(got) != len(wantClients) {
			t.Errorf("%s allowed clients = %v, want %v", service, auth.Services, wantClients)
			continue
		}
		for _, s := range wantClients {
			if !got[s] {
				t.Errorf("%s allowed clients = %v, missing %q", service, auth.Services, s)
			}
		}
		if auth.Services[0] == service {
			t.Errorf("%s must not authorize its own identity by default", service)
		}
	}
	if _, err := transportsecurity.AuthorizedClients("unknown-service", "acme"); err == nil {
		t.Error("unknown service accepted")
	}
}

// --- manager: identity binding and material validation ----------------------

func TestNewManagerBindsDeclaredIdentityToCertificate(t *testing.T) {
	p := newTestPKI(t)
	id := sdk.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-7"}
	leaf := p.issue(id, issueOverride{})
	bundle := p.signedBundle(1)
	crl := p.signedCRL(1)

	m := newMaterialDir(t, p, id, leaf, bundle, crl)
	manager, err := transportsecurity.NewManager(m.settings)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	wantURI := "agentnexus://enterprise/acme/service/connector-agent/installation/agent-7"
	if manager.IdentityURI() != wantURI {
		t.Errorf("IdentityURI = %q, want %q", manager.IdentityURI(), wantURI)
	}

	// Declared identity differs from certificate identity: refuse to start.
	other := m.settings
	other.Identity = sdk.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-8"}
	if _, err := transportsecurity.NewManager(other); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("installation mismatch: err = %v, want identity binding error", err)
	}
	wrongService := m.settings
	wrongService.Identity = sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	if _, err := transportsecurity.NewManager(wrongService); err == nil {
		t.Error("service mismatch between declared identity and certificate accepted")
	}

	// A certificate without the profile URI SAN carries no identity: refuse.
	noURI := p.issue(id, issueOverride{noURI: true})
	m2 := newMaterialDir(t, p, id, noURI, p.signedBundle(p.bundleSeq+1), crl)
	if _, err := transportsecurity.NewManager(m2.settings); err == nil {
		t.Error("certificate without identity URI SAN accepted")
	}
}

func TestNewManagerFailsClosedOnBadMaterial(t *testing.T) {
	p := newTestPKI(t)
	id := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	leaf := p.issue(id, issueOverride{})
	bundle := p.signedBundle(1)
	crl := p.signedCRL(1)

	incomplete := transportsecurity.Settings{CertFile: "only-cert.pem", Identity: id}
	if _, err := transportsecurity.NewManager(incomplete); err == nil {
		t.Error("incomplete settings accepted")
	}

	invalidIdentity := newMaterialDir(t, p, sdk.Identity{}, leaf, bundle, crl)
	if _, err := transportsecurity.NewManager(invalidIdentity.settings); err == nil {
		t.Error("empty identity accepted")
	}

	// Trust bundle signed by a different authority key must be rejected.
	rogue := newTestPKI(t)
	rogueBundle := rogue.signedBundle(1)
	m := newMaterialDir(t, p, id, leaf, rogueBundle, crl)
	writeFile(t, m.settings.TrustAuthorityFile, p.authorityPublicPEM())
	if _, err := transportsecurity.NewManager(m.settings); err == nil {
		t.Error("trust bundle signed by an untrusted authority accepted")
	}

	// Certificate that does not chain to the bundled roots must be rejected.
	strangerLeaf := rogue.issue(id, issueOverride{})
	m3 := newMaterialDir(t, p, id, strangerLeaf, bundle, crl)
	if _, err := transportsecurity.NewManager(m3.settings); err == nil {
		t.Error("certificate outside the trust bundle accepted")
	}

	// A service whose own certificate is revoked must refuse to start.
	p.revoke(leaf.leaf)
	revokedCRL := p.signedCRL(2)
	m4 := newMaterialDir(t, p, id, leaf, bundle, revokedCRL)
	if _, err := transportsecurity.NewManager(m4.settings); err == nil {
		t.Error("service started with its own certificate revoked")
	}
}

// --- anti-rollback on reload -------------------------------------------------

func TestReloadRejectsStaleTrustBundleAndCRL(t *testing.T) {
	p := newTestPKI(t)
	id := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	leaf := p.issue(id, issueOverride{})
	bundleV2 := p.signedBundle(2)
	crlV2 := p.signedCRL(2)
	m := newMaterialDir(t, p, id, leaf, bundleV2, crlV2)
	manager, err := transportsecurity.NewManager(m.settings)
	if err != nil {
		t.Fatal(err)
	}
	generation := manager.Generation()

	rotations := 0
	manager.OnRotate(func() { rotations++ })

	// Identical material: a reload is a no-op, not a rotation.
	if err := manager.Reload(); err != nil {
		t.Fatalf("no-op reload failed: %v", err)
	}
	if manager.Generation() != generation || rotations != 0 {
		t.Errorf("no-op reload rotated material: generation %d -> %d, rotations=%d", generation, manager.Generation(), rotations)
	}

	// Rollback to an older signed bundle must be rejected and keep material.
	m.replaceBundle(t, p.signedBundle(1))
	if err := manager.Reload(); !errors.Is(err, sdk.ErrStaleTrustBundle) {
		t.Errorf("stale bundle reload: err = %v, want ErrStaleTrustBundle", err)
	}
	if manager.Generation() != generation {
		t.Error("stale bundle must not replace current material")
	}

	// A strictly newer bundle rotates.
	m.replaceBundle(t, p.signedBundle(3))
	if err := manager.Reload(); err != nil {
		t.Fatalf("newer bundle reload: %v", err)
	}
	if manager.Generation() == generation || rotations != 1 {
		t.Errorf("newer bundle must rotate: generation %d -> %d, rotations=%d", generation, manager.Generation(), rotations)
	}

	// CRL number rollback must be rejected.
	m.replaceCRL(t, p.signedCRL(1))
	if err := manager.Reload(); !errors.Is(err, sdk.ErrStaleCRL) {
		t.Errorf("stale CRL reload: err = %v, want ErrStaleCRL", err)
	}
}

// --- real handshake matrix ----------------------------------------------------

type handshakeOutcome struct {
	serverErr   error
	clientErr   error
	serverState *tls.ConnectionState
	clientState *tls.ConnectionState
}

func runHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) handshakeOutcome {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type serverResult struct {
		err   error
		state *tls.ConnectionState
	}
	serverCh := make(chan serverResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverCh <- serverResult{err: err}
			return
		}
		defer conn.Close()
		tconn := tls.Server(conn, serverCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := tconn.HandshakeContext(ctx); err != nil {
			serverCh <- serverResult{err: err}
			return
		}
		state := tconn.ConnectionState()
		_, werr := tconn.Write([]byte("ok"))
		serverCh <- serverResult{err: werr, state: &state}
	}()

	outcome := handshakeOutcome{}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tconn := tls.Client(conn, clientCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tconn.HandshakeContext(ctx); err != nil {
		outcome.clientErr = err
	} else {
		// In TLS 1.3 a server-side rejection of the client certificate only
		// surfaces on the first read, so always read the server's byte.
		buf := make([]byte, 2)
		if _, err := io.ReadFull(tconn, buf); err != nil {
			outcome.clientErr = err
		} else {
			state := tconn.ConnectionState()
			outcome.clientState = &state
		}
	}
	result := <-serverCh
	outcome.serverErr = result.err
	outcome.serverState = result.state
	return outcome
}

func sendPlaintext(t *testing.T, serverCfg *tls.Config) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverCh <- err
			return
		}
		defer conn.Close()
		tconn := tls.Server(conn, serverCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		serverCh <- tconn.HandshakeContext(ctx)
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: gateway\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	return <-serverCh
}

func TestMutualTLSHandshakeMatrix(t *testing.T) {
	p := newTestPKI(t)
	serverID := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	clientID := sdk.Identity{Enterprise: "acme", Service: "gateway-agent"}
	serverLeaf := p.issue(serverID, issueOverride{})
	clientLeaf := p.issue(clientID, issueOverride{})
	bundle := p.signedBundle(1)
	crl := p.signedCRL(1)

	serverDir := newMaterialDir(t, p, serverID, serverLeaf, bundle, crl)
	serverManager, err := transportsecurity.NewManager(serverDir.settings)
	if err != nil {
		t.Fatal(err)
	}
	serverPeers, err := transportsecurity.AuthorizedClients("gateway-api", "acme")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := serverManager.ServerTLSConfig(serverPeers)
	if err != nil {
		t.Fatal(err)
	}

	clientDir := newMaterialDir(t, p, clientID, clientLeaf, bundle, crl)
	clientManager, err := transportsecurity.NewManager(clientDir.settings)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := clientManager.ClientTLSConfig(sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-api"}}, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("mutual_tls13_success", func(t *testing.T) {
		out := runHandshake(t, serverCfg, clientCfg)
		if out.serverErr != nil || out.clientErr != nil {
			t.Fatalf("handshake failed: server=%v client=%v", out.serverErr, out.clientErr)
		}
		if out.serverState.Version != tls.VersionTLS13 || out.clientState.Version != tls.VersionTLS13 {
			t.Errorf("negotiated version server=%#x client=%#x, want TLS 1.3", out.serverState.Version, out.clientState.Version)
		}
		peer, err := sdk.PeerIdentity(*out.serverState)
		if err != nil || peer != clientID {
			t.Errorf("server saw peer %+v (err=%v), want %+v", peer, err, clientID)
		}
		peer, err = sdk.PeerIdentity(*out.clientState)
		if err != nil || peer != serverID {
			t.Errorf("client saw peer %+v (err=%v), want %+v", peer, err, serverID)
		}
	})

	t.Run("plaintext_rejected", func(t *testing.T) {
		err := sendPlaintext(t, serverCfg)
		if err == nil {
			t.Fatal("plaintext connection completed a TLS handshake")
		}
	})

	t.Run("wrong_service_identity_rejected", func(t *testing.T) {
		rogue := p.issue(sdk.Identity{Enterprise: "acme", Service: "rogue-service"}, issueOverride{})
		cfg := adversaryClientConfig(t, p, rogue, "localhost", 0)
		out := runHandshake(t, serverCfg, cfg)
		if out.serverErr == nil || !strings.Contains(out.serverErr.Error(), "service") {
			t.Fatalf("server err = %v, want authorization failure naming the service", out.serverErr)
		}
	})

	t.Run("wrong_tenant_identity_rejected", func(t *testing.T) {
		mallory := p.issue(sdk.Identity{Enterprise: "mallory", Service: "gateway-agent"}, issueOverride{})
		cfg := adversaryClientConfig(t, p, mallory, "localhost", 0)
		out := runHandshake(t, serverCfg, cfg)
		if out.serverErr == nil || !strings.Contains(out.serverErr.Error(), "enterprise") {
			t.Fatalf("server err = %v, want tenant authorization failure despite a valid chain", out.serverErr)
		}
	})

	t.Run("hostname_mismatch_rejected", func(t *testing.T) {
		cfg, err := clientManager.ClientTLSConfig(sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-api"}}, "gateway.wrong.example")
		if err != nil {
			t.Fatal(err)
		}
		out := runHandshake(t, serverCfg, cfg)
		if out.clientErr == nil {
			t.Fatal("hostname mismatch accepted")
		}
	})

	t.Run("missing_client_certificate_rejected", func(t *testing.T) {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: p.rootsPool(), ServerName: "localhost"}
		out := runHandshake(t, serverCfg, cfg)
		if out.serverErr == nil {
			t.Fatal("connection without a client certificate accepted")
		}
	})

	t.Run("expired_client_certificate_rejected", func(t *testing.T) {
		expired := p.issue(clientID, issueOverride{notAfter: time.Now().Add(-time.Hour)})
		cfg := adversaryClientConfig(t, p, expired, "localhost", 0)
		out := runHandshake(t, serverCfg, cfg)
		if out.serverErr == nil || !strings.Contains(out.serverErr.Error(), "expired") {
			t.Fatalf("server err = %v, want certificate-expired failure", out.serverErr)
		}
	})

	t.Run("tls12_downgrade_rejected", func(t *testing.T) {
		cfg := adversaryClientConfig(t, p, clientLeaf, "localhost", tls.VersionTLS12)
		out := runHandshake(t, serverCfg, cfg)
		if out.serverErr == nil && out.clientErr == nil {
			t.Fatal("TLS 1.2 downgrade accepted")
		}
	})

	t.Run("wrong_installation_rejected", func(t *testing.T) {
		agent8 := p.issue(sdk.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-8"}, issueOverride{})
		pinned, err := clientManager.ClientTLSConfig(sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"connector-agent"}, Installation: "agent-7"}, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		agentServerCfg := adversaryServerConfig(t, p, agent8)
		out := runHandshake(t, agentServerCfg, pinned)
		if out.clientErr == nil || !strings.Contains(out.clientErr.Error(), "installation") {
			t.Fatalf("client err = %v, want installation binding failure", out.clientErr)
		}
	})

	t.Run("revoked_client_certificate_rejected", func(t *testing.T) {
		// Works before revocation...
		out := runHandshake(t, serverCfg, clientCfg)
		if out.serverErr != nil || out.clientErr != nil {
			t.Fatalf("pre-revocation handshake failed: server=%v client=%v", out.serverErr, out.clientErr)
		}
		// ...and is rejected by NEW handshakes after the CRL update.
		p.revoke(clientLeaf.leaf)
		serverDir.replaceCRL(t, p.signedCRL(p.crlNumber+1))
		if err := serverManager.Reload(); err != nil {
			t.Fatal(err)
		}
		out = runHandshake(t, serverCfg, clientCfg)
		if out.serverErr == nil || !strings.Contains(out.serverErr.Error(), "revoked") {
			t.Fatalf("server err = %v, want revocation failure", out.serverErr)
		}
	})
}

// adversaryClientConfig builds a plain crypto/tls client the way an attacker
// or a legacy peer would: valid chain material, no profile enforcement.
func adversaryClientConfig(t *testing.T, p *testPKI, leaf issuedLeaf, serverName string, maxVersion uint16) *tls.Config {
	t.Helper()
	cert := p.tlsCertificate(leaf)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxVersion,
		RootCAs:      p.rootsPool(),
		ServerName:   serverName,
		Certificates: []tls.Certificate{cert},
	}
}

func adversaryServerConfig(t *testing.T, p *testPKI, leaf issuedLeaf) *tls.Config {
	t.Helper()
	cert := p.tlsCertificate(leaf)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.rootsPool(),
		Certificates: []tls.Certificate{cert},
	}
}

// --- rotation rebuilds pools and never re-admits a revoked identity ---------

type remoteAddrRecorder struct {
	mu    sync.Mutex
	addrs map[string]int
}

func (r *remoteAddrRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	if r.addrs == nil {
		r.addrs = map[string]int{}
	}
	r.addrs[req.RemoteAddr]++
	r.mu.Unlock()
	_, _ = w.Write([]byte("ok"))
}

func (r *remoteAddrRecorder) distinct() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.addrs)
}

func startMTLSServer(t *testing.T, manager *transportsecurity.Manager, peers sdk.PeerAuthorization, handler http.Handler) string {
	t.Helper()
	serverCfg, err := manager.ServerTLSConfig(peers)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, TLSConfig: serverCfg, ReadHeaderTimeout: 5 * time.Second}
	manager.InstrumentServer(srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return fmt.Sprintf("https://%s/", ln.Addr().String())
}

func mustGet(t *testing.T, client *transportsecurity.HTTPClient, url string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
}

func TestReloadRebuildsClientPoolsAndRejectsRevokedServer(t *testing.T) {
	p := newTestPKI(t)
	serverID := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	clientID := sdk.Identity{Enterprise: "acme", Service: "gateway-agent"}
	serverLeaf := p.issue(serverID, issueOverride{})
	clientLeaf := p.issue(clientID, issueOverride{})
	bundle := p.signedBundle(1)
	crl := p.signedCRL(1)

	serverDir := newMaterialDir(t, p, serverID, serverLeaf, bundle, crl)
	serverManager, err := transportsecurity.NewManager(serverDir.settings)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := transportsecurity.AuthorizedClients("gateway-api", "acme")
	if err != nil {
		t.Fatal(err)
	}
	recorder := &remoteAddrRecorder{}
	url := startMTLSServer(t, serverManager, peers, recorder)

	clientDir := newMaterialDir(t, p, clientID, clientLeaf, bundle, crl)
	clientManager, err := transportsecurity.NewManager(clientDir.settings)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientManager.NewHTTPClient(sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-api"}}, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	// Two requests ride the same pooled connection: the pool is real.
	mustGet(t, client, url)
	mustGet(t, client, url)
	if recorder.distinct() != 1 {
		t.Fatalf("expected both requests on one pooled connection, saw %d connections", recorder.distinct())
	}

	// The server's identity is revoked and the client learns it via its CRL
	// update. The pool built before the update must not keep the revoked
	// identity alive: the next request must fail, not reuse the old conn.
	p.revoke(serverLeaf.leaf)
	clientDir.replaceCRL(t, p.signedCRL(p.crlNumber+1))
	if err := clientManager.Reload(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded against a revoked server identity: the connection pool silently outlived the trust update")
	}
	if !errors.Is(err, sdk.ErrCertificateRevoked) {
		t.Fatalf("err = %v, want ErrCertificateRevoked", err)
	}
}

func TestServerReloadClosesPooledConnectionsFromRevokedClient(t *testing.T) {
	p := newTestPKI(t)
	serverID := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	clientID := sdk.Identity{Enterprise: "acme", Service: "gateway-agent"}
	serverLeaf := p.issue(serverID, issueOverride{})
	clientLeaf := p.issue(clientID, issueOverride{})
	bundle := p.signedBundle(1)
	crl := p.signedCRL(1)

	serverDir := newMaterialDir(t, p, serverID, serverLeaf, bundle, crl)
	serverManager, err := transportsecurity.NewManager(serverDir.settings)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := transportsecurity.AuthorizedClients("gateway-api", "acme")
	if err != nil {
		t.Fatal(err)
	}
	recorder := &remoteAddrRecorder{}
	url := startMTLSServer(t, serverManager, peers, recorder)

	// The soon-to-be-revoked client holds a keep-alive pool of its own.
	adversary := &http.Client{Transport: &http.Transport{TLSClientConfig: adversaryClientConfig(t, p, clientLeaf, "localhost", 0)}}
	resp, err := adversary.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Revoke the client identity and update the server's CRL. The server must
	// close established connections from before the update AND refuse the new
	// handshake, leaving the revoked identity nothing to reuse.
	p.revoke(clientLeaf.leaf)
	serverDir.replaceCRL(t, p.signedCRL(p.crlNumber+1))
	if err := serverManager.Reload(); err != nil {
		t.Fatal(err)
	}
	resp, err = adversary.Get(url)
	if err == nil {
		resp.Body.Close()
		t.Fatal("revoked client kept using its pooled connection after the trust update")
	}
}

func TestOverlappingRotationKeepsServiceAliveAndRetiresOldRoot(t *testing.T) {
	p := newTestPKI(t)
	serverID := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	clientID := sdk.Identity{Enterprise: "acme", Service: "gateway-agent"}
	oldServerLeaf := p.issue(serverID, issueOverride{})
	oldClientLeaf := p.issue(clientID, issueOverride{})
	bundle := p.signedBundle(1)
	crl := p.signedCRL(1)

	serverDir := newMaterialDir(t, p, serverID, oldServerLeaf, bundle, crl)
	serverManager, err := transportsecurity.NewManager(serverDir.settings)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := transportsecurity.AuthorizedClients("gateway-api", "acme")
	if err != nil {
		t.Fatal(err)
	}
	url := startMTLSServer(t, serverManager, peers, &remoteAddrRecorder{})

	clientDir := newMaterialDir(t, p, clientID, oldClientLeaf, bundle, crl)
	clientManager, err := transportsecurity.NewManager(clientDir.settings)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientManager.NewHTTPClient(sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-api"}}, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	mustGet(t, client, url)

	// Phase 1: introduce the new root alongside the old one (overlap), and
	// revoke a new-root identity mid-rotation to prove revocation survives.
	p.roots = append(p.roots, p.newRoot("agentnexus-test-root-2"))
	dualBundle := p.signedBundle(2)
	newServerLeaf := p.issue(serverID, issueOverride{})
	newClientLeaf := p.issue(clientID, issueOverride{})
	compromised := p.issue(sdk.Identity{Enterprise: "acme", Service: "connector-worker"}, issueOverride{})
	p.revoke(compromised.leaf)
	rotationCRL := p.signedCRL(2)

	serverDir.replaceBundle(t, dualBundle)
	serverDir.replaceCRL(t, rotationCRL)
	if err := serverManager.Reload(); err != nil {
		t.Fatal(err)
	}
	clientDir.replaceBundle(t, dualBundle)
	clientDir.replaceCRL(t, rotationCRL)
	if err := clientManager.Reload(); err != nil {
		t.Fatal(err)
	}
	// Old certificates still work during the overlap: no downtime.
	mustGet(t, client, url)

	// Phase 2: server re-keys onto the new root; old-root clients still work.
	serverDir.replaceCert(t, newServerLeaf)
	if err := serverManager.Reload(); err != nil {
		t.Fatal(err)
	}
	mustGet(t, client, url)

	// The compromised identity issued from the NEW root is already dead.
	compromisedCfg := adversaryClientConfig(t, p, compromised, "localhost", 0)
	serverCfg, err := serverManager.ServerTLSConfig(peers)
	if err != nil {
		t.Fatal(err)
	}
	out := runHandshake(t, serverCfg, compromisedCfg)
	if out.serverErr == nil || !strings.Contains(out.serverErr.Error(), "revoked") {
		t.Fatalf("mid-rotation revoked identity: server err = %v, want revocation failure", out.serverErr)
	}

	// Phase 3: client re-keys, then the old root is retired.
	clientDir.replaceCert(t, newClientLeaf)
	if err := clientManager.Reload(); err != nil {
		t.Fatal(err)
	}
	p.roots = p.roots[1:]
	finalBundle := p.signedBundle(3)
	finalCRL := p.signedCRL(3)
	serverDir.replaceBundle(t, finalBundle)
	serverDir.replaceCRL(t, finalCRL)
	if err := serverManager.Reload(); err != nil {
		t.Fatal(err)
	}
	clientDir.replaceBundle(t, finalBundle)
	clientDir.replaceCRL(t, finalCRL)
	if err := clientManager.Reload(); err != nil {
		t.Fatal(err)
	}
	mustGet(t, client, url)

	// Identities from the retired root no longer handshake.
	oldCfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: p.rootsPool(), ServerName: "localhost", Certificates: []tls.Certificate{mustKeyPair(t, oldClientLeaf)}}
	serverCfg, err = serverManager.ServerTLSConfig(peers)
	if err != nil {
		t.Fatal(err)
	}
	out = runHandshake(t, serverCfg, oldCfg)
	if out.serverErr == nil {
		t.Fatal("certificate from the retired root accepted after rotation completed")
	}
}

func mustKeyPair(t *testing.T, leaf issuedLeaf) tls.Certificate {
	t.Helper()
	cert, err := tls.X509KeyPair(leaf.certPEM, leaf.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// --- the client is https-only ---------------------------------------------

func TestHTTPClientRefusesPlaintextRequests(t *testing.T) {
	p := newTestPKI(t)
	id := sdk.Identity{Enterprise: "acme", Service: "gateway-agent"}
	leaf := p.issue(id, issueOverride{})
	m := newMaterialDir(t, p, id, leaf, p.signedBundle(1), p.signedCRL(1))
	manager, err := transportsecurity.NewManager(m.settings)
	if err != nil {
		t.Fatal(err)
	}
	client, err := manager.NewHTTPClient(sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-api"}}, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:9/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(req); !errors.Is(err, transportsecurity.ErrPlaintextRefused) {
		t.Fatalf("plaintext request err = %v, want ErrPlaintextRefused", err)
	}
}
