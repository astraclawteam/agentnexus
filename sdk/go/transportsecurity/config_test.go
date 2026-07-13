// Black-box tests for the single public AgentNexus TLS/mTLS profile.
//
// The profile is a frozen public contract: minimum protocol version TLS 1.3,
// mandatory mutual authentication, exactly one agentnexus:// URI SAN identity
// per certificate, signed trust bundles and CRLs with strictly monotonic
// sequences (anti-rollback). Enterprise tooling mirrors these values as
// literals; if they drift here, the enterprise mTLS matrix must be re-reviewed.
package transportsecurity_test

import (
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
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	ts "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
)

// --- test PKI helpers (generated at runtime; no fixtures on disk) ---

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

type leafOptions struct {
	uris      []*url.URL
	notAfter  time.Time
	serial    *big.Int
	dnsNames  []string
	ipAddrs   []net.IP
	extraURIs []*url.URL
}

func issueLeaf(t *testing.T, ca testCA, opts leafOptions) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := opts.serial
	if serial == nil {
		serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			t.Fatal(err)
		}
	}
	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(12 * time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         append(append([]*url.URL{}, opts.uris...), opts.extraURIs...),
		DNSNames:     opts.dnsNames,
		IPAddresses:  opts.ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func identityURL(t *testing.T, id ts.Identity) *url.URL {
	t.Helper()
	raw, err := id.URI()
	if err != nil {
		t.Fatalf("identity URI %+v: %v", id, err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func signTestBundle(t *testing.T, signer *ecdsa.PrivateKey, bundle ts.TrustBundle) []byte {
	t.Helper()
	digest := sha256.Sum256(bundle.SigningPayload())
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = sig
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func caPEM(t *testing.T, cas ...testCA) string {
	t.Helper()
	var b strings.Builder
	for _, ca := range cas {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

// --- profile constants ---

func TestProfileConstantsAreFrozen(t *testing.T) {
	if ts.ProfileName != "agentnexus-mtls/v1" {
		t.Errorf("ProfileName = %q, want agentnexus-mtls/v1", ts.ProfileName)
	}
	if ts.IdentityURIScheme != "agentnexus" {
		t.Errorf("IdentityURIScheme = %q, want agentnexus", ts.IdentityURIScheme)
	}
	if ts.TrustBundleFormat != "agentnexus-trust-bundle/v1" {
		t.Errorf("TrustBundleFormat = %q, want agentnexus-trust-bundle/v1", ts.TrustBundleFormat)
	}
	if ts.MinTLSVersion != tls.VersionTLS13 {
		t.Errorf("MinTLSVersion = %#x, want TLS 1.3 (%#x)", ts.MinTLSVersion, tls.VersionTLS13)
	}
}

// --- identity URI scheme ---

func TestIdentityURIRoundTrip(t *testing.T) {
	cases := []struct {
		id   ts.Identity
		want string
	}{
		{ts.Identity{Enterprise: "acme", Service: "gateway-api"}, "agentnexus://enterprise/acme/service/gateway-api"},
		{ts.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-7"}, "agentnexus://enterprise/acme/service/connector-agent/installation/agent-7"},
	}
	for _, tc := range cases {
		uri, err := tc.id.URI()
		if err != nil {
			t.Fatalf("URI(%+v): %v", tc.id, err)
		}
		if uri != tc.want {
			t.Errorf("URI(%+v) = %q, want %q", tc.id, uri, tc.want)
		}
		parsed, err := ts.ParseIdentityURI(uri)
		if err != nil {
			t.Fatalf("ParseIdentityURI(%q): %v", uri, err)
		}
		if parsed != tc.id {
			t.Errorf("round trip %q = %+v, want %+v", uri, parsed, tc.id)
		}
	}
}

func TestParseIdentityURIRejectsMalformedIdentities(t *testing.T) {
	bad := []string{
		"",
		"https://enterprise/acme/service/gateway-api",
		"agentnexus://tenant/acme/service/gateway-api",
		"agentnexus://enterprise/acme",
		"agentnexus://enterprise/acme/service",
		"agentnexus://enterprise//service/gateway-api",
		"agentnexus://enterprise/acme/service/gateway-api/installation",
		"agentnexus://enterprise/acme/service/gateway-api/installation/",
		"agentnexus://enterprise/acme/service/gateway-api/extra/tail",
		"agentnexus://enterprise/Acme/service/gateway-api",
		"agentnexus://enterprise/acme/service/gateway api",
		"agentnexus://enterprise/acme/service/-gateway",
	}
	for _, raw := range bad {
		if _, err := ts.ParseIdentityURI(raw); err == nil {
			t.Errorf("ParseIdentityURI(%q) accepted a malformed identity", raw)
		}
	}
}

func TestIdentityValidateRejectsMissingOrInvalidFields(t *testing.T) {
	bad := []ts.Identity{
		{},
		{Enterprise: "acme"},
		{Service: "gateway-api"},
		{Enterprise: "Acme", Service: "gateway-api"},
		{Enterprise: "acme", Service: "gateway api"},
		{Enterprise: "acme", Service: "gateway-api", Installation: "Agent"},
	}
	for _, id := range bad {
		if err := id.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted an invalid identity", id)
		}
	}
	if err := (ts.Identity{Enterprise: "acme", Service: "gateway-api", Installation: "agent-7"}).Validate(); err != nil {
		t.Errorf("valid identity rejected: %v", err)
	}
}

func TestCertificateIdentityRequiresExactlyOneProfileURI(t *testing.T) {
	ca := newTestCA(t, "root")
	id := ts.Identity{Enterprise: "acme", Service: "gateway-api"}
	leaf, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{identityURL(t, id)}})
	got, err := ts.CertificateIdentity(leaf)
	if err != nil {
		t.Fatalf("CertificateIdentity: %v", err)
	}
	if got != id {
		t.Errorf("CertificateIdentity = %+v, want %+v", got, id)
	}

	noURI, _ := issueLeaf(t, ca, leafOptions{})
	if _, err := ts.CertificateIdentity(noURI); err == nil {
		t.Error("certificate without an identity URI SAN was accepted")
	}

	second := identityURL(t, ts.Identity{Enterprise: "acme", Service: "connector-worker"})
	twoURIs, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{identityURL(t, id)}, extraURIs: []*url.URL{second}})
	if _, err := ts.CertificateIdentity(twoURIs); err == nil {
		t.Error("certificate with two agentnexus identity URIs was accepted")
	}
}

func TestPeerIdentityReadsLeafOfConnection(t *testing.T) {
	ca := newTestCA(t, "root")
	id := ts.Identity{Enterprise: "acme", Service: "connector-worker"}
	leaf, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{identityURL(t, id)}})
	got, err := ts.PeerIdentity(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
	if err != nil {
		t.Fatalf("PeerIdentity: %v", err)
	}
	if got != id {
		t.Errorf("PeerIdentity = %+v, want %+v", got, id)
	}
	if _, err := ts.PeerIdentity(tls.ConnectionState{}); err == nil {
		t.Error("PeerIdentity accepted a connection without peer certificates")
	}
}

// --- peer authorization ---

func TestPeerAuthorizationAuthorize(t *testing.T) {
	auth := ts.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-agent", "connector-worker"}}
	if err := auth.Authorize(ts.Identity{Enterprise: "acme", Service: "gateway-agent"}); err != nil {
		t.Errorf("expected peer allowed, got %v", err)
	}
	if err := auth.Authorize(ts.Identity{Enterprise: "acme", Service: "connector-worker", Installation: "any"}); err != nil {
		t.Errorf("installation-free authorization must allow any installation, got %v", err)
	}
	if err := auth.Authorize(ts.Identity{Enterprise: "mallory", Service: "gateway-agent"}); err == nil {
		t.Error("wrong enterprise accepted")
	}
	if err := auth.Authorize(ts.Identity{Enterprise: "acme", Service: "gateway-api"}); err == nil {
		t.Error("service outside the allowed set accepted")
	}

	pinned := ts.PeerAuthorization{Enterprise: "acme", Services: []string{"connector-agent"}, Installation: "agent-7"}
	if err := pinned.Authorize(ts.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-7"}); err != nil {
		t.Errorf("expected pinned installation allowed, got %v", err)
	}
	if err := pinned.Authorize(ts.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-8"}); err == nil {
		t.Error("wrong installation accepted despite installation pinning")
	}
	if err := pinned.Authorize(ts.Identity{Enterprise: "acme", Service: "connector-agent"}); err == nil {
		t.Error("missing installation accepted despite installation pinning")
	}
}

func TestPeerAuthorizationValidate(t *testing.T) {
	bad := []ts.PeerAuthorization{
		{},
		{Enterprise: "acme"},
		{Services: []string{"gateway-api"}},
		{Enterprise: "acme", Services: []string{""}},
		{Enterprise: "Acme", Services: []string{"gateway-api"}},
	}
	for _, auth := range bad {
		if err := auth.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted an invalid authorization", auth)
		}
	}
	if err := (ts.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-api"}}).Validate(); err != nil {
		t.Errorf("valid authorization rejected: %v", err)
	}
}

// --- TLS config builders ---

func testVerifyOptions(t *testing.T, ca testCA) ts.VerifyOptions {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return ts.VerifyOptions{
		Roots: pool,
		Peer:  ts.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-agent"}},
	}
}

func staticCert(cert tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
}

func staticClientCert(cert tls.Certificate) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
}

func TestServerTLSConfigEnforcesProfile(t *testing.T) {
	ca := newTestCA(t, "root")
	opts := testVerifyOptions(t, ca)
	cfg, err := ts.ServerTLSConfig(staticCert(tls.Certificate{}), opts)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != opts.Roots {
		t.Error("ClientCAs must be the provided trust roots")
	}
	if cfg.GetCertificate == nil || cfg.VerifyConnection == nil {
		t.Error("GetCertificate and VerifyConnection must be wired")
	}

	if _, err := ts.ServerTLSConfig(nil, opts); err == nil {
		t.Error("nil certificate getter accepted")
	}
	if _, err := ts.ServerTLSConfig(staticCert(tls.Certificate{}), ts.VerifyOptions{Peer: opts.Peer}); err == nil {
		t.Error("nil trust roots accepted")
	}
	if _, err := ts.ServerTLSConfig(staticCert(tls.Certificate{}), ts.VerifyOptions{Roots: opts.Roots}); err == nil {
		t.Error("invalid peer authorization accepted")
	}
}

func TestClientTLSConfigEnforcesProfile(t *testing.T) {
	ca := newTestCA(t, "root")
	opts := testVerifyOptions(t, ca)
	cfg, err := ts.ClientTLSConfig(staticClientCert(tls.Certificate{}), "gateway.internal", opts)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.RootCAs != opts.Roots {
		t.Error("RootCAs must be the provided trust roots")
	}
	if cfg.ServerName != "gateway.internal" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if cfg.GetClientCertificate == nil || cfg.VerifyConnection == nil {
		t.Error("GetClientCertificate and VerifyConnection must be wired (mutual auth is mandatory)")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must never be set by the profile")
	}

	if _, err := ts.ClientTLSConfig(nil, "gateway.internal", opts); err == nil {
		t.Error("nil client certificate getter accepted: the profile has no server-only mode")
	}
	if _, err := ts.ClientTLSConfig(staticClientCert(tls.Certificate{}), "", opts); err == nil {
		t.Error("empty server name accepted")
	}
	if _, err := ts.ClientTLSConfig(staticClientCert(tls.Certificate{}), "gateway.internal", ts.VerifyOptions{Peer: opts.Peer}); err == nil {
		t.Error("nil trust roots accepted")
	}
}

type revokeAll struct{}

func (revokeAll) CheckRevocation(*x509.Certificate) error { return ts.ErrCertificateRevoked }

func TestVerifyConnectionEnforcesIdentityVersionAndRevocation(t *testing.T) {
	ca := newTestCA(t, "root")
	opts := testVerifyOptions(t, ca)
	cfg, err := ts.ServerTLSConfig(staticCert(tls.Certificate{}), opts)
	if err != nil {
		t.Fatal(err)
	}

	good, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{identityURL(t, ts.Identity{Enterprise: "acme", Service: "gateway-agent"})}})
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{good}}); err != nil {
		t.Errorf("authorized peer rejected: %v", err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{good}}); err == nil {
		t.Error("TLS 1.2 connection accepted by VerifyConnection")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13}); err == nil {
		t.Error("connection without a peer certificate accepted")
	}

	wrongService, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{identityURL(t, ts.Identity{Enterprise: "acme", Service: "gateway-api"})}})
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{wrongService}}); err == nil {
		t.Error("wrong service identity accepted")
	}
	wrongTenant, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{identityURL(t, ts.Identity{Enterprise: "mallory", Service: "gateway-agent"})}})
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{wrongTenant}}); err == nil {
		t.Error("wrong enterprise identity accepted even though the chain is valid")
	}

	optsRevoked := opts
	optsRevoked.Revocation = revokeAll{}
	revokedCfg, err := ts.ServerTLSConfig(staticCert(tls.Certificate{}), optsRevoked)
	if err != nil {
		t.Fatal(err)
	}
	err = revokedCfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{good}})
	if !errors.Is(err, ts.ErrCertificateRevoked) {
		t.Errorf("revoked peer error = %v, want ErrCertificateRevoked", err)
	}
}

// --- trust bundle verification and anti-rollback ---

func newBundleSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestVerifyTrustBundleAcceptsSignedBundle(t *testing.T) {
	ca := newTestCA(t, "root")
	signer := newBundleSigner(t)
	raw := signTestBundle(t, signer, ts.TrustBundle{
		Format:       ts.TrustBundleFormat,
		Sequence:     3,
		IssuedAt:     time.Now().UTC(),
		RootsPEM:     caPEM(t, ca),
		SigningKeyID: "authority-1",
	})
	bundle, roots, err := ts.VerifyTrustBundle(raw, &signer.PublicKey, 2)
	if err != nil {
		t.Fatalf("VerifyTrustBundle: %v", err)
	}
	if bundle.Sequence != 3 {
		t.Errorf("Sequence = %d, want 3", bundle.Sequence)
	}
	if len(roots) != 1 || !roots[0].Equal(ca.cert) {
		t.Errorf("roots = %d certs, want the bundled CA", len(roots))
	}
}

func TestVerifyTrustBundleRejectsRollbackAndForgery(t *testing.T) {
	ca := newTestCA(t, "root")
	signer := newBundleSigner(t)
	bundle := ts.TrustBundle{
		Format:       ts.TrustBundleFormat,
		Sequence:     3,
		IssuedAt:     time.Now().UTC(),
		RootsPEM:     caPEM(t, ca),
		SigningKeyID: "authority-1",
	}
	raw := signTestBundle(t, signer, bundle)

	if _, _, err := ts.VerifyTrustBundle(raw, &signer.PublicKey, 3); !errors.Is(err, ts.ErrStaleTrustBundle) {
		t.Errorf("sequence equal to last seen: err = %v, want ErrStaleTrustBundle", err)
	}
	if _, _, err := ts.VerifyTrustBundle(raw, &signer.PublicKey, 7); !errors.Is(err, ts.ErrStaleTrustBundle) {
		t.Errorf("sequence below last seen: err = %v, want ErrStaleTrustBundle", err)
	}

	otherKey := newBundleSigner(t)
	if _, _, err := ts.VerifyTrustBundle(raw, &otherKey.PublicKey, 0); err == nil {
		t.Error("bundle accepted under the wrong authority key")
	}

	tampered := []byte(strings.Replace(string(raw), `"sequence":3`, `"sequence":9`, 1))
	if _, _, err := ts.VerifyTrustBundle(tampered, &signer.PublicKey, 0); err == nil {
		t.Error("tampered bundle accepted (sequence edited after signing)")
	}

	wrongFormat := bundle
	wrongFormat.Format = "agentnexus-trust-bundle/v0"
	if _, _, err := ts.VerifyTrustBundle(signTestBundle(t, signer, wrongFormat), &signer.PublicKey, 0); err == nil {
		t.Error("unknown bundle format accepted")
	}

	zeroSeq := bundle
	zeroSeq.Sequence = 0
	if _, _, err := ts.VerifyTrustBundle(signTestBundle(t, signer, zeroSeq), &signer.PublicKey, 0); err == nil {
		t.Error("sequence zero accepted")
	}

	nonCA := bundle
	leaf, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{identityURL(t, ts.Identity{Enterprise: "acme", Service: "gateway-api"})}})
	var b strings.Builder
	if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}); err != nil {
		t.Fatal(err)
	}
	nonCA.RootsPEM = b.String()
	if _, _, err := ts.VerifyTrustBundle(signTestBundle(t, signer, nonCA), &signer.PublicKey, 0); err == nil {
		t.Error("bundle whose root is not a CA accepted")
	}

	if _, _, err := ts.VerifyTrustBundle(raw, nil, 0); err == nil {
		t.Error("nil authority key accepted")
	}
}

// --- CRL verification, anti-rollback and revocation checking ---

func signTestCRL(t *testing.T, ca testCA, number int64, revoked []x509.RevocationListEntry, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revoked,
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestVerifyCRLEnforcesSignatureFreshnessAndMonotonicNumber(t *testing.T) {
	ca := newTestCA(t, "root")
	now := time.Now()
	der := signTestCRL(t, ca, 5, nil, now.Add(-time.Hour), now.Add(7*24*time.Hour))

	crl, err := ts.VerifyCRL(der, []*x509.Certificate{ca.cert}, big.NewInt(4), now)
	if err != nil {
		t.Fatalf("VerifyCRL: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("Number = %v, want 5", crl.Number)
	}

	if _, err := ts.VerifyCRL(der, []*x509.Certificate{ca.cert}, big.NewInt(5), now); !errors.Is(err, ts.ErrStaleCRL) {
		t.Errorf("equal CRL number: err = %v, want ErrStaleCRL", err)
	}
	if _, err := ts.VerifyCRL(der, []*x509.Certificate{ca.cert}, big.NewInt(9), now); !errors.Is(err, ts.ErrStaleCRL) {
		t.Errorf("older CRL number: err = %v, want ErrStaleCRL", err)
	}

	stranger := newTestCA(t, "stranger")
	if _, err := ts.VerifyCRL(der, []*x509.Certificate{stranger.cert}, nil, now); err == nil {
		t.Error("CRL accepted although no trusted root signed it")
	}

	expired := signTestCRL(t, ca, 6, nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := ts.VerifyCRL(expired, []*x509.Certificate{ca.cert}, nil, now); err == nil {
		t.Error("CRL past its NextUpdate accepted")
	}
}

func TestRevocationSetChecksSerials(t *testing.T) {
	ca := newTestCA(t, "root")
	id := identityURL(t, ts.Identity{Enterprise: "acme", Service: "gateway-agent"})
	revokedLeaf, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{id}})
	freshLeaf, _ := issueLeaf(t, ca, leafOptions{uris: []*url.URL{id}})

	now := time.Now()
	der := signTestCRL(t, ca, 1, []x509.RevocationListEntry{{SerialNumber: revokedLeaf.SerialNumber, RevocationTime: now}}, now.Add(-time.Hour), now.Add(24*time.Hour))
	crl, err := ts.VerifyCRL(der, []*x509.Certificate{ca.cert}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	set := ts.NewRevocationSet(crl)
	if err := set.CheckRevocation(revokedLeaf); !errors.Is(err, ts.ErrCertificateRevoked) {
		t.Errorf("revoked leaf: err = %v, want ErrCertificateRevoked", err)
	}
	if err := set.CheckRevocation(freshLeaf); err != nil {
		t.Errorf("unrevoked leaf rejected: %v", err)
	}
}
