// Package transportsecurity defines the single public AgentNexus TLS/mTLS
// profile shared by every AgentNexus service, agent and enterprise consumer.
//
// The profile is a frozen public contract:
//
//   - Protocol: TLS 1.3 minimum (MinTLSVersion). Anything below is rejected
//     both by tls.Config.MinVersion and, defense in depth, by the
//     per-connection VerifyConnection hook. TLS 1.3 cipher suites are fixed
//     by crypto/tls and intentionally not configurable, so the profile
//     carries no cipher list: setting MinVersion to 1.3 IS the cipher policy.
//   - Mutual authentication always: servers require and verify a client
//     certificate, clients always present one. The profile has no
//     server-only mode.
//   - Peer identity: every certificate carries exactly one URI SAN of the
//     form
//     agentnexus://enterprise/<enterprise>/service/<service>[/installation/<installation>]
//     where each segment matches [a-z0-9]([a-z0-9._-]*[a-z0-9])?. Identities
//     are unique per component, so a single identity can be revoked without
//     collateral damage, and verification rejects wrong-service and
//     wrong-tenant peers even when the certificate chain is valid.
//   - Trust bundle: a JSON document (TrustBundleFormat) carrying the PEM
//     trust roots, signed by the pinned bundle-authority key (ECDSA P-256,
//     ASN.1 signature over SHA-256 of SigningPayload) with a strictly
//     monotonic sequence. Consumers track the last accepted sequence and
//     MUST reject any bundle whose sequence is not strictly newer
//     (anti-rollback for signed offline trust updates).
//   - CRL: a DER X.509 CRL signed by one of the bundled trust roots, with a
//     strictly monotonic Number (anti-rollback) and a mandatory, unexpired
//     NextUpdate. Revocation is enforced per handshake via VerifyConnection,
//     which also runs on TLS session resumption.
//
// The package is dependency-free (standard library only) so that it can be
// consumed anywhere the profile must be enforced or mirrored.
package transportsecurity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// ProfileName names the frozen profile revision.
	ProfileName = "agentnexus-mtls/v1"
	// IdentityURIScheme is the URI SAN scheme carrying peer identity.
	IdentityURIScheme = "agentnexus"
	// TrustBundleFormat is the format marker of signed trust bundles.
	TrustBundleFormat = "agentnexus-trust-bundle/v1"
	// MinTLSVersion is the minimum accepted protocol version (TLS 1.3).
	MinTLSVersion uint16 = tls.VersionTLS13

	identityHost            = "enterprise"
	identityServiceMarker   = "service"
	identityInstallMarker   = "installation"
	identityMaxSegmentBytes = 128
)

// Sentinel errors surfaced by profile enforcement. They are wrapped with
// context, so match them with errors.Is.
var (
	ErrCertificateRevoked = errors.New("transportsecurity: certificate is revoked")
	ErrStaleTrustBundle   = errors.New("transportsecurity: trust bundle sequence is not newer than the last seen sequence")
	ErrStaleCRL           = errors.New("transportsecurity: certificate revocation list number is not newer than the last seen number")
)

// Identity is the unique mTLS identity of one AgentNexus component:
// the owning enterprise (tenant), the service name, and, for installed
// agents such as the Connector Agent, the registered installation.
type Identity struct {
	Enterprise   string
	Service      string
	Installation string
}

// Validate reports whether the identity is well-formed under the profile.
func (id Identity) Validate() error {
	if err := validateSegment("enterprise", id.Enterprise); err != nil {
		return err
	}
	if err := validateSegment("service", id.Service); err != nil {
		return err
	}
	if id.Installation != "" {
		if err := validateSegment("installation", id.Installation); err != nil {
			return err
		}
	}
	return nil
}

// URI renders the identity in the frozen URI SAN scheme.
func (id Identity) URI() (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	uri := IdentityURIScheme + "://" + identityHost + "/" + id.Enterprise + "/" + identityServiceMarker + "/" + id.Service
	if id.Installation != "" {
		uri += "/" + identityInstallMarker + "/" + id.Installation
	}
	return uri, nil
}

// ParseIdentityURI parses and strictly validates an identity URI.
func ParseIdentityURI(raw string) (Identity, error) {
	prefix := IdentityURIScheme + "://" + identityHost + "/"
	if !strings.HasPrefix(raw, prefix) {
		return Identity{}, fmt.Errorf("transportsecurity: identity %q is not an %s://%s/... URI", raw, IdentityURIScheme, identityHost)
	}
	segments := strings.Split(strings.TrimPrefix(raw, prefix), "/")
	if len(segments) != 3 && len(segments) != 5 {
		return Identity{}, fmt.Errorf("transportsecurity: identity %q must have 3 or 5 path segments, has %d", raw, len(segments))
	}
	if segments[1] != identityServiceMarker {
		return Identity{}, fmt.Errorf("transportsecurity: identity %q is missing the %q marker", raw, identityServiceMarker)
	}
	id := Identity{Enterprise: segments[0], Service: segments[2]}
	if len(segments) == 5 {
		if segments[3] != identityInstallMarker {
			return Identity{}, fmt.Errorf("transportsecurity: identity %q is missing the %q marker", raw, identityInstallMarker)
		}
		id.Installation = segments[4]
		if id.Installation == "" {
			return Identity{}, fmt.Errorf("transportsecurity: identity %q has an empty installation segment", raw)
		}
	}
	if err := id.Validate(); err != nil {
		return Identity{}, fmt.Errorf("transportsecurity: identity %q is invalid: %w", raw, err)
	}
	return id, nil
}

func validateSegment(field, segment string) error {
	if segment == "" {
		return fmt.Errorf("transportsecurity: identity %s must not be empty", field)
	}
	if len(segment) > identityMaxSegmentBytes {
		return fmt.Errorf("transportsecurity: identity %s exceeds %d bytes", field, identityMaxSegmentBytes)
	}
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
			if i == 0 || i == len(segment)-1 {
				return fmt.Errorf("transportsecurity: identity %s %q must start and end with a lowercase letter or digit", field, segment)
			}
		default:
			return fmt.Errorf("transportsecurity: identity %s %q contains an invalid character", field, segment)
		}
	}
	return nil
}

// CertificateIdentity extracts the identity of a certificate. The profile
// requires exactly one agentnexus:// URI SAN.
func CertificateIdentity(cert *x509.Certificate) (Identity, error) {
	if cert == nil {
		return Identity{}, errors.New("transportsecurity: no certificate")
	}
	var found []string
	for _, uri := range cert.URIs {
		if uri.Scheme == IdentityURIScheme {
			found = append(found, uri.String())
		}
	}
	if len(found) != 1 {
		return Identity{}, fmt.Errorf("transportsecurity: certificate carries %d %s identity URIs, want exactly 1", len(found), IdentityURIScheme)
	}
	return ParseIdentityURI(found[0])
}

// PeerIdentity extracts the peer identity from a connection state.
func PeerIdentity(cs tls.ConnectionState) (Identity, error) {
	if len(cs.PeerCertificates) == 0 {
		return Identity{}, errors.New("transportsecurity: peer presented no certificate")
	}
	return CertificateIdentity(cs.PeerCertificates[0])
}

// PeerAuthorization states which peer identities one side of a link accepts:
// the peer must belong to Enterprise, its service must be one of Services,
// and, when Installation is set, its installation must match exactly.
type PeerAuthorization struct {
	Enterprise   string
	Services     []string
	Installation string
}

// Validate reports whether the authorization is well-formed.
func (p PeerAuthorization) Validate() error {
	if err := validateSegment("enterprise", p.Enterprise); err != nil {
		return err
	}
	if len(p.Services) == 0 {
		return errors.New("transportsecurity: peer authorization must allow at least one service")
	}
	for _, service := range p.Services {
		if err := validateSegment("service", service); err != nil {
			return err
		}
	}
	if p.Installation != "" {
		if err := validateSegment("installation", p.Installation); err != nil {
			return err
		}
	}
	return nil
}

// Authorize checks a verified peer identity against the authorization.
func (p PeerAuthorization) Authorize(peer Identity) error {
	if peer.Enterprise != p.Enterprise {
		return fmt.Errorf("transportsecurity: peer enterprise %q is not authorized for enterprise %q", peer.Enterprise, p.Enterprise)
	}
	allowed := false
	for _, service := range p.Services {
		if peer.Service == service {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("transportsecurity: peer service %q is not an authorized service (allowed: %s)", peer.Service, strings.Join(p.Services, ", "))
	}
	if p.Installation != "" && peer.Installation != p.Installation {
		return fmt.Errorf("transportsecurity: peer installation %q does not match the bound installation %q", peer.Installation, p.Installation)
	}
	return nil
}

// RevocationChecker decides whether a presented certificate is revoked.
// Implementations must be safe for concurrent use.
type RevocationChecker interface {
	CheckRevocation(cert *x509.Certificate) error
}

// VerifyOptions carries the trust material and peer rules of one link side.
type VerifyOptions struct {
	// Roots are the current trust bundle roots. Servers verify client chains
	// against them, clients verify server chains against them.
	Roots *x509.CertPool
	// Peer is the mandatory peer identity authorization.
	Peer PeerAuthorization
	// Revocation, when set, is consulted for every presented certificate on
	// every handshake (including resumptions).
	Revocation RevocationChecker
}

func (o VerifyOptions) validate() error {
	if o.Roots == nil {
		return errors.New("transportsecurity: trust roots are required")
	}
	if err := o.Peer.Validate(); err != nil {
		return err
	}
	return nil
}

func verifyPeerConnection(opts VerifyOptions) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if cs.Version < MinTLSVersion {
			return fmt.Errorf("transportsecurity: negotiated protocol %#x is below the profile minimum TLS 1.3", cs.Version)
		}
		peer, err := PeerIdentity(cs)
		if err != nil {
			return err
		}
		if err := opts.Peer.Authorize(peer); err != nil {
			return err
		}
		if opts.Revocation != nil {
			for _, cert := range cs.PeerCertificates {
				if err := opts.Revocation.CheckRevocation(cert); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

// ServerTLSConfig builds the single-profile server configuration: TLS 1.3
// minimum, client certificates required and verified against the trust
// roots, and per-handshake peer identity + revocation enforcement.
func ServerTLSConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), opts VerifyOptions) (*tls.Config, error) {
	if getCertificate == nil {
		return nil, errors.New("transportsecurity: a server certificate getter is required")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       MinTLSVersion,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        opts.Roots,
		GetCertificate:   getCertificate,
		VerifyConnection: verifyPeerConnection(opts),
	}, nil
}

// ClientTLSConfig builds the single-profile client configuration: TLS 1.3
// minimum, a client certificate always presented (mutual auth has no opt
// out), standard hostname verification against serverName, and per-handshake
// peer identity + revocation enforcement.
func ClientTLSConfig(getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error), serverName string, opts VerifyOptions) (*tls.Config, error) {
	if getClientCertificate == nil {
		return nil, errors.New("transportsecurity: a client certificate getter is required (the profile is mutual-authentication only)")
	}
	if serverName == "" {
		return nil, errors.New("transportsecurity: a server name is required for hostname verification")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:           MinTLSVersion,
		RootCAs:              opts.Roots,
		ServerName:           serverName,
		GetClientCertificate: getClientCertificate,
		VerifyConnection:     verifyPeerConnection(opts),
	}, nil
}

// TrustBundle is the signed offline trust-root distribution document.
type TrustBundle struct {
	Format       string    `json:"format"`
	Sequence     uint64    `json:"sequence"`
	IssuedAt     time.Time `json:"issued_at"`
	RootsPEM     string    `json:"roots_pem"`
	SigningKeyID string    `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`
}

// SigningPayload is the canonical byte string covered by the bundle
// signature. IssuedAt is canonicalized to UTC UnixNano so signer and
// verifier never disagree on time formatting.
//
// The field ORDER is load-bearing and frozen: the fields are joined by
// newlines and RootsPEM — the only variable-length, newline-bearing field —
// MUST remain last so every field boundary stays unambiguous. Never place a
// newline-bearing field before it, and never append fields in place: adding
// a field requires a NEW bundle format version (a new TrustBundleFormat),
// mirrored by the enterprise management plane.
func (b TrustBundle) SigningPayload() []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%d\n%s\n%s", b.Format, b.Sequence, b.IssuedAt.UTC().UnixNano(), b.SigningKeyID, b.RootsPEM))
}

// VerifyTrustBundle authenticates a trust bundle against the pinned bundle
// authority key and enforces anti-rollback: the bundle sequence must be
// strictly newer than lastSequence (pass 0 when nothing was seen yet).
// It returns the bundle and its parsed CA roots.
func VerifyTrustBundle(raw []byte, authority *ecdsa.PublicKey, lastSequence uint64) (TrustBundle, []*x509.Certificate, error) {
	if authority == nil {
		return TrustBundle{}, nil, errors.New("transportsecurity: a pinned bundle authority key is required")
	}
	var bundle TrustBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return TrustBundle{}, nil, fmt.Errorf("transportsecurity: trust bundle is not well-formed JSON: %w", err)
	}
	if bundle.Format != TrustBundleFormat {
		return TrustBundle{}, nil, fmt.Errorf("transportsecurity: trust bundle format %q, want %q", bundle.Format, TrustBundleFormat)
	}
	digest := sha256.Sum256(bundle.SigningPayload())
	if !ecdsa.VerifyASN1(authority, digest[:], bundle.Signature) {
		return TrustBundle{}, nil, errors.New("transportsecurity: trust bundle signature verification failed")
	}
	if bundle.Sequence == 0 {
		return TrustBundle{}, nil, errors.New("transportsecurity: trust bundle sequence must be at least 1")
	}
	if bundle.Sequence <= lastSequence {
		return TrustBundle{}, nil, fmt.Errorf("%w: got %d, last seen %d", ErrStaleTrustBundle, bundle.Sequence, lastSequence)
	}
	if bundle.IssuedAt.IsZero() {
		return TrustBundle{}, nil, errors.New("transportsecurity: trust bundle carries no issuance time")
	}
	var roots []*x509.Certificate
	rest := []byte(bundle.RootsPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return TrustBundle{}, nil, fmt.Errorf("transportsecurity: trust bundle contains a %q PEM block, want CERTIFICATE", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return TrustBundle{}, nil, fmt.Errorf("transportsecurity: trust bundle root is not a valid certificate: %w", err)
		}
		if !cert.IsCA {
			return TrustBundle{}, nil, errors.New("transportsecurity: trust bundle contains a non-CA certificate")
		}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return TrustBundle{}, nil, errors.New("transportsecurity: trust bundle contains no roots")
	}
	return bundle, roots, nil
}

// VerifyCRL authenticates a DER CRL against the bundled trust roots and
// enforces anti-rollback and freshness: the CRL Number must be strictly
// newer than lastNumber (nil when nothing was seen yet) and NextUpdate must
// be set and not passed.
func VerifyCRL(der []byte, roots []*x509.Certificate, lastNumber *big.Int, now time.Time) (*x509.RevocationList, error) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("transportsecurity: revocation list is not valid DER: %w", err)
	}
	if len(roots) == 0 {
		return nil, errors.New("transportsecurity: no trust roots to verify the revocation list against")
	}
	signed := false
	for _, root := range roots {
		if err := crl.CheckSignatureFrom(root); err == nil {
			signed = true
			break
		}
	}
	if !signed {
		return nil, errors.New("transportsecurity: revocation list is not signed by any trusted root")
	}
	if crl.Number == nil {
		return nil, errors.New("transportsecurity: revocation list carries no monotonic number")
	}
	if lastNumber != nil && crl.Number.Cmp(lastNumber) <= 0 {
		return nil, fmt.Errorf("%w: got %v, last seen %v", ErrStaleCRL, crl.Number, lastNumber)
	}
	if crl.NextUpdate.IsZero() {
		return nil, errors.New("transportsecurity: revocation list carries no next update")
	}
	if now.After(crl.NextUpdate) {
		return nil, fmt.Errorf("transportsecurity: revocation list expired at %s", crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	return crl, nil
}

// RevocationSet is a RevocationChecker backed by the serial numbers of a
// verified CRL. AgentNexus serials are 120-bit random values, so the serial
// alone identifies a certificate within a deployment.
type RevocationSet struct {
	revoked map[string]struct{}
}

// NewRevocationSet builds a revocation set from a verified CRL.
func NewRevocationSet(crl *x509.RevocationList) *RevocationSet {
	set := &RevocationSet{revoked: make(map[string]struct{})}
	if crl == nil {
		return set
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil {
			set.revoked[entry.SerialNumber.Text(16)] = struct{}{}
		}
	}
	return set
}

// CheckRevocation implements RevocationChecker.
func (s *RevocationSet) CheckRevocation(cert *x509.Certificate) error {
	if cert == nil || cert.SerialNumber == nil {
		return errors.New("transportsecurity: no certificate to check for revocation")
	}
	if s == nil || s.revoked == nil {
		return nil
	}
	if _, ok := s.revoked[cert.SerialNumber.Text(16)]; ok {
		return fmt.Errorf("%w: serial %s", ErrCertificateRevoked, cert.SerialNumber.Text(16))
	}
	return nil
}
