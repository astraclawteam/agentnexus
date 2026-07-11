package browserauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testUpstreamSecret = "Upstream-IdP-client-secret-Q7mV2xK9pR4tY8dF3"
const testDownstreamSecret = "Console-BFF-client-secret-N8xQ3vK7pT4yR9dF2"

func mustTestConsoleCredentials(t *testing.T, clientID string) ConsoleClientCredentials {
	t.Helper()
	credentials, err := NewConsoleClientCredentials(map[string][]string{clientID: {testDownstreamSecret}})
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func TestEnterpriseOIDCHardHTTPTimeoutCancelsJWKSAndAllowsRetry(t *testing.T) {
	key := mustRSAKey(t)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "idp"))
	if err != nil {
		t.Fatal(err)
	}
	issuerURL := "https://idp.example.com"
	claims := struct {
		jwt.Claims
		Nonce string `json:"nonce"`
	}{Claims: jwt.Claims{Issuer: issuerURL, Subject: "subject", Audience: jwt.Audience{"nexus"}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute))}, Nonce: "nonce"}
	rawIDToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	var jwksCalls atomic.Int32
	jwksCanceled := make(chan error, 1)
	transport := &oidcRoundTripFixture{roundTrip: func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			return oidcJSONResponse(r, map[string]any{"issuer": issuerURL, "authorization_endpoint": issuerURL + "/authorize", "token_endpoint": issuerURL + "/token", "jwks_uri": issuerURL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/token":
			return oidcJSONResponse(r, map[string]any{"access_token": "upstream", "token_type": "Bearer", "id_token": rawIDToken})
		case "/jwks":
			if jwksCalls.Add(1) == 1 {
				<-r.Context().Done()
				jwksCanceled <- r.Context().Err()
				return nil, r.Context().Err()
			}
			return oidcJSONResponse(r, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "idp", Algorithm: "RS256", Use: "sig"}}})
		default:
			return nil, fmt.Errorf("unexpected OIDC request: %s %s", r.Method, r.URL)
		}
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	originalTimeout := client.Timeout
	originalTransport := client.Transport
	ctx := oidc.ClientContext(context.Background(), client)
	downstream := mustRSAKey(t)
	hardTimeout := 50 * time.Millisecond
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: issuerURL, PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", UpstreamClientSecret: testUpstreamSecret, CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, ConsoleCredentials: mustTestConsoleCredentials(t, "atlas"), SigningKeyID: "current", SigningPrivateKey: downstream, HTTPTimeout: hardTimeout}
	upstream, err := NewEnterpriseOIDC(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if upstream.client == client || upstream.client.Timeout != hardTimeout {
		t.Fatalf("OIDC client was not cloned with hard timeout: caller=%p internal=%p timeout=%s", client, upstream.client, upstream.client.Timeout)
	}
	if _, _, err := upstream.ExchangeAndVerify(context.Background(), "first"); err == nil {
		t.Fatal("black-hole JWKS unexpectedly succeeded")
	}
	select {
	case err := <-jwksCanceled:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("JWKS request canceled with %v", err)
		}
	default:
		t.Fatal("JWKS RoundTrip did not observe its hard deadline")
	}
	if client.Timeout != originalTimeout || client.Transport != originalTransport {
		t.Fatalf("caller client mutated: timeout=%s transport=%T", client.Timeout, client.Transport)
	}
	identity, nonce, err := upstream.ExchangeAndVerify(context.Background(), "second")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "subject" || nonce != "nonce" || jwksCalls.Load() < 2 {
		t.Fatalf("identity=%+v nonce=%s calls=%d", identity, nonce, jwksCalls.Load())
	}
}

type oidcRoundTripFixture struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (f *oidcRoundTripFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	return f.roundTrip(r)
}

func oidcJSONResponse(r *http.Request, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body)), Request: r}, nil
}

func TestOIDCConfigRejectsUnsafeOrAmbiguousRedirectsAndKeys(t *testing.T) {
	key := mustRSAKey(t)
	valid := OIDCConfig{
		EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com",
		ClientID: "nexus", UpstreamClientSecret: testUpstreamSecret, CallbackURL: "https://nexus.example.com/oauth2/idp/callback",
		ConsoleClients:     map[string][]string{"agentatlas": {"https://atlas.example.com/auth/callback", "http://127.0.0.1:4173/callback"}},
		ConsoleCredentials: mustTestConsoleCredentials(t, "agentatlas"),
		SigningKeyID:       "current", SigningPrivateKey: key, PreviousSigningKeys: map[string]crypto.PublicKey{"previous": &mustRSAKey(t).PublicKey},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	loopback := valid
	loopback.PublicIssuerURL = "http://localhost:8080"
	loopback.CallbackURL = "http://localhost:8080/oauth2/idp/callback"
	if err := loopback.Validate(); err != nil {
		t.Fatalf("loopback callback rejected: %v", err)
	}
	for _, callback := range []string{"https://nexus.example.com/other", "https://nexus.example.com/oauth2/idp/callback?x=1"} {
		cfg := valid
		cfg.CallbackURL = callback
		if err := cfg.Validate(); err == nil {
			t.Fatalf("callback mismatch accepted: %s", callback)
		}
	}
	for _, bad := range []string{"/relative", "https://user@example.com/cb", "https://atlas.example.com/cb#fragment", "http://atlas.example.com/cb"} {
		cfg := valid
		cfg.ConsoleClients = map[string][]string{"agentatlas": {bad}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted redirect %q", bad)
		}
	}
	for _, badIssuer := range []string{"https://idp.example.com?tenant=x", "https://nexus.example.com?tenant=x"} {
		cfg := valid
		cfg.PublicIssuerURL = badIssuer
		if err := cfg.Validate(); err == nil {
			t.Fatalf("issuer base with query accepted: %q", badIssuer)
		}
	}
	cfg := valid
	cfg.PreviousSigningKeys = map[string]crypto.PublicKey{"current": &key.PublicKey}
	if err := cfg.Validate(); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cfg = valid
	cfg.SigningPrivateKey = weak
	if err := cfg.Validate(); err == nil {
		t.Fatal("weak RSA key accepted")
	}
}

func TestTokenIssuerAdvertisesTheECDSACurveAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", UpstreamClientSecret: testUpstreamSecret, CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, ConsoleCredentials: mustTestConsoleCredentials(t, "atlas"), SigningKeyID: "ec", SigningPrivateKey: key}
	issuer, err := NewTokenIssuer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.Algorithm() != string(jose.ES384) {
		t.Fatalf("alg=%s", issuer.Algorithm())
	}
}

func TestTokenIssuerAdvertisesAlgorithmsForMixedRotationKeys(t *testing.T) {
	current := mustRSAKey(t)
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", UpstreamClientSecret: testUpstreamSecret, CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, ConsoleCredentials: mustTestConsoleCredentials(t, "atlas"), SigningKeyID: "rsa", SigningPrivateKey: current, PreviousSigningKeys: map[string]crypto.PublicKey{"ec": &ec.PublicKey, "ed": edPublic}}
	issuer, err := NewTokenIssuer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(issuer.Algorithms(), ","); got != "RS256,ES384,EdDSA" {
		t.Fatalf("algorithms=%s", got)
	}
	raw, err := issuer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	for _, key := range set.Keys {
		if key.Algorithm == "" {
			t.Fatalf("kid %s has no alg", key.KeyID)
		}
	}
}

func TestOIDCConfigRejectsMalformedPreviousPublicKeys(t *testing.T) {
	base := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", UpstreamClientSecret: testUpstreamSecret, CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, ConsoleCredentials: mustTestConsoleCredentials(t, "atlas"), SigningKeyID: "rsa", SigningPrivateKey: mustRSAKey(t)}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	badExponent := mustRSAKey(t).PublicKey
	badExponent.E = 2
	invalidEC := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	invalidEd := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize-1))
	for name, key := range map[string]crypto.PublicKey{"weak-rsa": &weak.PublicKey, "bad-exponent": &badExponent, "bad-point": invalidEC, "bad-ed": invalidEd} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			cfg.PreviousSigningKeys = map[string]crypto.PublicKey{"old": key}
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid public key accepted")
			}
		})
	}
}

func TestJWKSAndIDTokenExposeOnlyPublicRotatableKeys(t *testing.T) {
	current := mustRSAKey(t)
	previous := mustRSAKey(t)
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", UpstreamClientSecret: testUpstreamSecret, CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"agentatlas": {"https://atlas.example.com/cb"}}, ConsoleCredentials: mustTestConsoleCredentials(t, "agentatlas"), SigningKeyID: "current", SigningPrivateKey: current, PreviousSigningKeys: map[string]crypto.PublicKey{"previous": &previous.PublicKey}}
	issuer, err := NewTokenIssuer(cfg, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := issuer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(jwks, &raw); err != nil {
		t.Fatal(err)
	}
	encoded := string(jwks)
	for _, forbidden := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("private JWK member leaked: %s", encoded)
		}
	}
	if !strings.Contains(encoded, `"current"`) || !strings.Contains(encoded, `"previous"`) {
		t.Fatalf("rotation keys=%s", encoded)
	}

	token, ttl, err := issuer.SignIDToken(IDTokenInput{Subject: "user-1", Audience: "agentatlas", Nonce: "nonce-1", EnterpriseID: "ent-1", EnterpriseUserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 5*time.Minute {
		t.Fatalf("ttl=%s", ttl)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		jwt.Claims
		Nonce            string `json:"nonce"`
		EnterpriseID     string `json:"enterprise_id"`
		EnterpriseUserID string `json:"enterprise_user_id"`
	}
	if err := parsed.Claims(&current.PublicKey, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != cfg.PublicIssuerURL || claims.Subject != "user-1" || claims.Audience[0] != "agentatlas" || claims.Nonce != "nonce-1" || claims.EnterpriseID != "ent-1" {
		t.Fatalf("claims=%+v", claims)
	}
	if parsed.Headers[0].KeyID != "current" {
		t.Fatalf("kid=%q", parsed.Headers[0].KeyID)
	}
}

func TestLoadSigningPrivateKeyRejectsPublicEncryptedAndLooseFiles(t *testing.T) {
	dir := t.TempDir()
	key := mustRSAKey(t)
	privatePEM, publicPEM := pemFixtures(t, key)
	privatePath := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningPrivateKey(privatePath); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(publicPath, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningPrivateKey(publicPath); err == nil {
		t.Fatal("public key accepted")
	}
	if runtime.GOOS != "windows" {
		loose := filepath.Join(dir, "loose.pem")
		if err := os.WriteFile(loose, privatePEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSigningPrivateKey(loose); err == nil {
			t.Fatal("loose permissions accepted")
		}
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pemFixtures(t *testing.T, key *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
}
