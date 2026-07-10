package browserauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestOIDCConfigRejectsUnsafeOrAmbiguousRedirectsAndKeys(t *testing.T) {
	key := mustRSAKey(t)
	valid := OIDCConfig{
		EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com",
		ClientID: "nexus", ClientSecret: "secret", CallbackURL: "https://nexus.example.com/oauth2/idp/callback",
		ConsoleClients: map[string][]string{"agentatlas": {"https://atlas.example.com/auth/callback", "http://127.0.0.1:4173/callback"}},
		SigningKeyID:   "current", SigningPrivateKey: key, PreviousSigningKeys: map[string]crypto.PublicKey{"previous": &mustRSAKey(t).PublicKey},
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
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", ClientSecret: "secret", CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, SigningKeyID: "ec", SigningPrivateKey: key}
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
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", ClientSecret: "secret", CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, SigningKeyID: "rsa", SigningPrivateKey: current, PreviousSigningKeys: map[string]crypto.PublicKey{"ec": &ec.PublicKey, "ed": edPublic}}
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
	base := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", ClientSecret: "secret", CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, SigningKeyID: "rsa", SigningPrivateKey: mustRSAKey(t)}
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
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", ClientSecret: "secret", CallbackURL: "https://nexus.example.com/oauth2/idp/callback", ConsoleClients: map[string][]string{"agentatlas": {"https://atlas.example.com/cb"}}, SigningKeyID: "current", SigningPrivateKey: current, PreviousSigningKeys: map[string]crypto.PublicKey{"previous": &previous.PublicKey}}
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
