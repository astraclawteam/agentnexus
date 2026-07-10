package browserauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	loopback.CallbackURL = "http://localhost:8080/oauth2/idp/callback"
	if err := loopback.Validate(); err != nil {
		t.Fatalf("loopback callback rejected: %v", err)
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
	cfg := OIDCConfig{EnterpriseID: "ent-1", EnterpriseIssuerURL: "https://idp.example.com", PublicIssuerURL: "https://nexus.example.com", ClientID: "nexus", ClientSecret: "secret", CallbackURL: "https://nexus.example.com/cb", ConsoleClients: map[string][]string{"atlas": {"https://atlas.example.com/cb"}}, SigningKeyID: "ec", SigningPrivateKey: key}
	issuer, err := NewTokenIssuer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.Algorithm() != string(jose.ES384) {
		t.Fatalf("alg=%s", issuer.Algorithm())
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
