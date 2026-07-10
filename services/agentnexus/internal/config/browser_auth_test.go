package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBrowserAuthIsDisabledWithoutInstallingFakeAuth(t *testing.T) {
	t.Setenv("AGENTNEXUS_BROWSER_AUTH_ENABLED", "false")
	cfg, err := LoadBrowserAuth()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("browser auth enabled")
	}
}

func TestLoadBrowserAuthEnabledFailsClosedOnEveryRequiredSetting(t *testing.T) {
	t.Setenv("AGENTNEXUS_BROWSER_AUTH_ENABLED", "true")
	if _, err := LoadBrowserAuth(); err == nil {
		t.Fatal("incomplete auth configuration accepted")
	}
}

func TestLoadBrowserAuthReadsSigningKeyOnlyFromMountedPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "oidc-signing.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"AGENTNEXUS_BROWSER_AUTH_ENABLED": "true", "AGENTNEXUS_DATABASE_URL": "postgres://localhost/agentnexus",
		"AGENTNEXUS_OIDC_ENTERPRISE_ID": "ent-1", "AGENTNEXUS_OIDC_ENTERPRISE_ISSUER_URL": "https://idp.example.com",
		"AGENTNEXUS_OIDC_PUBLIC_ISSUER_URL": "https://nexus.example.com", "AGENTNEXUS_OIDC_CLIENT_ID": "nexus",
		"AGENTNEXUS_OIDC_CLIENT_SECRET": "secret", "AGENTNEXUS_OIDC_CALLBACK_URL": "https://nexus.example.com/oauth2/idp/callback",
		"AGENTNEXUS_OIDC_CONSOLE_CLIENTS_JSON": `{"agentatlas":["https://atlas.example.com/auth/callback"]}`,
		"AGENTNEXUS_OIDC_SIGNING_KEY_ID":       "current", "AGENTNEXUS_OIDC_SIGNING_KEY_PATH": path,
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	cfg, err := LoadBrowserAuth()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.DatabaseURL == "" || cfg.OIDC.SigningPrivateKey == nil {
		t.Fatalf("cfg=%+v", cfg)
	}
}
