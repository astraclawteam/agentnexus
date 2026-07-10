package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
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
		"AGENTNEXUS_BROWSER_AUTH_ENABLED": "true", "AGENTNEXUS_POSTGRES_DSN": "postgres://localhost/agentnexus",
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

func TestLoadBrowserAuthPrefersDeploymentPostgresDSN(t *testing.T) {
	// Reuse the valid key/config fixture from the path-loading test through explicit environment setup.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "key.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	for name, value := range map[string]string{"AGENTNEXUS_BROWSER_AUTH_ENABLED": "true", "AGENTNEXUS_POSTGRES_DSN": "postgres://preferred/agentnexus", "AGENTNEXUS_DATABASE_URL": "postgres://legacy/wrong", "AGENTNEXUS_OIDC_ENTERPRISE_ID": "ent-1", "AGENTNEXUS_OIDC_ENTERPRISE_ISSUER_URL": "https://idp.example.com", "AGENTNEXUS_OIDC_PUBLIC_ISSUER_URL": "https://nexus.example.com", "AGENTNEXUS_OIDC_CLIENT_ID": "nexus", "AGENTNEXUS_OIDC_CLIENT_SECRET": "secret", "AGENTNEXUS_OIDC_CALLBACK_URL": "https://nexus.example.com/oauth2/idp/callback", "AGENTNEXUS_OIDC_CONSOLE_CLIENTS_JSON": `{"atlas":["https://atlas.example.com/cb"]}`, "AGENTNEXUS_OIDC_SIGNING_KEY_ID": "current", "AGENTNEXUS_OIDC_SIGNING_KEY_PATH": path} {
		t.Setenv(name, value)
	}
	cfg, err := LoadBrowserAuth()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "postgres://preferred/agentnexus" {
		t.Fatalf("dsn=%s", cfg.DatabaseURL)
	}
}

func TestLoadBrowserAuthParsesStrictLoginAttemptLimits(t *testing.T) {
	setValidBrowserAuthEnvironment(t)
	cfg, err := LoadBrowserAuth()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoginAttemptLimits != browserauth.DefaultLoginAttemptLimits() {
		t.Fatalf("defaults=%+v", cfg.LoginAttemptLimits)
	}

	t.Setenv("AGENTNEXUS_OIDC_LOGIN_ATTEMPT_PER_BROWSER_LIMIT", "3")
	t.Setenv("AGENTNEXUS_OIDC_LOGIN_ATTEMPT_GLOBAL_LIMIT", "10")
	cfg, err = LoadBrowserAuth()
	if err != nil || cfg.LoginAttemptLimits != (browserauth.LoginAttemptLimits{PerBrowser: 3, Global: 10}) {
		t.Fatalf("configured=%+v err=%v", cfg.LoginAttemptLimits, err)
	}

	for name, values := range map[string][2]string{
		"not integer": {"eight", "4096"},
		"per zero":    {"0", "4096"},
		"per high":    {"65", "4096"},
		"global low":  {"8", "7"},
		"global high": {"8", "65537"},
	} {
		t.Run(name, func(t *testing.T) {
			setValidBrowserAuthEnvironment(t)
			t.Setenv("AGENTNEXUS_OIDC_LOGIN_ATTEMPT_PER_BROWSER_LIMIT", values[0])
			t.Setenv("AGENTNEXUS_OIDC_LOGIN_ATTEMPT_GLOBAL_LIMIT", values[1])
			if _, err := LoadBrowserAuth(); err == nil {
				t.Fatal("invalid limits accepted")
			}
		})
	}
}

func setValidBrowserAuthEnvironment(t *testing.T) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"AGENTNEXUS_BROWSER_AUTH_ENABLED": "true", "AGENTNEXUS_POSTGRES_DSN": "postgres://localhost/agentnexus", "AGENTNEXUS_OIDC_ENTERPRISE_ID": "ent-1", "AGENTNEXUS_OIDC_ENTERPRISE_ISSUER_URL": "https://idp.example.com", "AGENTNEXUS_OIDC_PUBLIC_ISSUER_URL": "https://nexus.example.com", "AGENTNEXUS_OIDC_CLIENT_ID": "nexus", "AGENTNEXUS_OIDC_CLIENT_SECRET": "secret", "AGENTNEXUS_OIDC_CALLBACK_URL": "https://nexus.example.com/oauth2/idp/callback", "AGENTNEXUS_OIDC_CONSOLE_CLIENTS_JSON": `{"atlas":["https://atlas.example.com/cb"]}`, "AGENTNEXUS_OIDC_SIGNING_KEY_ID": "current", "AGENTNEXUS_OIDC_SIGNING_KEY_PATH": path} {
		t.Setenv(name, value)
	}
}
