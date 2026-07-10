package config

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
)

type BrowserAuthConfig struct {
	Enabled            bool
	DatabaseURL        string
	OIDC               browserauth.OIDCConfig
	LoginAttemptLimits browserauth.LoginAttemptLimits
}

func LoadBrowserAuth() (BrowserAuthConfig, error) {
	enabledValue := strings.TrimSpace(os.Getenv("AGENTNEXUS_BROWSER_AUTH_ENABLED"))
	if enabledValue == "" || enabledValue == "false" {
		return BrowserAuthConfig{}, nil
	}
	if enabledValue != "true" {
		return BrowserAuthConfig{}, errors.New("AGENTNEXUS_BROWSER_AUTH_ENABLED must be true or false")
	}
	dsn := os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_DATABASE_URL")
	}
	limits := browserauth.DefaultLoginAttemptLimits()
	perBrowser, err := optionalPositiveInt("AGENTNEXUS_OIDC_LOGIN_ATTEMPT_PER_BROWSER_LIMIT", limits.PerBrowser)
	if err != nil {
		return BrowserAuthConfig{}, err
	}
	global, err := optionalPositiveInt("AGENTNEXUS_OIDC_LOGIN_ATTEMPT_GLOBAL_LIMIT", limits.Global)
	if err != nil {
		return BrowserAuthConfig{}, err
	}
	limits, err = browserauth.NewLoginAttemptLimits(perBrowser, global)
	if err != nil {
		return BrowserAuthConfig{}, fmt.Errorf("invalid OIDC login attempt limits: %w", err)
	}
	config := BrowserAuthConfig{Enabled: true, DatabaseURL: dsn, LoginAttemptLimits: limits}
	if config.DatabaseURL == "" {
		return BrowserAuthConfig{}, errors.New("AGENTNEXUS_POSTGRES_DSN is required when browser auth is enabled")
	}
	privateKey, err := browserauth.LoadSigningPrivateKey(os.Getenv("AGENTNEXUS_OIDC_SIGNING_KEY_PATH"))
	if err != nil {
		return BrowserAuthConfig{}, fmt.Errorf("load browser OIDC signing key: %w", err)
	}
	clients := map[string][]string{}
	if err := json.Unmarshal([]byte(os.Getenv("AGENTNEXUS_OIDC_CONSOLE_CLIENTS_JSON")), &clients); err != nil {
		return BrowserAuthConfig{}, fmt.Errorf("parse console clients: %w", err)
	}
	previous := map[string]crypto.PublicKey{}
	previousPaths := map[string]string{}
	if raw := strings.TrimSpace(os.Getenv("AGENTNEXUS_OIDC_PREVIOUS_SIGNING_KEYS_JSON")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &previousPaths); err != nil {
			return BrowserAuthConfig{}, fmt.Errorf("parse previous signing keys: %w", err)
		}
		for kid, path := range previousPaths {
			key, err := browserauth.LoadSigningPublicKey(path)
			if err != nil {
				return BrowserAuthConfig{}, fmt.Errorf("load previous signing key %q: %w", kid, err)
			}
			previous[kid] = key
		}
	}
	config.OIDC = browserauth.OIDCConfig{
		EnterpriseID: os.Getenv("AGENTNEXUS_OIDC_ENTERPRISE_ID"), EnterpriseIssuerURL: os.Getenv("AGENTNEXUS_OIDC_ENTERPRISE_ISSUER_URL"),
		PublicIssuerURL: os.Getenv("AGENTNEXUS_OIDC_PUBLIC_ISSUER_URL"), ClientID: os.Getenv("AGENTNEXUS_OIDC_CLIENT_ID"), ClientSecret: os.Getenv("AGENTNEXUS_OIDC_CLIENT_SECRET"),
		CallbackURL: os.Getenv("AGENTNEXUS_OIDC_CALLBACK_URL"), ConsoleClients: clients, SigningKeyID: os.Getenv("AGENTNEXUS_OIDC_SIGNING_KEY_ID"), SigningPrivateKey: privateKey, PreviousSigningKeys: previous,
	}
	if err := config.OIDC.Validate(); err != nil {
		return BrowserAuthConfig{}, err
	}
	return config, nil
}

func optionalPositiveInt(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	return value, nil
}
