package browserauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const idTokenLifetime = 5 * time.Minute

type OIDCConfig struct {
	EnterpriseID        string
	EnterpriseIssuerURL string
	PublicIssuerURL     string
	ClientID            string
	ClientSecret        string
	CallbackURL         string
	ConsoleClients      map[string][]string
	SigningKeyID        string
	SigningPrivateKey   crypto.Signer
	PreviousSigningKeys map[string]crypto.PublicKey
}

func (c OIDCConfig) Validate() error {
	if c.EnterpriseID == "" || c.EnterpriseIssuerURL == "" || c.PublicIssuerURL == "" || c.ClientID == "" || c.ClientSecret == "" || c.CallbackURL == "" || c.SigningKeyID == "" || c.SigningPrivateKey == nil || len(c.ConsoleClients) == 0 {
		return errors.New("browser OIDC configuration incomplete")
	}
	for _, raw := range []string{c.EnterpriseIssuerURL, c.PublicIssuerURL} {
		if err := validateIssuerURL(raw); err != nil {
			return err
		}
	}
	if err := validateAbsoluteHTTPSURL(c.CallbackURL, true); err != nil {
		return err
	}
	if _, err := signerAlgorithm(c.SigningPrivateKey); err != nil {
		return err
	}
	seen := map[string]struct{}{c.SigningKeyID: {}}
	for kid, key := range c.PreviousSigningKeys {
		if kid == "" || key == nil {
			return errors.New("previous signing key requires kid and key")
		}
		if _, exists := seen[kid]; exists {
			return fmt.Errorf("duplicate signing kid %q", kid)
		}
		if err := validatePublicKey(key); err != nil {
			return fmt.Errorf("previous signing key %q: %w", kid, err)
		}
		seen[kid] = struct{}{}
	}
	for clientID, redirects := range c.ConsoleClients {
		if clientID == "" || len(redirects) == 0 {
			return errors.New("console client requires exact redirect allow-list")
		}
		unique := map[string]struct{}{}
		for _, redirect := range redirects {
			if err := validateAbsoluteHTTPSURL(redirect, true); err != nil {
				return fmt.Errorf("client %q redirect: %w", clientID, err)
			}
			if _, exists := unique[redirect]; exists {
				return fmt.Errorf("duplicate redirect for client %q", clientID)
			}
			unique[redirect] = struct{}{}
		}
	}
	return nil
}

func validateIssuerURL(raw string) error {
	if err := validateAbsoluteHTTPSURL(raw, false); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.RawQuery != "" {
		return errors.New("issuer URL must not contain a query")
	}
	return nil
}

func (c OIDCConfig) AllowsRedirect(clientID, redirectURI string) bool {
	if validateAbsoluteHTTPSURL(redirectURI, true) != nil {
		return false
	}
	for _, allowed := range c.ConsoleClients[clientID] {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func validateAbsoluteHTTPSURL(raw string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid absolute URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" || !allowLoopbackHTTP {
		return errors.New("URL must use HTTPS")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("HTTP redirect must be loopback")
	}
	return nil
}

type IDTokenInput struct {
	Subject          string
	Audience         string
	Nonce            string
	EnterpriseID     string
	EnterpriseUserID string
}

type TokenIssuer struct {
	config OIDCConfig
	now    func() time.Time
	signer jose.Signer
	alg    jose.SignatureAlgorithm
}

func NewTokenIssuer(config OIDCConfig, now func() time.Time) (*TokenIssuer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	alg, err := signerAlgorithm(config.SigningPrivateKey)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: config.SigningPrivateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", config.SigningKeyID))
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &TokenIssuer{config: config, now: now, signer: signer, alg: alg}, nil
}

func (i *TokenIssuer) SignIDToken(input IDTokenInput) (string, time.Duration, error) {
	if i == nil || input.Subject == "" || input.Audience == "" || input.Nonce == "" || input.EnterpriseID == "" || input.EnterpriseUserID == "" {
		return "", 0, ErrInvalidInput
	}
	now := i.now().UTC()
	claims := struct {
		jwt.Claims
		Nonce            string `json:"nonce"`
		EnterpriseID     string `json:"enterprise_id"`
		EnterpriseUserID string `json:"enterprise_user_id"`
	}{Claims: jwt.Claims{Issuer: i.config.PublicIssuerURL, Subject: input.Subject, Audience: jwt.Audience{input.Audience}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(idTokenLifetime))}, Nonce: input.Nonce, EnterpriseID: input.EnterpriseID, EnterpriseUserID: input.EnterpriseUserID}
	token, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	return token, idTokenLifetime, err
}

func (i *TokenIssuer) JWKS() ([]byte, error) {
	if i == nil {
		return nil, errors.New("token issuer unavailable")
	}
	current := jose.JSONWebKey{Key: i.config.SigningPrivateKey.Public(), KeyID: i.config.SigningKeyID, Algorithm: string(i.alg), Use: "sig"}
	keys := []jose.JSONWebKey{current}
	kids := make([]string, 0, len(i.config.PreviousSigningKeys))
	for kid := range i.config.PreviousSigningKeys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		key := i.config.PreviousSigningKeys[kid]
		keys = append(keys, jose.JSONWebKey{Key: key, KeyID: kid, Use: "sig"})
	}
	return json.Marshal(jose.JSONWebKeySet{Keys: keys})
}

func (i *TokenIssuer) Algorithm() string {
	if i == nil {
		return ""
	}
	return string(i.alg)
}

func DecodeS256Challenge(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func signerAlgorithm(signer crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		if key.N == nil || key.N.BitLen() < 2048 {
			return "", errors.New("RSA signing key must be at least 2048 bits")
		}
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		if key.Curve == nil {
			return "", errors.New("ECDSA signing key has no curve")
		}
		switch key.Curve.Params().Name {
		case "P-256":
			return jose.ES256, nil
		case "P-384":
			return jose.ES384, nil
		case "P-521":
			return jose.ES512, nil
		default:
			return "", errors.New("unsupported ECDSA signing curve")
		}
	case ed25519.PrivateKey:
		return jose.EdDSA, nil
	default:
		return "", errors.New("unsupported signing private key type")
	}
}

func validatePublicKey(key crypto.PublicKey) error {
	switch value := key.(type) {
	case *rsa.PublicKey:
		if value.N == nil || value.N.BitLen() < 2048 {
			return errors.New("RSA public key must be at least 2048 bits")
		}
		return nil
	case *ecdsa.PublicKey:
		if value.Curve == nil {
			return errors.New("ECDSA public key has no curve")
		}
		switch value.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return nil
		default:
			return errors.New("unsupported ECDSA public curve")
		}
	case ed25519.PublicKey:
		return nil
	default:
		return errors.New("unsupported public key type")
	}
}

func LoadSigningPrivateKey(path string) (crypto.Signer, error) {
	if path == "" {
		return nil, errors.New("signing key path required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("signing key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signing key file permissions are too broad")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 || strings.Contains(block.Type, "ENCRYPTED") || len(block.Headers) != 0 {
		return nil, errors.New("malformed or encrypted signing key")
	}
	var parsed any
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errors.New("unexpected signing key PEM type")
	}
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signing private key")
	}
	if _, err := signerAlgorithm(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

func LoadSigningPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("malformed signing public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := validatePublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

type VerifiedIdentity struct{ Issuer, Subject string }

type EnterpriseOIDC struct {
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

func NewEnterpriseOIDC(ctx context.Context, config OIDCConfig) (*EnterpriseOIDC, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(ctx, config.EnterpriseIssuerURL)
	if err != nil {
		return nil, err
	}
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	return &EnterpriseOIDC{oauth2: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, Endpoint: provider.Endpoint(), RedirectURL: config.CallbackURL, Scopes: []string{oidc.ScopeOpenID}}, verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}), client: client}, nil
}

func (o *EnterpriseOIDC) AuthCodeURL(state, nonce string) string {
	return o.oauth2.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.AccessTypeOnline)
}

func (o *EnterpriseOIDC) ExchangeAndVerify(ctx context.Context, code string) (VerifiedIdentity, string, error) {
	if o.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, o.client)
	}
	token, err := o.oauth2.Exchange(ctx, code)
	if err != nil {
		return VerifiedIdentity{}, "", err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return VerifiedIdentity{}, "", errors.New("upstream token response lacks id_token")
	}
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return VerifiedIdentity{}, "", err
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return VerifiedIdentity{}, "", err
	}
	return VerifiedIdentity{Issuer: idToken.Issuer, Subject: idToken.Subject}, claims.Nonce, nil
}
