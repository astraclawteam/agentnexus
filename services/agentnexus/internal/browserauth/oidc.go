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
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const idTokenLifetime = 5 * time.Minute

type OIDCConfig struct {
	EnterpriseID         string
	EnterpriseIssuerURL  string
	PublicIssuerURL      string
	ClientID             string
	UpstreamClientSecret string
	CallbackURL          string
	ConsoleClients       map[string][]string
	ConsoleCredentials   ConsoleClientCredentials
	SigningKeyID         string
	SigningPrivateKey    crypto.Signer
	PreviousSigningKeys  map[string]crypto.PublicKey
	HTTPTimeout          time.Duration
}

const defaultOIDCHTTPTimeout = 15 * time.Second

func (c OIDCConfig) effectiveHTTPTimeout() (time.Duration, error) {
	if c.HTTPTimeout == 0 {
		return defaultOIDCHTTPTimeout, nil
	}
	if c.HTTPTimeout < time.Millisecond || c.HTTPTimeout > 2*time.Minute {
		return 0, errors.New("OIDC HTTP timeout is out of range")
	}
	return c.HTTPTimeout, nil
}

func (c OIDCConfig) Validate() error {
	if c.EnterpriseID == "" || c.EnterpriseIssuerURL == "" || c.PublicIssuerURL == "" || c.ClientID == "" || c.UpstreamClientSecret == "" || c.CallbackURL == "" || c.SigningKeyID == "" || c.SigningPrivateKey == nil || len(c.ConsoleClients) == 0 {
		return errors.New("browser OIDC configuration incomplete")
	}
	if _, err := c.effectiveHTTPTimeout(); err != nil {
		return err
	}
	if err := validateIssuerURL(c.EnterpriseIssuerURL, false); err != nil {
		return err
	}
	if err := validateIssuerURL(c.PublicIssuerURL, true); err != nil {
		return err
	}
	if err := validateAbsoluteHTTPSURL(c.CallbackURL, true); err != nil {
		return err
	}
	if c.CallbackURL != strings.TrimRight(c.PublicIssuerURL, "/")+"/oauth2/idp/callback" {
		return errors.New("OIDC callback URL must match the public issuer callback endpoint")
	}
	if _, err := signerAlgorithm(c.SigningPrivateKey); err != nil {
		return err
	}
	if err := validatePublicKey(c.SigningPrivateKey.Public()); err != nil {
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
		if !ValidConsoleClientID(clientID) || len(redirects) == 0 {
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
	if err := c.ConsoleCredentials.ValidateClosedSet(c.ConsoleClients); err != nil {
		return err
	}
	return nil
}

func (c OIDCConfig) AuthenticateConsoleClient(clientID, secret string) bool {
	return c.ConsoleCredentials.Authenticate(clientID, secret)
}

func validateIssuerURL(raw string, allowLoopback bool) error {
	if err := validateAbsoluteHTTPSURL(raw, allowLoopback); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.RawQuery != "" {
		return errors.New("issuer URL must not contain a query")
	}
	return nil
}

func (c OIDCConfig) AllowsRedirect(clientID, redirectURI string) bool {
	if !ValidConsoleClientID(clientID) || validateAbsoluteHTTPSURL(redirectURI, true) != nil {
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
		alg, _ := publicKeyAlgorithm(key)
		keys = append(keys, jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(alg), Use: "sig"})
	}
	return json.Marshal(jose.JSONWebKeySet{Keys: keys})
}

func (i *TokenIssuer) Algorithm() string {
	if i == nil {
		return ""
	}
	return string(i.alg)
}

func (i *TokenIssuer) Algorithms() []string {
	if i == nil {
		return []string{}
	}
	result := []string{string(i.alg)}
	seen := map[string]struct{}{string(i.alg): {}}
	kids := make([]string, 0, len(i.config.PreviousSigningKeys))
	for kid := range i.config.PreviousSigningKeys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		alg, _ := publicKeyAlgorithm(i.config.PreviousSigningKeys[kid])
		value := string(alg)
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
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
		if value.E < 3 || value.E%2 == 0 {
			return errors.New("RSA public exponent is invalid")
		}
		return nil
	case *ecdsa.PublicKey:
		if value.Curve == nil {
			return errors.New("ECDSA public key has no curve")
		}
		if value.X == nil || value.Y == nil || !value.Curve.IsOnCurve(value.X, value.Y) {
			return errors.New("ECDSA public key point is invalid")
		}
		switch value.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return nil
		default:
			return errors.New("unsupported ECDSA public curve")
		}
	case ed25519.PublicKey:
		if len(value) != ed25519.PublicKeySize {
			return errors.New("Ed25519 public key has invalid length")
		}
		return nil
	default:
		return errors.New("unsupported public key type")
	}
}

func publicKeyAlgorithm(key crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	if err := validatePublicKey(key); err != nil {
		return "", err
	}
	switch value := key.(type) {
	case *rsa.PublicKey:
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		switch value.Curve.Params().Name {
		case "P-256":
			return jose.ES256, nil
		case "P-384":
			return jose.ES384, nil
		case "P-521":
			return jose.ES512, nil
		}
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	}
	return "", errors.New("unsupported public key type")
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
	clientID string
}

func NewEnterpriseOIDC(ctx context.Context, config OIDCConfig) (*EnterpriseOIDC, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	timeout, _ := config.effectiveHTTPTimeout()
	baseClient, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if baseClient == nil {
		baseClient = http.DefaultClient
	}
	clientCopy := *baseClient
	baseTransport := clientCopy.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	clientCopy.Transport = &oidcTimeoutTransport{base: baseTransport, timeout: timeout}
	if clientCopy.Timeout == 0 || clientCopy.Timeout > timeout {
		clientCopy.Timeout = timeout
	}
	client := &clientCopy
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, config.EnterpriseIssuerURL)
	if err != nil {
		return nil, err
	}
	return &EnterpriseOIDC{oauth2: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.UpstreamClientSecret, Endpoint: provider.Endpoint(), RedirectURL: config.CallbackURL, Scopes: []string{oidc.ScopeOpenID}}, verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}), client: client, clientID: config.ClientID}, nil
}

type oidcTimeoutTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

func (t *oidcTimeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), t.timeout)
	resp, err := t.base.RoundTrip(req.Clone(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	body := &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
	context.AfterFunc(ctx, func() { _ = body.Close() })
	resp.Body = body
	return resp, nil
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (b *cancelOnCloseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		_ = b.Close()
	}
	return n, err
}

func (b *cancelOnCloseBody) Close() error {
	b.once.Do(func() {
		b.cancel()
		b.err = b.ReadCloser.Close()
	})
	return b.err
}

func (o *EnterpriseOIDC) AuthCodeURL(state, nonce string) string {
	return o.oauth2.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.AccessTypeOnline)
}

func (o *EnterpriseOIDC) ExchangeAndVerify(ctx context.Context, code string) (VerifiedIdentity, string, error) {
	if o.client != nil {
		ctx = oidc.ClientContext(ctx, o.client)
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
		Nonce           string `json:"nonce"`
		AuthorizedParty string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return VerifiedIdentity{}, "", err
	}
	if (claims.AuthorizedParty != "" || len(idToken.Audience) > 1) && claims.AuthorizedParty != o.clientID {
		return VerifiedIdentity{}, "", errors.New("upstream ID token authorized party mismatch")
	}
	return VerifiedIdentity{Issuer: idToken.Issuer, Subject: idToken.Subject}, claims.Nonce, nil
}
