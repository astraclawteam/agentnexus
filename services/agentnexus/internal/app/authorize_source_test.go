package app

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAuthorizeSourceResolverCanonicalizesRemoteAddress(t *testing.T) {
	resolver := NewAuthorizeSourceResolver(nil)
	req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
	req.RemoteAddr = "[::ffff:192.0.2.10]:4321"
	got, err := resolver.ResolveAuthorizeSource(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizeSourceHash("192.0.2.10"); got != want {
		t.Fatalf("hash=%q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverIgnoresForwardedForFromUntrustedRemote(t *testing.T) {
	resolver := NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
	req.RemoteAddr = "192.0.2.10:4321"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	got, err := resolver.ResolveAuthorizeSource(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizeSourceHash("192.0.2.10"); got != want {
		t.Fatalf("untrusted proxy spoof changed source: %q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverWalksTrustedForwardedChainRightToLeft(t *testing.T) {
	resolver := NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:ffff::/48")})
	req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
	req.RemoteAddr = "10.0.0.10:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7, 2001:db8:ffff::7, 10.0.0.9")
	got, err := resolver.ResolveAuthorizeSource(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizeSourceHash("198.51.100.7"); got != want {
		t.Fatalf("source=%q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverFallsBackToTrustedRemoteOnInvalidForwardedChain(t *testing.T) {
	resolver := NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
	req.RemoteAddr = "10.0.0.10:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, not-an-ip, 10.0.0.9")
	got, err := resolver.ResolveAuthorizeSource(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizeSourceHash("10.0.0.10"); got != want {
		t.Fatalf("invalid chain was trusted: %q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverParsesEveryForwardedForHeaderValue(t *testing.T) {
	resolver := NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
	req.RemoteAddr = "10.0.0.10:4321"
	req.Header.Add("X-Forwarded-For", "203.0.113.9")
	req.Header.Add("X-Forwarded-For", "198.51.100.7, 10.0.0.9")
	got, err := resolver.ResolveAuthorizeSource(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizeSourceHash("198.51.100.7"); got != want {
		t.Fatalf("source=%q want=%q", got, want)
	}
}

func authorizeSourceHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
