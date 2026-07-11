package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"net/netip"
	"regexp"
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
	if want := authorizeSourceHash("ipv4/32:192.0.2.10"); got != want {
		t.Fatalf("hash=%q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverIgnoresForwardedForFromUntrustedRemote(t *testing.T) {
	resolver := NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
	req.RemoteAddr = "192.0.2.10:4321"
	req.Header.Set("X-Forwarded-For", "garbage, fe80::1%eth0, 198.51.100.1")
	got, err := resolver.ResolveAuthorizeSource(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizeSourceHash("ipv4/32:192.0.2.10"); got != want {
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
	if want := authorizeSourceHash("ipv4/32:198.51.100.7"); got != want {
		t.Fatalf("source=%q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverStopsAtFirstUntrustedAddressBeforeLeftGarbage(t *testing.T) {
	resolver := NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
	req.RemoteAddr = "10.0.0.10:4321"
	req.Header.Set("X-Forwarded-For", "garbage, 203.0.113.9, 10.0.0.9")
	got, err := resolver.ResolveAuthorizeSource(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := authorizeSourceHash("ipv4/32:203.0.113.9"); got != want {
		t.Fatalf("source=%q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverRejectsMalformedTrustedSuffix(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    []string
	}{
		{name: "malformed", remoteAddr: "10.0.0.10:4321", headers: []string{"203.0.113.9, garbage, 10.0.0.9"}},
		{name: "empty", remoteAddr: "10.0.0.10:4321", headers: []string{"203.0.113.9", "", "10.0.0.9"}},
		{name: "remote zone", remoteAddr: "[fe80::1%eth0]:4321", headers: []string{"203.0.113.9"}},
		{name: "trusted suffix zone", remoteAddr: "10.0.0.10:4321", headers: []string{"203.0.113.9, fe80::1%eth0"}},
		{name: "client zone", remoteAddr: "10.0.0.10:4321", headers: []string{"fe80::1%eth0, 10.0.0.9"}},
	}
	resolver := NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fe80::/10")})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
			req.RemoteAddr = tt.remoteAddr
			for _, value := range tt.headers {
				req.Header.Add("X-Forwarded-For", value)
			}
			if _, err := resolver.ResolveAuthorizeSource(req); !errors.Is(err, ErrInvalidForwardedChain) {
				t.Fatalf("error=%v want ErrInvalidForwardedChain", err)
			}
		})
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
	if want := authorizeSourceHash("ipv4/32:198.51.100.7"); got != want {
		t.Fatalf("source=%q want=%q", got, want)
	}
}

func TestAuthorizeSourceResolverNormalizesIPv6To64BitSource(t *testing.T) {
	resolver := NewAuthorizeSourceResolver(nil)
	resolve := func(remoteAddr string) string {
		t.Helper()
		req := httptest.NewRequest("GET", "https://nexus.example/oauth2/authorize", nil)
		req.RemoteAddr = remoteAddr
		got, err := resolver.ResolveAuthorizeSource(req)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got) || got == remoteAddr {
			t.Fatalf("source hash=%q", got)
		}
		return got
	}

	a := resolve("[2001:db8:1:2::1]:4321")
	if same64 := resolve("[2001:db8:1:2:ffff::2]:9876"); same64 != a {
		t.Fatalf("same /64 hashes differ: %q != %q", same64, a)
	}
	if same128 := resolve("[2001:db8:1:2::1]:9876"); same128 != a {
		t.Fatalf("same /128 hashes differ: %q != %q", same128, a)
	}
	if other64 := resolve("[2001:db8:1:3::1]:4321"); other64 == a {
		t.Fatalf("different /64 hashes match: %q", other64)
	}
	if ipv4 := resolve("192.0.2.10:4321"); ipv4 == a {
		t.Fatalf("IPv4 and IPv6 source domains match: %q", ipv4)
	}
}

func authorizeSourceHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
