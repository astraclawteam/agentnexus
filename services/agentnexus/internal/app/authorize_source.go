package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type AuthorizeSourceResolver interface {
	ResolveAuthorizeSource(*http.Request) (string, error)
}

type authorizeSourceResolver struct {
	trustedProxyCIDRs []netip.Prefix
}

func NewAuthorizeSourceResolver(trustedProxyCIDRs []netip.Prefix) AuthorizeSourceResolver {
	return &authorizeSourceResolver{trustedProxyCIDRs: append([]netip.Prefix(nil), trustedProxyCIDRs...)}
}

func (r *authorizeSourceResolver) ResolveAuthorizeSource(req *http.Request) (string, error) {
	remote, err := parseRemoteIP(req.RemoteAddr)
	if err != nil {
		return "", err
	}
	source := remote
	if r.trusted(remote) {
		if forwarded, ok := parseForwardedFor(strings.Join(req.Header.Values("X-Forwarded-For"), ",")); ok {
			for i := len(forwarded) - 1; i >= 0; i-- {
				if !r.trusted(forwarded[i]) {
					source = forwarded[i]
					break
				}
			}
		}
	}
	sum := sha256.Sum256([]byte(source.String()))
	return hex.EncodeToString(sum[:]), nil
}

func (r *authorizeSourceResolver) trusted(addr netip.Addr) bool {
	for _, prefix := range r.trustedProxyCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parseRemoteIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, parseErr := netip.ParseAddr(strings.TrimSpace(host))
	if parseErr != nil {
		return netip.Addr{}, errors.New("invalid remote address")
	}
	return addr.Unmap(), nil
}

func parseForwardedFor(value string) ([]netip.Addr, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, false
	}
	parts := strings.Split(value, ",")
	addresses := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return nil, false
		}
		addresses = append(addresses, addr.Unmap())
	}
	return addresses, true
}
