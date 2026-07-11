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

var ErrInvalidForwardedChain = errors.New("invalid forwarded chain")

type authorizeSourceResolver struct {
	trustedProxyCIDRs []netip.Prefix
}

func NewAuthorizeSourceResolver(trustedProxyCIDRs []netip.Prefix) AuthorizeSourceResolver {
	return &authorizeSourceResolver{trustedProxyCIDRs: append([]netip.Prefix(nil), trustedProxyCIDRs...)}
}

func (r *authorizeSourceResolver) ResolveAuthorizeSource(req *http.Request) (string, error) {
	remote, err := parseRemoteIP(req.RemoteAddr)
	if err != nil {
		return "", ErrInvalidForwardedChain
	}
	source := remote
	if r.trusted(remote) {
		forwarded := req.Header.Values("X-Forwarded-For")
		if len(forwarded) > 0 {
			parts := make([]string, 0, len(forwarded))
			for _, value := range forwarded {
				parts = append(parts, strings.Split(value, ",")...)
			}
			for i := len(parts) - 1; i >= 0; i-- {
				addr, parseErr := parseForwardedIP(parts[i])
				if parseErr != nil {
					return "", ErrInvalidForwardedChain
				}
				if !r.trusted(addr) {
					source = addr
					break
				}
			}
		}
	}
	sum := sha256.Sum256([]byte(canonicalSource(source)))
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
	if parseErr != nil || addr.Zone() != "" {
		return netip.Addr{}, errors.New("invalid remote address")
	}
	return addr.Unmap(), nil
}

func parseForwardedIP(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, ErrInvalidForwardedChain
	}
	return addr.Unmap(), nil
}

func canonicalSource(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		return "ipv4/32:" + addr.String()
	}
	return "ipv6/64:" + netip.PrefixFrom(addr, 64).Masked().Addr().String()
}
