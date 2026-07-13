// Package secretprovider freezes the AgentNexus Secret Provider contract: the
// authenticated local protocol a service uses to exchange a master credential
// reference for an operation-scoped, short-lived Secret Handle, and the handle
// and derived-secret value types a connector receives in place of any master
// credential.
//
// Contract (GA Task 3):
//
//   - A connector NEVER sees a master credential. It receives only a Handle:
//     opaque metadata bound to one connector identity, one operation, one
//     master version and a single-use or TTL lifetime. The master is absent
//     from the Handle entirely — a Handle carries no secret material at all.
//   - Usable material is obtained by redeeming the Handle at the provider over
//     the authenticated local transport. Redeemed material is derived from the
//     master (a one-way function of it); it is never the master itself and is
//     valid only for the handle's exact scope, version and lifetime.
//   - Every rendering of a Handle or a redeemed Secret redacts its sensitive
//     content: a stray %v, %+v, %#v, String or JSON encoding can never spill a
//     credential into a log line, a connector RPC payload or an audit record.
//   - Rejections are explicit and fail closed: connector identity mismatch,
//     operation-scope mismatch, expired or consumed handle, revoked (or rotated
//     away) master version, unknown credential, unauthenticated caller and
//     provider outage each map to a named sentinel error.
package secretprovider

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Contract sentinels. Callers match these with errors.Is; transports and
// service clients translate their internal failures onto exactly this set.
var (
	// ErrProviderUnavailable marks a provider outage. New secret-requiring
	// operations fail closed on it — there is no plaintext or cached-master
	// fallback.
	ErrProviderUnavailable = errors.New("secret provider unavailable")
	// ErrUnauthenticated marks a caller that did not present the provider's
	// local authentication token.
	ErrUnauthenticated = errors.New("secret provider caller not authenticated")
	// ErrInvalidRequest marks a malformed acquire/redeem request.
	ErrInvalidRequest = errors.New("secret provider request invalid")
	// ErrUnknownCredential marks an acquire for a credential reference the
	// provider does not hold.
	ErrUnknownCredential = errors.New("secret provider credential unknown")
	// ErrInvalidHandle marks a redeem for a handle the provider never issued or
	// has forgotten.
	ErrInvalidHandle = errors.New("secret handle invalid")
	// ErrScopeMismatch marks a handle redeemed under a connector identity or
	// operation other than the one it was issued for.
	ErrScopeMismatch = errors.New("secret handle scope mismatch")
	// ErrHandleExpired marks a redeem after the handle's TTL elapsed.
	ErrHandleExpired = errors.New("secret handle expired")
	// ErrHandleConsumed marks a second redeem of a single-use handle.
	ErrHandleConsumed = errors.New("secret handle already consumed")
	// ErrRevokedVersion marks a redeem of a handle bound to a master version
	// that was revoked or rotated away.
	ErrRevokedVersion = errors.New("secret handle master version revoked")
)

// Scope binds a Secret Handle to exactly one connector identity and one
// operation. A handle issued for one scope can never be revealed for another.
type Scope struct {
	// ConnectorRef is the connector identity the handle is issued to.
	ConnectorRef string `json:"connector_ref"`
	// Resource is the connector resource the operation addresses.
	Resource string `json:"resource"`
	// Operation is the connector operation name.
	Operation string `json:"operation"`
	// Action is the operation action, "read" or "write".
	Action string `json:"action"`
}

// String renders the scope as a stable, non-secret audit label.
func (s Scope) String() string {
	return s.ConnectorRef + "/" + s.Resource + "/" + s.Operation + "/" + s.Action
}

func (s Scope) valid() bool {
	return canonical(s.ConnectorRef) && canonical(s.Resource) && canonical(s.Operation) && canonical(s.Action)
}

// equal compares every scope field with a length-independent compare. Scope
// fields are not secrets, but matching them without an early-exit keeps the
// rejection path free of value-dependent timing and mirrors the trust layer's
// comparison hygiene.
func (s Scope) equal(other Scope) bool {
	return constantTimeEqual(s.ConnectorRef, other.ConnectorRef) &&
		constantTimeEqual(s.Resource, other.Resource) &&
		constantTimeEqual(s.Operation, other.Operation) &&
		constantTimeEqual(s.Action, other.Action)
}

// Handle is the operation-scoped, short-lived reference a connector receives in
// place of a master credential. It is opaque metadata only: it carries no
// secret material. Material for the bound operation is obtained by redeeming
// the handle at the provider.
type Handle struct {
	id        string
	scope     Scope
	version   string
	issuedAt  time.Time
	expiresAt time.Time
	singleUse bool
}

func newHandle(id string, scope Scope, version string, issuedAt, expiresAt time.Time, singleUse bool) (Handle, error) {
	if !canonical(id) || !scope.valid() || !canonical(version) || issuedAt.IsZero() || !expiresAt.After(issuedAt) {
		return Handle{}, ErrInvalidHandle
	}
	return Handle{id: id, scope: scope, version: version, issuedAt: issuedAt, expiresAt: expiresAt, singleUse: singleUse}, nil
}

// ID is the opaque handle identifier used to redeem it.
func (h Handle) ID() string { return h.id }

// Scope is the connector identity and operation the handle is bound to.
func (h Handle) Scope() Scope { return h.scope }

// Version is the opaque master version the handle derives from.
func (h Handle) Version() string { return h.version }

// IssuedAt is when the handle was minted.
func (h Handle) IssuedAt() time.Time { return h.issuedAt }

// ExpiresAt is the handle's TTL boundary.
func (h Handle) ExpiresAt() time.Time { return h.expiresAt }

// SingleUse reports whether the handle may be redeemed at most once.
func (h Handle) SingleUse() bool { return h.singleUse }

// Expired reports whether the handle's TTL has elapsed at the given time.
func (h Handle) Expired(at time.Time) bool { return !at.Before(h.expiresAt) }

// safeView is the only serialized form of a Handle: opaque, non-secret
// metadata. It is what may safely appear in a connector RPC payload or an audit
// record.
type safeView struct {
	ID        string    `json:"handle_id"`
	Scope     Scope     `json:"scope"`
	Version   string    `json:"version"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	SingleUse bool      `json:"single_use"`
}

func (h Handle) view() safeView {
	return safeView{ID: h.id, Scope: h.scope, Version: h.version, IssuedAt: h.issuedAt, ExpiresAt: h.expiresAt, SingleUse: h.singleUse}
}

// MarshalJSON emits only non-secret handle metadata.
func (h Handle) MarshalJSON() ([]byte, error) { return json.Marshal(h.view()) }

// UnmarshalJSON reconstructs a Handle from its transported metadata. It is the
// counterpart of MarshalJSON used by out-of-process Provider clients to rebuild
// the handle they received over the authenticated provider connection. A
// reconstructed handle is only a reference: redeeming it is authoritative and
// re-checks scope, version, expiry and single-use at the provider, so a forged
// or tampered handle grants nothing.
func (h *Handle) UnmarshalJSON(data []byte) error {
	var view safeView
	if err := json.Unmarshal(data, &view); err != nil {
		return err
	}
	rebuilt, err := newHandle(view.ID, view.Scope, view.Version, view.IssuedAt, view.ExpiresAt, view.SingleUse)
	if err != nil {
		return err
	}
	*h = rebuilt
	return nil
}

// String renders the handle for logs without any secret content.
func (h Handle) String() string {
	return fmt.Sprintf("SecretHandle(id=%s scope=%s version=%s single_use=%t expires=%s)",
		h.id, h.scope.String(), h.version, h.singleUse, h.expiresAt.Format(time.RFC3339))
}

// GoString keeps %#v free of secret content.
func (h Handle) GoString() string { return h.String() }

// Secret is derived, operation-scoped credential material returned by a redeem.
// It is not the master credential. It redacts itself in every rendering; the
// material is obtained only through the explicit Reveal call at the point of
// use.
type Secret struct {
	material string
}

// newSecret wraps derived material. It never wraps a master credential.
func newSecret(material string) Secret { return Secret{material: material} }

// SecretFromMaterial reconstructs a redeemed Secret from derived material a
// transport client received over the authenticated provider connection. It is
// the out-of-process counterpart of Redeem's return value; the material must
// already be derived, operation-scoped material — never a master credential.
func SecretFromMaterial(material string) Secret { return Secret{material: material} }

// Reveal returns the derived material. This is the ONLY path to the value; call
// it at the point of use and never store or log the result.
func (s Secret) Reveal() string { return s.material }

// String redacts the material.
func (s Secret) String() string { return "SecretMaterial(redacted)" }

// GoString redacts the material under %#v.
func (s Secret) GoString() string { return s.String() }

// MarshalJSON refuses to serialize material: a redeemed secret must never be
// persisted or transmitted as JSON.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal("[redacted]")
}

// canonical accepts only a non-empty, whitespace-trimmed string that is free of
// control characters (including NUL — this codebase forbids NUL bytes reaching
// audit strings) and free of the '/' character reserved as the Scope.String
// delimiter. Rejecting '/' keeps Scope.String injective across distinct scopes,
// and rejecting control characters keeps every scope, version and credential
// reference safe to place in a log line or audit record.
func canonical(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == '/' {
			return false
		}
	}
	return true
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
