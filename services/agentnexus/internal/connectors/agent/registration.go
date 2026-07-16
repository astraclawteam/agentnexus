package agent

import (
	"errors"
	"fmt"

	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
)

// ServiceName is the connector agent's mTLS service identity segment.
const ServiceName = "connector-agent"

// ErrIdentityNotCertDerived marks an identity that is not a valid, cert-derived
// connector-agent installation identity.
var ErrIdentityNotCertDerived = errors.New("connector agent identity is not cert-derived")

// AgentIdentity is the GA cert-derived identity of a Connector Agent. It is
// asserted by the mTLS certificate URI SAN (enterprise + installation), issued
// by the PKI — NEVER by caller-supplied JSON authenticated with a shared HMAC
// key (the retired pre-GA model, which let a caller assert its own trusted
// enterprise/actor, forbidden by the GA identity contract, Task 0B). The
// legacy Identity{AgentID, EnterpriseID, DisplayName} + NewRegistrationRequest /
// VerifyRegistrationRequest HMAC surface is removed.
type AgentIdentity struct {
	Enterprise   string
	Installation string
	URI          string
}

// IdentityProvider yields the bound mTLS identity URI. *transportsecurity.Manager
// satisfies it via manager.IdentityURI().
type IdentityProvider interface {
	IdentityURI() string
}

// CertDerivedIdentity parses the manager's bound identity URI into the agent's
// cert-derived identity, asserting it is a connector-agent installation. The
// enterprise and installation come from the certificate the PKI issued, never
// from caller input.
func CertDerivedIdentity(p IdentityProvider) (AgentIdentity, error) {
	if p == nil {
		return AgentIdentity{}, errors.Join(ErrIdentityNotCertDerived, errors.New("no identity provider"))
	}
	uri := p.IdentityURI()
	id, err := sdk.ParseIdentityURI(uri)
	if err != nil {
		return AgentIdentity{}, errors.Join(ErrIdentityNotCertDerived, err)
	}
	if id.Service != ServiceName {
		return AgentIdentity{}, errors.Join(ErrIdentityNotCertDerived, fmt.Errorf("certificate service %q is not %q", id.Service, ServiceName))
	}
	if id.Installation == "" {
		return AgentIdentity{}, errors.Join(ErrIdentityNotCertDerived, errors.New("certificate carries no installation; a GA connector agent identity binds a registered installation"))
	}
	return AgentIdentity{Enterprise: id.Enterprise, Installation: id.Installation, URI: uri}, nil
}
