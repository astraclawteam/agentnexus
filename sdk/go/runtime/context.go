// Package runtime is the canonical Go expression of the vendor-neutral
// AgentNexus Agent runtime contract v1 (ELC-NEXUS-1 candidate).
//
// Frozen boundaries:
//
//   - Public request DTOs carry request/trace correlation, a business-semantic
//     capability, an opaque business-context reference, a parameter hash, a
//     purpose, constraints and an expiry. They NEVER carry trusted identity:
//     tenant, actor, organization version, trust class, risk authority and
//     approval authority come only from verified credentials.
//   - Connector topology (instance IDs, endpoints, table/API paths,
//     credentials, customer network shape) never appears in Agent-facing
//     types; it stays in connector-internal messages.
//   - AgentNexus transmits but never authors approval plans; risk decisions
//     arrive signed from the calling authority.
//
// Contract precedence: this SDK is the NORMATIVE validation surface of the
// frozen contract. The OpenAPI documents describe the same shapes for
// consumers; where an OpenAPI annotation is looser or expressed differently
// (for example OpenAPI 3.0 cannot combine allOf composition with
// additionalProperties: false), the SDK rules win and the runtime rejects
// unknown envelope fields server-side. Length limits in this SDK count BYTES
// (Go len); OpenAPI minLength/maxLength annotations count Unicode code
// points and are descriptive.
//
// Surface note: EvidenceRequest, EvidenceReadRequest and ActionRequest are
// bound to gateway-runtime.yaml operations today. BusinessCapabilityRequest
// and ApprovalRequest are frozen types whose HTTP operations arrive
// additively in later tasks; adding those operations is not a contract
// change.
package runtime

import "time"

// TrustClass is the verified trust classification of the calling Agent
// client. It is derived from verified credentials by the runtime and can
// never be supplied through request JSON. GA Task 0C extends the trust
// registry; the classes themselves are frozen here.
type TrustClass string

const (
	// TrustFirstParty marks a first-party Agent platform client operated
	// under the same trust root as the deployment.
	TrustFirstParty TrustClass = "first_party_trusted"
	// TrustCertifiedThirdParty marks an external provider that passed the
	// published conformance and certification process.
	TrustCertifiedThirdParty TrustClass = "certified_third_party"
	// TrustUntrusted marks every other caller.
	TrustUntrusted TrustClass = "untrusted"
)

// Valid reports whether the trust class is one of the frozen classes.
func (c TrustClass) Valid() bool {
	switch c {
	case TrustFirstParty, TrustCertifiedThirdParty, TrustUntrusted:
		return true
	}
	return false
}

// PrincipalContext is the verified identity context the runtime binds to
// every Agent interaction. It is constructed exclusively from verified
// credentials (mutual TLS, signed client assertions, sealed organization
// snapshots) — there is deliberately no decoder from public request JSON.
type PrincipalContext struct {
	// TenantRef is the opaque verified tenant reference.
	TenantRef string `json:"tenant_ref"`
	// PrincipalRef is the opaque verified actor reference (human or service).
	PrincipalRef string `json:"principal_ref"`
	// AgentClientRef binds the verified Agent client identity.
	AgentClientRef string `json:"agent_client_ref"`
	// AgentReleaseRef binds the verified Agent client release.
	AgentReleaseRef string `json:"agent_release_ref"`
	// TrustClass is the verified trust classification of the client.
	TrustClass TrustClass `json:"trust_class"`
	// OrgSnapshotRef references the sealed organization snapshot the
	// interaction is evaluated against.
	OrgSnapshotRef string `json:"org_snapshot_ref"`
	// VerifiedAt is when the credentials were verified.
	VerifiedAt time.Time `json:"verified_at"`
	// ExpiresAt bounds how long this verified context may be used.
	ExpiresAt time.Time `json:"expires_at"`
}

// Validate applies the canonical PrincipalContext rules.
func (p PrincipalContext) Validate() error {
	if err := requireNonEmpty("tenant_ref", p.TenantRef); err != nil {
		return err
	}
	if err := requireNonEmpty("principal_ref", p.PrincipalRef); err != nil {
		return err
	}
	if err := requireNonEmpty("agent_client_ref", p.AgentClientRef); err != nil {
		return err
	}
	if err := requireNonEmpty("agent_release_ref", p.AgentReleaseRef); err != nil {
		return err
	}
	if !p.TrustClass.Valid() {
		return fieldErrorf("trust_class", "%q is not a frozen trust class", p.TrustClass)
	}
	if err := requireNonEmpty("org_snapshot_ref", p.OrgSnapshotRef); err != nil {
		return err
	}
	if p.VerifiedAt.IsZero() {
		return fieldErrorf("verified_at", "is required")
	}
	if p.ExpiresAt.IsZero() {
		return fieldErrorf("expires_at", "is required")
	}
	if !p.ExpiresAt.After(p.VerifiedAt) {
		return fieldErrorf("expires_at", "must be after verified_at")
	}
	return nil
}
