package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// The deployment-authored registration path for the private semantic registry.
//
// WHY A CATALOG AND NOT AN API. Service.RegisterSourceBinding is administrative
// and had no caller anywhere outside tests, so the registry was EMPTY in every
// composed deployment: resolveNeed's GetSourceBinding returned ErrNotFound for
// every data class and locate denied with not_resolvable before it ever reached
// a content source. The surface was registered, healthy to every probe, and
// refused everything. This file is the missing caller.
//
// It is deliberately NOT an HTTP surface. api/openapi/gateway-runtime.yaml is
// the frozen, digest-pinned contract for this service and it declares no
// registry, admin or operator path — 26 operations, none of them this. Adding
// one would be a cross-repo contract change, not a wiring fix, so registration
// arrives as DEPLOYMENT CONFIGURATION: a document the operator supplies at
// startup, which never crosses a wire in either direction.
//
// WHY THE CONNECTOR REFERENCE IS MANDATORY. The evidence plane's production
// ContentSource is the connector runtime, so every real source is connector-
// backed. Rather than let an operator type a private SourceRef — which would be
// a second, parallel place where connector topology is declared, free to drift
// from the customer bindings of migration 000012 — a catalog entry NAMES the
// customer's own connector binding and the pack capability to read through, and
// the SourceRef is DERIVED from that by ConnectorSourceResolver against the
// signed connector_products / connector_bindings tables. Those tables stay the
// single authority for connector topology; this catalog only supplies what they
// do not declare.
//
// WHAT THEY DO NOT DECLARE, and therefore what an operator must state here:
//
//   - The business-semantic DATA CLASS an Agent addresses. A pack declares
//     capabilities (erp.purchase_order.read), never data classes.
//   - The org-placed authorization target (ResourceType/ResourceID) and the
//     AccessCapability the neutral capability evaluator checks against the
//     sealed organization snapshot. A connector binding says nothing about
//     organization placement.
//   - The explicit cached-read grant, the raw-content retention TTL and the
//     observation-authority declaration.
//
// Deriving any of those from a connector binding would be inventing an
// authorization fact, which is exactly what worker.HostFactory refuses to do
// one plane over. So they are declared, and validated here at startup rather
// than discovered as a permanent deny at request time.
//
// WHAT THIS STILL DOES NOT DELIVER. A registered data class makes locate reach
// its content source; it does not make the source answer. With
// PendingContentSource composed, an authorized locate now fails at the fetch
// with 503 evidence_unavailable instead of 403 evidence_denied — the honest
// next failure, and the one the B6 note predicted. Verification-purpose READS
// remain a separate matter entirely: they deny at observation_authority_
// undeclared unless an entry declares an observation authority, and even a
// declaring entry then needs an ObservationProducer implementation (Task 7)
// that this build does not have. A green locate is not evidence that
// verification works.
const SourceCatalogSchemaVersion = "evidence.source_catalog/v1"

// ErrInvalidCatalog marks a source catalog that cannot be applied. It is always
// a startup failure: a deployment that declared its evidence sources wrongly is
// told so, rather than booting into a plane that denies every locate.
var ErrInvalidCatalog = errors.New("evidence source catalog is invalid")

const (
	// connectorSourcePrefix and connectorSourceSeparator render the private
	// SourceRef of a connector-backed data class. The form is deterministic and
	// digest-free ON PURPOSE: it is re-derived identically on every apply, so a
	// restart upserts the same row rather than churning it, and a product
	// upgrade that re-pins the binding to a new pack digest leaves the reference
	// (and every handle bound to it) intact. The pinned pack is re-read from the
	// binding tables at resolution time, so freshness comes from the tables, not
	// from a digest frozen into this string.
	connectorSourcePrefix    = "connector:"
	connectorSourceSeparator = "#"
)

// SourceCatalog is the deployment-authored declaration of the private semantic
// registry. It is read from a file at startup and never from a request body.
type SourceCatalog struct {
	SchemaVersion string          `json:"schema_version"`
	Sources       []CatalogSource `json:"sources"`
}

// Declared reports whether the deployment supplied a catalog at all.
func (c SourceCatalog) Declared() bool { return c.SchemaVersion != "" || len(c.Sources) > 0 }

// CatalogSource declares one data class: which connector operation supplies it,
// which organization-placed capability authorizes reading it, and under what
// caching, retention and observation-authority terms.
type CatalogSource struct {
	TenantRef string `json:"tenant_ref"`
	// DataClass is the business-semantic name an Agent addresses in a data
	// need. It is the ONLY field of this entry that ever appears on a wire.
	DataClass string `json:"data_class"`
	// Connector names the customer connector binding and the pack capability
	// this data class reads through. It is a NAME, not topology: the private
	// SourceRef is derived from the binding tables, never typed here.
	Connector CatalogConnectorRef `json:"connector"`
	// AccessCapability, ResourceType and ResourceID are the authorization
	// target the neutral capability evaluator decides on against the sealed
	// organization snapshot.
	AccessCapability string `json:"access_capability"`
	ResourceType     string `json:"resource_type"`
	ResourceID       string `json:"resource_id"`
	// CachedReadAllowed is the EXPLICIT cached-read grant. Every read in this
	// plane serves locate-staged content, so an entry that omits it registers a
	// data class whose reads all deny at cached_read_not_permitted — legal, and
	// occasionally intended, but rarely what an operator means.
	CachedReadAllowed bool `json:"cached_read_allowed"`
	// RetentionTTLSeconds optionally SHORTENS raw-content retention below the
	// handle expiry; 0 means the handle expiry governs.
	RetentionTTLSeconds int64 `json:"retention_ttl_seconds,omitempty"`
	// ObservationAuthority optionally declares the frozen tier this source
	// reports under and the freshness bound of its observations. Absent, every
	// verification-purpose read of this data class fails CLOSED.
	ObservationAuthority *CatalogObservationAuthority `json:"observation_authority,omitempty"`
}

// CatalogConnectorRef names one customer connector binding and one capability
// declared by the signed pack that binding pins.
type CatalogConnectorRef struct {
	// BindingKey is the customer's own name for their connector instance, as
	// stored in connector_bindings. It is private: it addresses server-side
	// truth and never reaches an Agent-facing surface.
	BindingKey string `json:"binding_key"`
	// Capability is the business-semantic pack capability supplying this data
	// class. It must be declared with a READ effect — see
	// ConnectorSourceResolver.
	Capability string `json:"capability"`
}

// CatalogObservationAuthority is the all-or-nothing observation-authority
// declaration: a frozen tier together with a strictly positive freshness bound.
type CatalogObservationAuthority struct {
	Tier                  string `json:"tier"`
	FreshnessBoundSeconds int64  `json:"freshness_bound_seconds"`
}

// SourceRegistrar is the narrow administrative port a catalog is applied
// through. *Service satisfies it; the interface exists so applying a catalog is
// testable without composing the whole evidence runtime.
type SourceRegistrar interface {
	RegisterSourceBinding(ctx context.Context, binding SourceBinding) (SourceBinding, error)
}

// ConnectorSourceRef is one resolution request against the connector binding
// tables.
type ConnectorSourceRef struct {
	TenantRef  string
	BindingKey string
	Capability string
}

// SourceRef renders the private source reference of a connector-backed data
// class. Callers must have validated the reference first (ValidateConnectorRef);
// the separator is not escaped, so an unvalidated binding key could render an
// ambiguous reference.
func (r ConnectorSourceRef) SourceRef() string {
	return connectorSourcePrefix + r.BindingKey + connectorSourceSeparator + r.Capability
}

// ConnectorSourceResolver turns a catalog entry's connector reference into the
// private SourceRef, against server-side truth.
//
// An implementation MUST refuse a reference it cannot bind to exactly one
// existing customer binding whose pinned, signed pack declares the capability
// with a READ effect. The read requirement is not decoration: the evidence
// plane observes, and registering a data class onto a write-effect capability
// would point locate at a side-effecting operation.
//
// It is a port rather than a concrete type because the binding tables live
// behind a pgx pool the evidence package does not own, and because a resolution
// failure must be an operator-legible startup error rather than a store detail.
type ConnectorSourceResolver interface {
	ResolveConnectorSource(ctx context.Context, ref ConnectorSourceRef) (string, error)
}

// ParseSourceCatalog decodes and fully validates a catalog document. Unknown
// fields are rejected (closed-world, matching the connector SDK's treatment of
// pack and binding documents): a typo in a key that silently defaulted would
// register a binding the operator did not describe.
func ParseSourceCatalog(data []byte) (SourceCatalog, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var catalog SourceCatalog
	if err := dec.Decode(&catalog); err != nil {
		return SourceCatalog{}, fmt.Errorf("%w: decode: %w", ErrInvalidCatalog, err)
	}
	if dec.More() {
		return SourceCatalog{}, fmt.Errorf("%w: the document carries trailing content after the catalog", ErrInvalidCatalog)
	}
	if err := ValidateSourceCatalog(catalog); err != nil {
		return SourceCatalog{}, err
	}
	return catalog, nil
}

// ValidateSourceCatalog checks every rule a catalog must satisfy before any of
// it is applied. Validation is WHOLE-DOCUMENT and happens before the first
// write, so a catalog with a bad entry registers none of its entries rather
// than half of them.
func ValidateSourceCatalog(catalog SourceCatalog) error {
	if catalog.SchemaVersion != SourceCatalogSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidCatalog, SourceCatalogSchemaVersion)
	}
	if len(catalog.Sources) == 0 {
		// An empty catalog is the empty registry with extra steps: every locate
		// would still deny at not_resolvable. An operator who supplied a catalog
		// meant to register something, so say so now.
		return fmt.Errorf("%w: it declares no sources, which leaves every locate denying at not_resolvable", ErrInvalidCatalog)
	}
	seen := make(map[string]bool, len(catalog.Sources))
	for i, source := range catalog.Sources {
		if err := validateCatalogSource(source); err != nil {
			return fmt.Errorf("%w: sources[%d]: %w", ErrInvalidCatalog, i, err)
		}
		// (tenant, data class) is the registry's primary key. Two entries for it
		// would upsert one over the other, silently applying whichever came
		// last, so a duplicate is refused rather than resolved.
		key := source.TenantRef + "\x00" + source.DataClass
		if seen[key] {
			return fmt.Errorf("%w: sources[%d]: data class %q is declared more than once for this tenant",
				ErrInvalidCatalog, i, source.DataClass)
		}
		seen[key] = true
	}
	return nil
}

func validateCatalogSource(source CatalogSource) error {
	for _, field := range []struct{ name, value string }{
		{"tenant_ref", source.TenantRef},
		{"data_class", source.DataClass},
		{"access_capability", source.AccessCapability},
		{"resource_type", source.ResourceType},
		{"resource_id", source.ResourceID},
	} {
		if !canonical(field.value) || hasControlBytes(field.value) {
			return fmt.Errorf("%s must be a non-empty, untrimmable, control-free value", field.name)
		}
	}
	if err := ValidateConnectorRef(source.Connector); err != nil {
		return err
	}
	// The authorization target must be a pair the neutral capability evaluator
	// actually knows. An unknown pair is not a subtle misconfiguration: the
	// evaluator denies every unknown capability at high risk, so the data class
	// would register and then deny every locate at policy_denied forever. That
	// is the same silent shape this whole file exists to end, so it is a startup
	// error.
	if _, _, known := policy.RequiredCapabilityPermission(
		policy.ResourceType(source.ResourceType), policy.Capability(source.AccessCapability),
	); !known {
		return fmt.Errorf("access_capability %q is not a capability the neutral policy grants on resource_type %q, so every locate for this data class would deny at policy_denied",
			source.AccessCapability, source.ResourceType)
	}
	if source.RetentionTTLSeconds < 0 {
		return errors.New("retention_ttl_seconds must not be negative")
	}
	if authority := source.ObservationAuthority; authority != nil {
		if !validAuthorityTier(authority.Tier) {
			return fmt.Errorf("observation_authority.tier %q is not one of the frozen tiers (%s, %s, %s)",
				authority.Tier, AuthorityTierSystemOfRecord, AuthorityTierAuthoritativeReplica, AuthorityTierDerived)
		}
		if authority.FreshnessBoundSeconds <= 0 {
			// Whole seconds is the durable unit of the registry column, so a
			// sub-second bound could not survive the round trip anyway.
			return errors.New("observation_authority.freshness_bound_seconds must be a positive whole number of seconds")
		}
	}
	return nil
}

// ValidateConnectorRef checks a connector reference is renderable as a private
// SourceRef. The separator check is load-bearing: a binding key containing it
// would render a reference that parses back into a different key and capability.
func ValidateConnectorRef(ref CatalogConnectorRef) error {
	if !canonical(ref.BindingKey) || hasControlBytes(ref.BindingKey) {
		return errors.New("connector.binding_key must be a non-empty, untrimmable, control-free value")
	}
	if strings.Contains(ref.BindingKey, connectorSourceSeparator) {
		return fmt.Errorf("connector.binding_key must not contain %q", connectorSourceSeparator)
	}
	if !canonical(ref.Capability) || hasControlBytes(ref.Capability) {
		return errors.New("connector.capability must be a non-empty, untrimmable, control-free value")
	}
	return nil
}

// ApplySourceCatalog registers every declared source binding.
//
// The whole catalog is validated and every connector reference resolved BEFORE
// the first registration, so a catalog naming a connector binding that does not
// exist registers nothing at all rather than leaving the registry half applied.
//
// Applying is IDEMPOTENT by construction, which is what makes running it on
// every startup safe: the upsert keys on (tenant_ref, data_class), never
// rewrites the binding id (so no live handle is rebound), and advances
// source_version monotonically (so no live handle is invalidated and a revived
// tombstone still bumps past it).
func ApplySourceCatalog(ctx context.Context, registrar SourceRegistrar, resolver ConnectorSourceResolver, catalog SourceCatalog) ([]SourceBinding, error) {
	if registrar == nil {
		return nil, fmt.Errorf("%w: no registrar to apply it through", ErrInvalidCatalog)
	}
	if resolver == nil {
		// Fail closed rather than fall back to a caller-supplied SourceRef: an
		// unresolved catalog is precisely the parallel registry this design
		// refuses to become.
		return nil, fmt.Errorf("%w: no connector source resolver is wired, so no source reference can be derived", ErrInvalidCatalog)
	}
	if err := ValidateSourceCatalog(catalog); err != nil {
		return nil, err
	}

	pending := make([]SourceBinding, 0, len(catalog.Sources))
	for i, source := range catalog.Sources {
		ref := ConnectorSourceRef{
			TenantRef:  source.TenantRef,
			BindingKey: source.Connector.BindingKey,
			Capability: source.Connector.Capability,
		}
		sourceRef, err := resolver.ResolveConnectorSource(ctx, ref)
		if err != nil {
			// The entry is named by its business-semantic address only. The
			// binding key stays out of the message for the same reason
			// worker.PostgresBindingResolver keeps binding counts out of its
			// own: tenant and data class are enough for an operator holding the
			// catalog to find the entry.
			return nil, fmt.Errorf("%w: sources[%d]: data class %q of tenant %q does not resolve to a readable connector source: %w",
				ErrInvalidCatalog, i, source.DataClass, source.TenantRef, err)
		}
		if !canonical(sourceRef) || hasControlBytes(sourceRef) {
			return nil, fmt.Errorf("%w: sources[%d]: the resolver returned an unusable source reference", ErrInvalidCatalog, i)
		}
		binding := SourceBinding{
			TenantRef: source.TenantRef,
			DataClass: source.DataClass,
			SourceRef: sourceRef,
			// The connector. prefix is what makes connectorBacked() true, so a
			// catalog-registered data class always requires the credential-
			// derived connector capability at locate AND read. It is derived
			// from the declared capability rather than stated, so a catalog can
			// never register a connector source that opts out of that check.
			SourceCapability:  policy.ConnectorCapabilityPrefix + source.Connector.Capability,
			AccessCapability:  source.AccessCapability,
			ResourceType:      source.ResourceType,
			ResourceID:        source.ResourceID,
			CachedReadAllowed: source.CachedReadAllowed,
			RetentionTTL:      time.Duration(source.RetentionTTLSeconds) * time.Second,
		}
		if authority := source.ObservationAuthority; authority != nil {
			binding.AuthorityTier = authority.Tier
			binding.FreshnessBound = time.Duration(authority.FreshnessBoundSeconds) * time.Second
		}
		pending = append(pending, binding)
	}

	registered := make([]SourceBinding, 0, len(pending))
	for i, binding := range pending {
		stored, err := registrar.RegisterSourceBinding(ctx, binding)
		if err != nil {
			return nil, fmt.Errorf("%w: sources[%d]: registering data class %q of tenant %q: %w",
				ErrInvalidCatalog, i, binding.DataClass, binding.TenantRef, err)
		}
		registered = append(registered, stored)
	}
	return registered, nil
}
