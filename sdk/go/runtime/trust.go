package runtime

import (
	"sort"
	"strconv"
	"strings"
)

// This file is the PUBLIC expression of the Agent-client trust registry
// contract (GA Task 0C). The trust CLASSES themselves are frozen in context.go
// (TrustFirstParty / TrustCertifiedThirdParty / TrustUntrusted); this file adds
// the certification BINDING types every trust registry (open-core and
// enterprise) shares:
//
//   - a certification binds a publisher, a product, a semantic-version range, a
//     signing key, a signed release-manifest digest, a trust class and a
//     capability ceiling;
//   - the capability ceiling is the maximum a customer policy may ever grant.
//     A customer policy may NARROW it, never raise it (Narrow is an
//     intersection);
//   - untrusted is the absence of a certification, so a binding is never
//     untrusted.
//
// The types are zero-dependency data + validation; risk classification and the
// AstraClaw connector-denial rule live in the runtime that consumes them, not
// in these public types.

// VersionRange is the semantic-version window a certification binds. Min is
// inclusive and Max is exclusive; an empty bound is open on that side.
type VersionRange struct {
	MinInclusive string `json:"min_inclusive"`
	MaxExclusive string `json:"max_exclusive"`
}

// Validate checks that the declared bounds are dotted numeric versions and,
// when both are present, that Min precedes Max.
func (r VersionRange) Validate() error {
	if r.MinInclusive == "" && r.MaxExclusive == "" {
		return fieldErrorf("version_range", "requires at least one bound")
	}
	if r.MinInclusive != "" {
		if _, ok := parseVersion(r.MinInclusive); !ok {
			return fieldErrorf("version_range.min_inclusive", "%q is not a dotted numeric version", r.MinInclusive)
		}
	}
	if r.MaxExclusive != "" {
		if _, ok := parseVersion(r.MaxExclusive); !ok {
			return fieldErrorf("version_range.max_exclusive", "%q is not a dotted numeric version", r.MaxExclusive)
		}
	}
	if r.MinInclusive != "" && r.MaxExclusive != "" {
		if cmp, ok := compareVersions(r.MinInclusive, r.MaxExclusive); !ok || cmp >= 0 {
			return fieldErrorf("version_range", "min_inclusive %q must precede max_exclusive %q", r.MinInclusive, r.MaxExclusive)
		}
	}
	return nil
}

// Contains reports whether version falls in [MinInclusive, MaxExclusive).
// Versions are DOTTED-NUMERIC only (for example 1.4.2); a version carrying a
// semver pre-release or build tag (1.4.2-rc1, 1.4.2+build) is non-numeric, is
// never contained, and therefore resolves as untrusted at the trust registry.
func (r VersionRange) Contains(version string) bool {
	if _, ok := parseVersion(version); !ok {
		return false
	}
	if r.MinInclusive != "" {
		if cmp, ok := compareVersions(version, r.MinInclusive); !ok || cmp < 0 {
			return false
		}
	}
	if r.MaxExclusive != "" {
		if cmp, ok := compareVersions(version, r.MaxExclusive); !ok || cmp >= 0 {
			return false
		}
	}
	return true
}

// SigningKey identifies the public signing key the certified release's build
// manifest must be signed by. Rotating the key is a new signing identity that
// requires recertification.
type SigningKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// Validate checks the signing key is a supported, fully specified key.
func (k SigningKey) Validate() error {
	if err := requireNonEmpty("signing_key.key_id", k.KeyID); err != nil {
		return err
	}
	if k.Algorithm != "ed25519" {
		return fieldErrorf("signing_key.algorithm", "%q is not a supported signing algorithm", k.Algorithm)
	}
	if err := requireNonEmpty("signing_key.public_key", k.PublicKey); err != nil {
		return err
	}
	return nil
}

// CapabilityCeiling is the maximum set of business-semantic capabilities a
// certified Agent client may ever exercise. Customer policy may Narrow it but
// never raise it.
type CapabilityCeiling []string

// Allows reports whether capability is within the ceiling.
func (c CapabilityCeiling) Allows(capability string) bool {
	for _, allowed := range c {
		if allowed == capability {
			return true
		}
	}
	return false
}

// Narrow returns the intersection of this ceiling with a customer ceiling: a
// customer policy may only REMOVE capabilities, never add one. A nil customer
// ceiling leaves the certified ceiling unchanged. The result is sorted and
// deduplicated.
func (c CapabilityCeiling) Narrow(customer CapabilityCeiling) CapabilityCeiling {
	if customer == nil {
		return c.normalized()
	}
	keep := map[string]bool{}
	for _, capability := range c {
		if customer.Allows(capability) {
			keep[capability] = true
		}
	}
	out := make(CapabilityCeiling, 0, len(keep))
	for capability := range keep {
		out = append(out, capability)
	}
	sort.Strings(out)
	return out
}

func (c CapabilityCeiling) normalized() CapabilityCeiling {
	seen := map[string]bool{}
	out := make(CapabilityCeiling, 0, len(c))
	for _, capability := range c {
		if !seen[capability] {
			seen[capability] = true
			out = append(out, capability)
		}
	}
	sort.Strings(out)
	return out
}

// CertificationBinding is the immutable set of facts one certification revision
// binds together. It never carries trusted identity or connector topology.
type CertificationBinding struct {
	Publisher             string            `json:"publisher"`
	Product               string            `json:"product"`
	VersionRange          VersionRange      `json:"version_range"`
	SigningKey            SigningKey        `json:"signing_key"`
	ReleaseManifestDigest string            `json:"release_manifest_digest"`
	TrustClass            TrustClass        `json:"trust_class"`
	CapabilityCeiling     CapabilityCeiling `json:"capability_ceiling"`
}

// Validate applies the canonical certification-binding rules.
func (b CertificationBinding) Validate() error {
	if err := requireNonEmpty("publisher", b.Publisher); err != nil {
		return err
	}
	if err := requireNonEmpty("product", b.Product); err != nil {
		return err
	}
	if err := b.VersionRange.Validate(); err != nil {
		return err
	}
	if err := b.SigningKey.Validate(); err != nil {
		return err
	}
	if err := ValidateSHA256Ref(b.ReleaseManifestDigest); err != nil {
		return fieldErrorf("release_manifest_digest", "%v", err)
	}
	if !b.TrustClass.Valid() {
		return fieldErrorf("trust_class", "%q is not a frozen trust class", b.TrustClass)
	}
	// Untrusted is the ABSENCE of certification; a certification binding whose
	// class is untrusted is a contradiction.
	if b.TrustClass == TrustUntrusted {
		return fieldErrorf("trust_class", "a certification binding cannot be untrusted")
	}
	for i, capability := range b.CapabilityCeiling {
		if err := validateCapability(capability); err != nil {
			return fieldErrorf("capability_ceiling", "entry %d: %v", i, err)
		}
	}
	return nil
}

// parseVersion splits a dotted numeric version into its segments. It rejects
// empty, non-numeric and negative segments.
func parseVersion(v string) ([]int, bool) {
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// compareVersions compares two dotted numeric versions, padding the shorter
// with zeros. It returns ok=false when either version is not numeric.
func compareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	n := len(av)
	if len(bv) > n {
		n = len(bv)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}
