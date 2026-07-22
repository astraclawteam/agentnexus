package agenttrust

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// tenant used across the trust-registry tests.
const testTenant = "ten_alpha"

// deterministicIDs mints canonical, handle-shaped identifiers so tests can
// assert on stable references.
func deterministicIDs() func(string) string {
	counter := 0
	return func(prefix string) string {
		counter++
		return fmt.Sprintf("%s%016d", prefix, counter)
	}
}

// fixture builds a service over an in-memory store with a frozen clock.
func fixture(t *testing.T) (*Service, *MemoryStore, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	svc := NewService(store,
		WithClock(func() time.Time { return now }),
		WithIDGenerator(deterministicIDs()),
	)
	return svc, store, now
}

func firstPartyKey() runtime.SigningKey {
	return runtime.SigningKey{KeyID: "key_release_2026", Algorithm: "ed25519", PublicKey: "cHVibGljLWtleS1ieXRlcw"}
}

func stdRange() runtime.VersionRange {
	return runtime.VersionRange{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"}
}

const stdDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// certifyFirstParty registers and certifies a compliant first-party client and
// returns the client and certification.
func certifyFirstParty(t *testing.T, svc *Service, ceiling []string) (AgentClient, Certification) {
	t.Helper()
	client, err := svc.Register(context.Background(), testTenant, RegisterInput{
		Publisher: "AgentAtlas", Product: "atlas-runtime", EnterpriseRegistered: true,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	cert, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "AgentAtlas", Product: "atlas-runtime", VersionRange: stdRange(),
		SigningKey: firstPartyKey(), ReleaseManifestDigest: stdDigest,
		TrustClass: runtime.TrustFirstParty, CapabilityCeiling: ceiling,
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	return client, cert
}

func compliantRelease() Release {
	return Release{
		Publisher: "AgentAtlas", Product: "atlas-runtime", Version: "1.4.2",
		SigningKeyID: firstPartyKey().KeyID, ReleaseManifestDigest: stdDigest,
	}
}

func TestServiceUnknownAgentDefaultsToUntrusted(t *testing.T) {
	svc, _, _ := fixture(t)
	// A never-registered, never-certified Agent is untrusted and can never
	// reach a side effect, but an explicitly-opened low-risk read is allowed.
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{
		Release:         compliantRelease(),
		Capability:      "knowledge.suggest",
		SideEffect:      false,
		CustomerCeiling: []string{"knowledge.suggest"},
	})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted {
		t.Fatalf("trust class = %q, want untrusted", got.TrustClass)
	}
	if got.SideEffectAllowed {
		t.Fatal("untrusted Agent must never be allowed a side effect")
	}
	if !got.Granted {
		t.Fatal("an explicitly-opened low-risk read should be granted to an untrusted Agent")
	}

	// The same untrusted Agent may not perform a side effect even if the
	// customer tries to open one.
	sideEffect, err := svc.Assess(context.Background(), testTenant, AssessRequest{
		Release:         compliantRelease(),
		Capability:      "knowledge.create",
		SideEffect:      true,
		CustomerCeiling: []string{"knowledge.create"},
	})
	if err != nil {
		t.Fatalf("Assess side effect: %v", err)
	}
	if sideEffect.Granted || sideEffect.SideEffectAllowed {
		t.Fatalf("untrusted side effect must be denied: %+v", sideEffect)
	}
}

func TestServiceNameOnlyFirstPartyImpersonationRejected(t *testing.T) {
	svc, _, _ := fixture(t)
	// A client that merely claims the first-party publisher name but has no
	// signed build manifest must not be certifiable as first party.
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "AgentAtlas", Product: "atlas-runtime", EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "AgentAtlas", Product: "atlas-runtime", VersionRange: stdRange(),
		SigningKey: firstPartyKey(), ReleaseManifestDigest: stdDigest,
		TrustClass: runtime.TrustFirstParty, CapabilityCeiling: []string{"knowledge.create"},
		SignedBuildManifest: false, TTL: time.Hour, // no signed manifest
	})
	if !errors.Is(err, ErrCertificationRejected) {
		t.Fatalf("name-only first-party certification without a signed manifest: err = %v, want ErrCertificationRejected", err)
	}

	// A client not enterprise-registered cannot become first party either.
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "Imposter", Product: "atlas-runtime", EnterpriseRegistered: false}); err != nil {
		t.Fatalf("Register imposter: %v", err)
	}
	_, err = svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "Imposter", Product: "atlas-runtime", VersionRange: stdRange(),
		SigningKey: firstPartyKey(), ReleaseManifestDigest: stdDigest,
		TrustClass: runtime.TrustFirstParty, CapabilityCeiling: []string{"knowledge.create"},
		SignedBuildManifest: true, TTL: time.Hour,
	})
	if !errors.Is(err, ErrCertificationRejected) {
		t.Fatalf("first-party certification without enterprise registration: err = %v, want ErrCertificationRejected", err)
	}
}

func TestServiceWrongPublisherKeyIsUntrusted(t *testing.T) {
	svc, _, _ := fixture(t)
	certifyFirstParty(t, svc, []string{"knowledge.create"})
	// Release presents the certified publisher/product/version but a different
	// signing key — it matches no active certification.
	release := compliantRelease()
	release.SigningKeyID = "key_rotated_attacker"
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted || got.Granted || got.SideEffectAllowed {
		t.Fatalf("wrong publisher key must be untrusted: %+v", got)
	}
}

func TestServiceVersionOutsideRangeIsUntrusted(t *testing.T) {
	svc, _, _ := fixture(t)
	certifyFirstParty(t, svc, []string{"knowledge.create"})
	for _, version := range []string{"0.9.0", "2.0.0", "2.5.1"} {
		release := compliantRelease()
		release.Version = version
		got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
		if err != nil {
			t.Fatalf("Assess %s: %v", version, err)
		}
		if got.TrustClass != runtime.TrustUntrusted || got.SideEffectAllowed {
			t.Fatalf("version %s outside [1.0.0,2.0.0) must be untrusted: %+v", version, got)
		}
	}
	// A version inside the range is trusted.
	inside, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: compliantRelease(), Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess inside: %v", err)
	}
	if inside.TrustClass != runtime.TrustFirstParty || !inside.SideEffectAllowed {
		t.Fatalf("version inside range must be first-party with the side effect allowed: %+v", inside)
	}
}

func TestServiceSigningKeyReplacementRequiresRecertification(t *testing.T) {
	svc, _, now := fixture(t)
	certifyFirstParty(t, svc, []string{"knowledge.create"})

	// An upgraded release re-signed under a new signing identity is NOT trusted
	// on the old certification.
	upgraded := compliantRelease()
	upgraded.Version = "1.9.9"
	upgraded.SigningKeyID = "key_release_2027"
	upgraded.ReleaseManifestDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	before, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: upgraded, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess before recert: %v", err)
	}
	if before.TrustClass != runtime.TrustUntrusted {
		t.Fatalf("upgrade under a replaced signing key must be untrusted until recertified: %+v", before)
	}

	// Recertifying the new signing identity restores trust.
	_ = now
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "AgentAtlas", Product: "atlas-runtime", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_release_2027", Algorithm: "ed25519", PublicKey: "bmV3LXB1YmxpYy1rZXk"},
		ReleaseManifestDigest: upgraded.ReleaseManifestDigest,
		TrustClass:            runtime.TrustFirstParty, CapabilityCeiling: []string{"knowledge.create"},
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("recertify: %v", err)
	}
	after, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: upgraded, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess after recert: %v", err)
	}
	if after.TrustClass != runtime.TrustFirstParty || !after.SideEffectAllowed {
		t.Fatalf("recertified signing identity must restore first-party trust: %+v", after)
	}
}

func TestServiceCertificationExpiryEndsTrust(t *testing.T) {
	store := NewMemoryStore()
	clock := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return clock }
	svc := NewService(store, WithClock(func() time.Time { return nowFn() }), WithIDGenerator(deterministicIDs()))
	certifyFirstParty(t, svc, []string{"knowledge.create"})

	// Advance past the certification lifetime.
	clock = clock.Add(91 * 24 * time.Hour)
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: compliantRelease(), Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted || got.SideEffectAllowed {
		t.Fatalf("expired certification must drop to untrusted: %+v", got)
	}
}

func TestServiceRevocationEndsTrust(t *testing.T) {
	svc, store, _ := fixture(t)
	_, cert := certifyFirstParty(t, svc, []string{"knowledge.create"})

	if _, err := svc.Revoke(context.Background(), testTenant, cert.ID, "key compromise"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: compliantRelease(), Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted || got.SideEffectAllowed {
		t.Fatalf("revoked certification must drop to untrusted: %+v", got)
	}
	// Revocation is an append-only status change; the immutable revision remains.
	changes := store.StatusChanges(testTenant, cert.ID)
	if len(changes) != 2 || changes[0].Status != StatusActive || changes[1].Status != StatusRevoked {
		t.Fatalf("status log = %+v, want [active revoked]", changes)
	}
	if changes[1].PrevHash != changes[0].EventHash || changes[1].EventHash == "" {
		t.Fatalf("status changes must be hash-chained: %+v", changes)
	}
}

func TestServiceCustomerPolicyNarrowsButNeverRaisesCeiling(t *testing.T) {
	svc, _, _ := fixture(t)
	certifyFirstParty(t, svc, []string{"knowledge.suggest", "knowledge.create"})

	// Narrowing: the customer removes create; only suggest remains.
	narrowed, err := svc.Assess(context.Background(), testTenant, AssessRequest{
		Release: compliantRelease(), Capability: "knowledge.create", SideEffect: true,
		CustomerCeiling: []string{"knowledge.suggest"},
	})
	if err != nil {
		t.Fatalf("Assess narrowed: %v", err)
	}
	if narrowed.Granted || narrowed.SideEffectAllowed {
		t.Fatalf("customer narrowing must remove knowledge.create: %+v", narrowed)
	}

	// Escalation: the customer lists a capability ABOVE the certified ceiling.
	// It must never be raised into the effective ceiling.
	escalated, err := svc.Assess(context.Background(), testTenant, AssessRequest{
		Release: compliantRelease(), Capability: "knowledge.approve_high_risk", SideEffect: true,
		CustomerCeiling: []string{"knowledge.suggest", "knowledge.create", "knowledge.approve_high_risk"},
	})
	if err != nil {
		t.Fatalf("Assess escalated: %v", err)
	}
	if escalated.Granted || escalated.SideEffectAllowed {
		t.Fatalf("customer policy must never raise the certified ceiling: %+v", escalated)
	}
}

func TestServiceThirdPartyWithoutCertifiedDecisionProviderCannotSideEffect(t *testing.T) {
	svc, _, _ := fixture(t)
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "PartnerCo", Product: "partner-agent", EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Certified third party but WITHOUT a certified decision provider.
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "PartnerCo", Product: "partner-agent", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_partner", Algorithm: "ed25519", PublicKey: "cGFydG5lci1rZXk"},
		ReleaseManifestDigest: stdDigest, TrustClass: runtime.TrustCertifiedThirdParty,
		CapabilityCeiling:   []string{"knowledge.suggest", "knowledge.create"},
		SignedBuildManifest: true, CertifiedDecisionProvider: false, TTL: 90 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("Certify: %v", err)
	}
	release := Release{Publisher: "PartnerCo", Product: "partner-agent", Version: "1.2.0", SigningKeyID: "key_partner", ReleaseManifestDigest: stdDigest}

	// A side-effect capability is denied without a certified decision provider.
	sideEffect, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess side effect: %v", err)
	}
	if sideEffect.TrustClass != runtime.TrustCertifiedThirdParty {
		t.Fatalf("trust class = %q, want certified_third_party", sideEffect.TrustClass)
	}
	if sideEffect.Granted || sideEffect.SideEffectAllowed {
		t.Fatalf("third party without a certified decision provider must not reach a side effect: %+v", sideEffect)
	}
	// A read within the ceiling is still allowed.
	read, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.suggest", SideEffect: false})
	if err != nil {
		t.Fatalf("Assess read: %v", err)
	}
	if !read.Granted {
		t.Fatalf("third-party low-risk read within the ceiling should be granted: %+v", read)
	}

	// With a certified decision provider, the side effect becomes reachable.
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "PartnerCo", Product: "partner-agent", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_partner", Algorithm: "ed25519", PublicKey: "cGFydG5lci1rZXk"},
		ReleaseManifestDigest: stdDigest, TrustClass: runtime.TrustCertifiedThirdParty,
		CapabilityCeiling:   []string{"knowledge.suggest", "knowledge.create"},
		SignedBuildManifest: true, CertifiedDecisionProvider: true, TTL: 90 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("Certify with provider: %v", err)
	}
	withProvider, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess with provider: %v", err)
	}
	if !withProvider.Granted || !withProvider.SideEffectAllowed {
		t.Fatalf("third party with a certified decision provider should reach the side effect: %+v", withProvider)
	}
}

func TestServiceAstraClawFirstPartyHasNoConnectorCapability(t *testing.T) {
	svc, _, _ := fixture(t)
	// Register AstraClaw/Xiaozhi as a first-party client and certify it — even
	// with a connector capability in the requested ceiling.
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "AstraClaw", Product: "xiaozhi-runtime", Origin: OriginAstraClaw, EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "AstraClaw", Product: "xiaozhi-runtime", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_astraclaw", Algorithm: "ed25519", PublicKey: "YXN0cmFjbGF3LWtleQ"},
		ReleaseManifestDigest: stdDigest, TrustClass: runtime.TrustFirstParty,
		CapabilityCeiling:   []string{"knowledge.create", "connector.erp.write"},
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("Certify: %v", err)
	}
	release := Release{Publisher: "AstraClaw", Product: "xiaozhi-runtime", Version: "1.1.0", SigningKeyID: "key_astraclaw", ReleaseManifestDigest: stdDigest, Origin: OriginAstraClaw}

	// The connector capability is stripped from the effective ceiling even
	// though this is a first-party signed client.
	connector, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "connector.erp.write", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess connector: %v", err)
	}
	if connector.TrustClass != runtime.TrustFirstParty {
		t.Fatalf("AstraClaw is still first party: %+v", connector)
	}
	if connector.Granted || connector.SideEffectAllowed {
		t.Fatalf("AstraClaw first-party signed must have ZERO connector capability: %+v", connector)
	}
	for _, capability := range connector.EffectiveCeiling {
		if capability == "connector.erp.write" {
			t.Fatalf("connector capability must not appear in AstraClaw's effective ceiling: %+v", connector.EffectiveCeiling)
		}
	}
	// A non-connector capability in the ceiling is still usable.
	knowledge, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess knowledge: %v", err)
	}
	if !knowledge.Granted || !knowledge.SideEffectAllowed {
		t.Fatalf("AstraClaw retains its non-connector capabilities: %+v", knowledge)
	}
}

func TestServiceCrossTenantCertificationIsolation(t *testing.T) {
	svc, _, _ := fixture(t)
	certifyFirstParty(t, svc, []string{"knowledge.create"})
	// A different tenant must not inherit tenant alpha's certification (tenant
	// escape): the identical release under another tenant is untrusted.
	got, err := svc.Assess(context.Background(), "ten_beta", AssessRequest{Release: compliantRelease(), Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted || got.SideEffectAllowed {
		t.Fatalf("certification must not cross tenants: %+v", got)
	}
}

func TestCertificationRevisionsAreImmutableAndStatusAppendOnly(t *testing.T) {
	svc, store, now := fixture(t)
	_, cert := certifyFirstParty(t, svc, []string{"knowledge.create"})

	// The certification revision is immutable: the store rejects a re-create of
	// the same identifier.
	if _, err := store.CreateCertification(context.Background(), cert, func() string { return "cst_dup" }, now); !errors.Is(err, ErrCertificationRejected) {
		t.Fatalf("re-creating an existing immutable certification revision must fail: %v", err)
	}

	// Revoking twice appends two status rows and never mutates the prior ones.
	if _, err := svc.Revoke(context.Background(), testTenant, cert.ID, "first"); err != nil {
		t.Fatalf("Revoke 1: %v", err)
	}
	if _, err := svc.Revoke(context.Background(), testTenant, cert.ID, "second"); err != nil {
		t.Fatalf("Revoke 2: %v", err)
	}
	changes := store.StatusChanges(testTenant, cert.ID)
	if len(changes) != 3 {
		t.Fatalf("status log length = %d, want 3 (active + two revocations)", len(changes))
	}
	if changes[0].Status != StatusActive || changes[1].Status != StatusRevoked || changes[2].Status != StatusRevoked {
		t.Fatalf("append-only status log = %+v", changes)
	}
	for i := 1; i < len(changes); i++ {
		if changes[i].PrevHash != changes[i-1].EventHash {
			t.Fatalf("hash chain broken at %d: %+v", i, changes)
		}
	}
}

func TestCertificationFirstPartyRequiresSignedManifestAndEnterpriseRegistration(t *testing.T) {
	svc, _, _ := fixture(t)
	// Certified third party only needs a signed manifest, not enterprise
	// registration; certify one against a not-registered client to prove the
	// first-party requirement is specific to first party.
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "PartnerCo", Product: "partner-agent", EnterpriseRegistered: false}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "PartnerCo", Product: "partner-agent", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_partner", Algorithm: "ed25519", PublicKey: "cGFydG5lci1rZXk"},
		ReleaseManifestDigest: stdDigest, TrustClass: runtime.TrustCertifiedThirdParty,
		CapabilityCeiling: []string{"knowledge.suggest"}, SignedBuildManifest: true, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("certified third party without enterprise registration should be allowed: %v", err)
	}

	// Same third party but without a signed manifest is rejected.
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "PartnerCo", Product: "partner-agent", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_partner", Algorithm: "ed25519", PublicKey: "cGFydG5lci1rZXk"},
		ReleaseManifestDigest: stdDigest, TrustClass: runtime.TrustCertifiedThirdParty,
		CapabilityCeiling: []string{"knowledge.suggest"}, SignedBuildManifest: false, TTL: time.Hour,
	}); !errors.Is(err, ErrCertificationRejected) {
		t.Fatalf("a certification without a signed build manifest must be rejected: %v", err)
	}
}

func TestServiceReleaseManifestDigestMustMatch(t *testing.T) {
	svc, _, _ := fixture(t)
	certifyFirstParty(t, svc, []string{"knowledge.create"})
	// Identical publisher/product/version/signing key, but a DIFFERENT signed
	// release manifest — the binding pins the digest, so this is untrusted.
	mismatched := compliantRelease()
	mismatched.ReleaseManifestDigest = "sha256:" + strings.Repeat("c", 64)
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: mismatched, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess mismatched: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted || got.Granted || got.SideEffectAllowed {
		t.Fatalf("a mismatched release-manifest digest must be untrusted: %+v", got)
	}
	// Control: the exact certified digest is trusted.
	match, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: compliantRelease(), Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess match: %v", err)
	}
	if match.TrustClass != runtime.TrustFirstParty || !match.SideEffectAllowed {
		t.Fatalf("the certified release-manifest digest must be trusted: %+v", match)
	}
}

func TestServiceVersionMinInclusiveBoundary(t *testing.T) {
	svc, _, _ := fixture(t)
	certifyFirstParty(t, svc, []string{"knowledge.create"})
	release := compliantRelease()
	release.Version = "1.0.0" // exactly the inclusive lower bound of [1.0.0, 2.0.0)
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustFirstParty || !got.SideEffectAllowed {
		t.Fatalf("the inclusive lower bound 1.0.0 must be trusted: %+v", got)
	}
}

func TestServiceAstraClawConnectorStaysStrippedUnderCustomerCeiling(t *testing.T) {
	svc, _, _ := fixture(t)
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "AstraClaw", Product: "xiaozhi-runtime", Origin: OriginAstraClaw, EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "AstraClaw", Product: "xiaozhi-runtime", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_astraclaw", Algorithm: "ed25519", PublicKey: "YXN0cmFjbGF3LWtleQ"},
		ReleaseManifestDigest: stdDigest, TrustClass: runtime.TrustFirstParty,
		CapabilityCeiling:   []string{"knowledge.create", "connector.erp.write"},
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("Certify: %v", err)
	}
	release := Release{Publisher: "AstraClaw", Product: "xiaozhi-runtime", Version: "1.1.0", SigningKeyID: "key_astraclaw", ReleaseManifestDigest: stdDigest, Origin: OriginAstraClaw}
	// The customer explicitly lists the connector capability; it must STAY
	// stripped — a customer ceiling narrows, it never resurrects a denied class.
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "connector.erp.write", SideEffect: true, CustomerCeiling: []string{"knowledge.create", "connector.erp.write"}})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.Granted || got.SideEffectAllowed {
		t.Fatalf("a customer ceiling must not resurrect AstraClaw connector capability: %+v", got)
	}
	for _, capability := range got.EffectiveCeiling {
		if capability == "connector.erp.write" {
			t.Fatalf("connector capability leaked into the effective ceiling: %+v", got.EffectiveCeiling)
		}
	}
}

func TestServiceFrozenOriginSurvivesReRegistration(t *testing.T) {
	svc, _, _ := fixture(t)
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "AstraClaw", Product: "xiaozhi-runtime", Origin: OriginAstraClaw, EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Certify(context.Background(), testTenant, CertifyInput{
		Publisher: "AstraClaw", Product: "xiaozhi-runtime", VersionRange: stdRange(),
		SigningKey:            runtime.SigningKey{KeyID: "key_astraclaw", Algorithm: "ed25519", PublicKey: "YXN0cmFjbGF3LWtleQ"},
		ReleaseManifestDigest: stdDigest, TrustClass: runtime.TrustFirstParty,
		CapabilityCeiling:   []string{"knowledge.create", "connector.erp.write"},
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("Certify: %v", err)
	}
	// Re-register the SAME client with the origin cleared. This must NOT weaken
	// the connector denial frozen into the immutable certification.
	if _, err := svc.Register(context.Background(), testTenant, RegisterInput{Publisher: "AstraClaw", Product: "xiaozhi-runtime", Origin: "", EnterpriseRegistered: true}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	// Present a release whose origin is also cleared; only the FROZEN cert origin
	// remains AstraClaw, and it must still strip the connector capability.
	release := Release{Publisher: "AstraClaw", Product: "xiaozhi-runtime", Version: "1.1.0", SigningKeyID: "key_astraclaw", ReleaseManifestDigest: stdDigest, Origin: ""}
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "connector.erp.write", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess connector: %v", err)
	}
	if got.Granted || got.SideEffectAllowed {
		t.Fatalf("re-registering with a cleared origin must not un-strip connector capability: %+v", got)
	}
	// The non-connector capability remains usable.
	knowledge, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess knowledge: %v", err)
	}
	if !knowledge.Granted || !knowledge.SideEffectAllowed {
		t.Fatalf("non-connector capability must remain granted: %+v", knowledge)
	}
}

func TestServiceRevokeRejectsControlByteReason(t *testing.T) {
	svc, _, _ := fixture(t)
	_, cert := certifyFirstParty(t, svc, []string{"knowledge.create"})
	// A reason carrying a control byte (NUL here) is rejected before it can enter
	// the hash preimage or the persisted log.
	if _, err := svc.Revoke(context.Background(), testTenant, cert.ID, "compromised\x00rm -rf"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a reason with a control byte must be rejected: %v", err)
	}
	// The rejected revoke left the certification active (unchanged).
	got, err := svc.Assess(context.Background(), testTenant, AssessRequest{Release: compliantRelease(), Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustFirstParty || !got.SideEffectAllowed {
		t.Fatalf("a rejected revoke must not change certification status: %+v", got)
	}
}
