package agenttrust

import (
	"context"
	"errors"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// Service is the trust registry service.
type Service struct {
	store Store
	now   func() time.Time
	newID func(prefix string) string
}

// Option configures a Service.
type Option func(*Service)

// WithClock overrides the service clock.
func WithClock(clock func() time.Time) Option {
	return func(s *Service) { s.now = clock }
}

// WithIDGenerator overrides the opaque identifier generator.
func WithIDGenerator(newID func(prefix string) string) Option {
	return func(s *Service) { s.newID = newID }
}

// NewService builds a trust registry over a Store.
func NewService(store Store, opts ...Option) *Service {
	svc := &Service{
		store: store,
		now:   func() time.Time { return time.Now().UTC() },
		newID: randomOpaqueID,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// RegisterInput is the enterprise registration of an Agent client. Enterprise
// registration is the admin act that makes first-party status reachable.
type RegisterInput struct {
	Publisher            string
	Product              string
	Origin               string
	EnterpriseRegistered bool
}

// Register records (or re-registers) an Agent client under a tenant.
//
// Governance note: setting EnterpriseRegistered=false on a re-registration does
// NOT revoke existing certifications — revisions are immutable and each froze
// its enterprise_registered fact at issuance. To end trust for a certified
// release, Revoke the certification (an explicit, audited, append-only act).
func (s *Service) Register(ctx context.Context, tenantRef string, in RegisterInput) (AgentClient, error) {
	if s == nil || s.store == nil {
		return AgentClient{}, ErrRegistryUnavailable
	}
	if !canonical(tenantRef) || !canonical(in.Publisher) || !canonical(in.Product) || !validOrigin(in.Origin) {
		return AgentClient{}, ErrInvalidInput
	}
	client := AgentClient{
		ID:                   s.newID("agc_"),
		TenantRef:            tenantRef,
		Publisher:            in.Publisher,
		Product:              in.Product,
		Origin:               in.Origin,
		EnterpriseRegistered: in.EnterpriseRegistered,
		CreatedAt:            s.now(),
	}
	if !canonical(client.ID) {
		return AgentClient{}, ErrRegistryUnavailable
	}
	stored, err := s.store.CreateAgentClient(ctx, client)
	if err != nil {
		return AgentClient{}, errors.Join(ErrRegistryUnavailable, err)
	}
	return stored, nil
}

// CertifyInput binds one immutable certification revision.
type CertifyInput struct {
	Publisher                 string
	Product                   string
	VersionRange              runtime.VersionRange
	SigningKey                runtime.SigningKey
	ReleaseManifestDigest     string
	TrustClass                runtime.TrustClass
	CapabilityCeiling         []string
	SignedBuildManifest       bool
	CertifiedDecisionProvider bool
	TTL                       time.Duration
}

// Certify issues an immutable certification revision. Prior active revisions of
// the same (tenant, publisher, product) are superseded through append-only
// status changes; the immutable revisions themselves are never mutated.
func (s *Service) Certify(ctx context.Context, tenantRef string, in CertifyInput) (Certification, error) {
	if s == nil || s.store == nil {
		return Certification{}, ErrRegistryUnavailable
	}
	if !canonical(tenantRef) || in.TTL <= 0 {
		return Certification{}, ErrInvalidInput
	}
	binding := runtime.CertificationBinding{
		Publisher:             in.Publisher,
		Product:               in.Product,
		VersionRange:          in.VersionRange,
		SigningKey:            in.SigningKey,
		ReleaseManifestDigest: in.ReleaseManifestDigest,
		TrustClass:            in.TrustClass,
		CapabilityCeiling:     runtime.CapabilityCeiling(in.CapabilityCeiling),
	}
	if err := binding.Validate(); err != nil {
		return Certification{}, errors.Join(ErrCertificationRejected, err)
	}
	// A certification ALWAYS attests a signed build manifest.
	if !in.SignedBuildManifest {
		return Certification{}, errors.Join(ErrCertificationRejected, errors.New("a signed build manifest is required"))
	}
	client, err := s.store.GetAgentClient(ctx, tenantRef, in.Publisher, in.Product)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Certification{}, errors.Join(ErrCertificationRejected, errors.New("agent client is not registered"))
		}
		return Certification{}, errors.Join(ErrRegistryUnavailable, err)
	}
	// First-party status additionally requires enterprise registration; a
	// name-only claim never yields first_party_trusted.
	if in.TrustClass == runtime.TrustFirstParty && !client.EnterpriseRegistered {
		return Certification{}, errors.Join(ErrCertificationRejected, errors.New("first-party status requires enterprise registration"))
	}

	now := s.now()
	cert := Certification{
		ID:                        s.newID("cert_"),
		TenantRef:                 tenantRef,
		AgentClientID:             client.ID,
		Origin:                    client.Origin, // frozen; re-registration can only strengthen the denial
		Binding:                   binding,
		SignedBuildManifest:       in.SignedBuildManifest,
		EnterpriseRegistered:      client.EnterpriseRegistered,
		CertifiedDecisionProvider: in.CertifiedDecisionProvider,
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(in.TTL),
		CreatedAt:                 now,
	}
	if !canonical(cert.ID) {
		return Certification{}, ErrRegistryUnavailable
	}
	// The store assigns the revision, writes the initial active status and
	// supersedes prior active revisions atomically.
	stored, err := s.store.CreateCertification(ctx, cert, func() string { return s.newID("cst_") }, now)
	if err != nil {
		if errors.Is(err, ErrCertificationRejected) {
			return Certification{}, err
		}
		return Certification{}, errors.Join(ErrRegistryUnavailable, err)
	}
	return stored, nil
}

// Revoke appends a revocation status change to a certification. Revocation is
// append-only: the immutable revision and every prior status row are untouched.
func (s *Service) Revoke(ctx context.Context, tenantRef, certificationID, reason string) error {
	if s == nil || s.store == nil {
		return ErrRegistryUnavailable
	}
	if !canonical(tenantRef) || !canonical(certificationID) || hasControlBytes(reason) {
		return ErrInvalidInput
	}
	if _, err := s.store.AppendStatus(ctx, tenantRef, certificationID, StatusRevoked, reason, s.newID("cst_"), s.now()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return errors.Join(ErrRegistryUnavailable, err)
	}
	return nil
}

// Release is the presented, credential-verified release under assessment. In
// real ingress these facts come from verified credentials and the signed build
// manifest; the registry treats them as the certification lookup key.
type Release struct {
	Publisher             string
	Product               string
	Version               string
	SigningKeyID          string
	ReleaseManifestDigest string
	Origin                string
}

// AssessRequest asks whether a presented release may exercise a capability.
// CustomerCeiling is the optional customer narrowing (nil = no narrowing); for
// an untrusted Agent it is the explicitly-opened low-risk read set.
type AssessRequest struct {
	Release         Release
	Capability      string
	SideEffect      bool
	CustomerCeiling []string
}

// Assessment is the resolved trust decision.
type Assessment struct {
	TrustClass        runtime.TrustClass
	Granted           bool
	SideEffectAllowed bool
	Reason            string
	EffectiveCeiling  []string
}

// Assess resolves the effective trust class and capability ceiling of a
// presented release. It never returns an error for an untrusted outcome — an
// unknown Agent is a valid, untrusted assessment.
func (s *Service) Assess(ctx context.Context, tenantRef string, req AssessRequest) (Assessment, error) {
	if s == nil || s.store == nil {
		return Assessment{}, ErrRegistryUnavailable
	}
	if !canonical(tenantRef) || !canonical(req.Capability) {
		return Assessment{}, ErrInvalidInput
	}

	cert, ok, err := s.activeCertification(ctx, tenantRef, req.Release)
	if err != nil {
		return Assessment{}, err
	}
	if !ok {
		// Untrusted default: only an explicitly-opened low-risk READ is granted;
		// a side effect is never reachable.
		granted := !req.SideEffect && runtime.CapabilityCeiling(req.CustomerCeiling).Allows(req.Capability)
		return Assessment{
			TrustClass:        runtime.TrustUntrusted,
			Granted:           granted,
			SideEffectAllowed: false,
			Reason:            "no active certification",
			EffectiveCeiling:  append([]string(nil), req.CustomerCeiling...),
		}, nil
	}

	// Determine the AstraClaw/Xiaozhi origin. The connector denial can only ever
	// STRENGTHEN, never weaken: it fires if the FROZEN certification origin, the
	// live registered client origin, OR the presented release origin is
	// AstraClaw/Xiaozhi. The frozen value defends against a later re-registration
	// that resets origin to "".
	astraClaw := isAstraClawOrigin(cert.Origin) || isAstraClawOrigin(req.Release.Origin)
	if client, err := s.store.GetAgentClient(ctx, tenantRef, req.Release.Publisher, req.Release.Product); err == nil {
		astraClaw = astraClaw || isAstraClawOrigin(client.Origin)
	}

	ceiling := cert.Binding.CapabilityCeiling
	if astraClaw {
		ceiling = stripConnectorCapabilities(ceiling)
	}
	effective := ceiling.Narrow(runtime.CapabilityCeiling(req.CustomerCeiling))
	within := effective.Allows(req.Capability)

	sideEffectPermitted := false
	switch cert.Binding.TrustClass {
	case runtime.TrustFirstParty:
		sideEffectPermitted = true
	case runtime.TrustCertifiedThirdParty:
		// A certified third party reaches a side effect only with a certified
		// Policy Decision Provider (the provider flow is GA Task 0F).
		sideEffectPermitted = cert.CertifiedDecisionProvider
	}

	assessment := Assessment{
		TrustClass:       cert.Binding.TrustClass,
		EffectiveCeiling: []string(effective),
	}
	if req.SideEffect {
		assessment.Granted = within && sideEffectPermitted
		assessment.SideEffectAllowed = assessment.Granted
		if !within {
			assessment.Reason = "capability outside effective ceiling"
		} else if !sideEffectPermitted {
			assessment.Reason = "side effect requires a certified decision provider"
		} else {
			assessment.Reason = "granted"
		}
	} else {
		assessment.Granted = within
		assessment.SideEffectAllowed = false
		if within {
			assessment.Reason = "read granted"
		} else {
			assessment.Reason = "capability outside effective ceiling"
		}
	}
	return assessment, nil
}

// activeCertification resolves the newest certification whose binding covers the
// presented release (version in range, signing key match, release-manifest
// digest match), that is neither expired nor revoked/superseded.
func (s *Service) activeCertification(ctx context.Context, tenantRef string, release Release) (Certification, bool, error) {
	if !canonical(release.Publisher) || !canonical(release.Product) {
		return Certification{}, false, nil
	}
	certs, err := s.store.ListCertifications(ctx, tenantRef, release.Publisher, release.Product)
	if err != nil {
		return Certification{}, false, errors.Join(ErrRegistryUnavailable, err)
	}
	now := s.now()
	for _, cert := range certs {
		if !cert.Binding.VersionRange.Contains(release.Version) {
			continue
		}
		if cert.Binding.SigningKey.KeyID != release.SigningKeyID {
			continue
		}
		if cert.Binding.ReleaseManifestDigest != release.ReleaseManifestDigest {
			continue
		}
		if !now.Before(cert.ExpiresAt) {
			continue // time-derived expiry
		}
		latest, err := s.store.LatestStatus(ctx, tenantRef, cert.ID)
		if err != nil {
			return Certification{}, false, errors.Join(ErrRegistryUnavailable, err)
		}
		if latest.Status != StatusActive {
			continue
		}
		return cert, true, nil
	}
	return Certification{}, false, nil
}

func validOrigin(origin string) bool {
	switch origin {
	case "", OriginAstraClaw, OriginXiaozhi:
		return true
	}
	// Any other declared origin must at least be canonical trace metadata.
	return canonical(origin)
}

func isAstraClawOrigin(origin string) bool {
	switch origin {
	case OriginAstraClaw, OriginXiaozhi:
		return true
	}
	return false
}

// stripConnectorCapabilities removes every enterprise connector capability from
// a ceiling, using policy.IsConnectorCapability as the single source of truth.
func stripConnectorCapabilities(ceiling runtime.CapabilityCeiling) runtime.CapabilityCeiling {
	out := make(runtime.CapabilityCeiling, 0, len(ceiling))
	for _, capability := range ceiling {
		if policy.IsConnectorCapability(policy.Capability(capability)) {
			continue
		}
		out = append(out, capability)
	}
	return out
}
