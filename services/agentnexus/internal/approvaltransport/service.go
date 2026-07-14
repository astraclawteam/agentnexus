package approvaltransport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// evidenceDecisionSkew bounds how far in the future a decided_at timestamp
// may claim to be (clock skew allowance, mirrors the ingress verifier skew).
const evidenceDecisionSkew = 30 * time.Second

// maxRevocationReasonBytes bounds persisted revocation reasons.
const maxRevocationReasonBytes = 1024

// Audit action vocabulary of the transmission lineage. Evidence carries TWO
// distinct acts so the trail separates a submission attempt from an accepted
// record: approval.evidence.submitted is appended BEFORE the store write
// (every submission act is audited, including ones the store then rejects as
// replays), approval.evidence.recorded is appended AFTER the atomic store
// write succeeds (the acceptance marker Task 0G chains against the persisted
// row).
const (
	auditActionTransmit          = "approval.plan.transmit"
	auditActionEvidenceSubmitted = "approval.evidence.submitted"
	auditActionEvidenceRecorded  = "approval.evidence.recorded"
	auditActionRevoke            = "approval.transmission.revoke"
)

// Service is the approval transmission service. It transmits the caller's
// signed plan unchanged, validates returned evidence and exposes status; it
// never classifies risk, walks hierarchy or chooses people.
type Service struct {
	store        Store
	channel      Channel
	audit        AuditSink
	providers    DecisionProviderVerifier
	attestations AttestationVerifier
	logger       *slog.Logger
	now          func() time.Time
	newID        func(prefix string) string
}

// Option configures a Service.
type Option func(*Service)

// WithClock overrides the service clock.
func WithClock(clock func() time.Time) Option {
	return func(s *Service) { s.now = clock }
}

// WithDecisionProviderVerifier wires the certified-decision-provider
// verification consulted for certified third-party callers (Task 0F wiring).
// Without it a certified third party cannot transmit: the nil seam fails
// closed and is never a pass-stub.
func WithDecisionProviderVerifier(verifier DecisionProviderVerifier) Option {
	return func(s *Service) { s.providers = verifier }
}

// WithAttestationVerifier wires cryptographic evidence-attestation
// verification against registered authority keys (Task 0F/0G wiring). nil
// means local checks only; a wired verifier only ever ADDS verification.
func WithAttestationVerifier(verifier AttestationVerifier) Option {
	return func(s *Service) { s.attestations = verifier }
}

// WithLogger overrides the service logger (0D evidence-service seam style).
// Log lines carry tenant/plan refs, attempt counters, coded reasons and the
// underlying transport error text - never plan content, purposes or
// attestation values.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// NewService builds the transmission service. Store, channel and audit sink
// are all mandatory: a deployment without a configured approval channel or
// audit lineage cannot transmit at all (fail closed at construction — there
// is never a resolution fallback).
func NewService(store Store, channel Channel, audit AuditSink, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, errors.New("approval transmission requires a store")
	}
	if channel == nil {
		return nil, errors.New("approval transmission requires a configured channel; AgentNexus never resolves approvals itself")
	}
	if audit == nil {
		return nil, errors.New("approval transmission requires an audit sink")
	}
	service := &Service{
		store:   store,
		channel: channel,
		audit:   audit,
		logger:  slog.Default(),
		now:     func() time.Time { return time.Now().UTC() },
		newID:   randomOpaqueID,
	}
	for _, opt := range opts {
		opt(service)
	}
	return service, nil
}

// Transmit accepts one signed approval plan from the verified caller,
// persists the correlation and forwards the plan UNCHANGED to the configured
// channel. Duplicate transmits of the same plan are idempotent; a still-
// pending plan is re-delivered (provider retry). A transport failure keeps
// the transmission pending and can never create approval progress.
func (s *Service) Transmit(ctx context.Context, principal runtime.PrincipalContext, req runtime.ApprovalRequest) (Transmission, error) {
	if err := s.guard(ctx); err != nil {
		return Transmission{}, err
	}
	if err := principal.Validate(); err != nil {
		return Transmission{}, errors.Join(ErrInvalidInput, err)
	}
	if err := s.verifyDecisionProvider(ctx, principal, req.Plan); err != nil {
		return Transmission{}, err
	}
	if err := req.Validate(); err != nil {
		return Transmission{}, errors.Join(ErrInvalidInput, err)
	}
	// The SDK requires only a non-empty authority; the durable store's CHECK
	// additionally demands a canonical value. Reject the padded form here as
	// a 400-class input instead of surfacing a 503 from the store.
	if !canonical(req.Plan.Authority) {
		return Transmission{}, errors.Join(ErrInvalidInput, errors.New("approval plan authority must be canonical (no surrounding whitespace)"))
	}
	now := s.now().UTC()
	if !req.ExpiresAt.After(now) {
		return Transmission{}, errors.Join(ErrInvalidInput, errors.New("approval plan expiry must be in the future"))
	}
	candidate := Transmission{
		TenantRef:          principal.TenantRef,
		PlanRef:            req.Plan.PlanRef,
		PlanHash:           req.Plan.PlanHash,
		Authority:          req.Plan.Authority,
		BusinessContextRef: req.BusinessContextRef,
		Capability:         req.Capability,
		ParameterHash:      req.ParameterHash,
		Purpose:            req.Purpose,
		Status:             StatusPending,
		ExpiresAt:          req.ExpiresAt.UTC(),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	existing, err := s.store.GetTransmission(ctx, candidate.TenantRef, candidate.PlanRef)
	switch {
	case err == nil:
		return s.continueExisting(ctx, existing, candidate)
	case !errors.Is(err, ErrNotFound):
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	// The transmit act is audited BEFORE the correlation persists: no
	// unaudited transmission exists, and a failed persist leaves only a
	// lineage entry for the attempted act.
	auditRef, err := s.audit.AppendApprovalAudit(ctx, AuditEvent{
		TenantRef:    candidate.TenantRef,
		PrincipalRef: principal.PrincipalRef,
		Action:       auditActionTransmit,
		PlanRef:      candidate.PlanRef,
		Decision:     "accepted",
		Details:      map[string]any{"capability": candidate.Capability, "parameter_hash": candidate.ParameterHash, "authority": candidate.Authority},
	})
	if err != nil || auditRef == "" {
		return Transmission{}, errors.Join(ErrUnavailable, errors.New("approval transmit audit append failed"), err)
	}
	candidate.AuditRefID = auditRef
	stored, created, err := s.store.CreateTransmission(ctx, candidate)
	if err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if !created {
		return s.continueExisting(ctx, stored, candidate)
	}
	return s.deliver(ctx, stored)
}

// continueExisting resolves an idempotent re-transmit: identical binding is
// required; a still-pending plan is re-delivered, every later state is
// returned as-is (delivered/evidence_recorded/revoked are never re-sent).
func (s *Service) continueExisting(ctx context.Context, existing, candidate Transmission) (Transmission, error) {
	if !existing.sameBinding(candidate) {
		return Transmission{}, ErrPlanConflict
	}
	if existing.Status != StatusPending {
		return existing, nil
	}
	return s.deliver(ctx, existing)
}

// deliver attempts one channel delivery and records the attempt. A channel
// error is a transport failure: the attempt is recorded as failed with a
// coded reason (never channel error text) and the transmission stays
// pending.
func (s *Service) deliver(ctx context.Context, transmission Transmission) (Transmission, error) {
	delivery := Delivery{
		TenantRef:          transmission.TenantRef,
		PlanRef:            transmission.PlanRef,
		PlanHash:           transmission.PlanHash,
		Authority:          transmission.Authority,
		BusinessContextRef: transmission.BusinessContextRef,
		Capability:         transmission.Capability,
		ParameterHash:      transmission.ParameterHash,
		Purpose:            transmission.Purpose,
		ExpiresAt:          transmission.ExpiresAt,
		Attempt:            transmission.DeliveryAttempts + 1,
	}
	outcome, reason := DeliveryDelivered, ""
	if err := s.channel.Deliver(ctx, delivery); err != nil {
		outcome, reason = DeliveryFailed, "channel_unavailable"
		// The persisted attempt row and the caller-visible reason stay coded;
		// the underlying transport cause is preserved here for diagnostics.
		s.logger.WarnContext(ctx, "approval.delivery_failed",
			slog.String("tenant_ref", delivery.TenantRef),
			slog.String("plan_ref", delivery.PlanRef),
			slog.Int("attempt", delivery.Attempt),
			slog.String("reason", reason),
			slog.String("error", err.Error()),
		)
	}
	updated, err := s.store.RecordDeliveryAttempt(ctx, transmission.TenantRef, transmission.PlanRef, outcome, reason, s.now().UTC())
	if err != nil {
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	return updated, nil
}

// RecordEvidence validates and stores the approval authority's decision for
// one transmitted plan: canonical shape, exact Action/parameter binding,
// plan digest, authority provenance, expiry, revocation and replay. It only
// STORES the validated evidence — grant issuance is Task 0F.
func (s *Service) RecordEvidence(ctx context.Context, principal runtime.PrincipalContext, evidence runtime.ApprovalEvidence) (EvidenceRecord, error) {
	if err := s.guard(ctx); err != nil {
		return EvidenceRecord{}, err
	}
	if err := principal.Validate(); err != nil {
		return EvidenceRecord{}, errors.Join(ErrInvalidInput, err)
	}
	if err := evidence.Validate(); err != nil {
		return EvidenceRecord{}, errors.Join(ErrEvidenceRejected, err)
	}
	evidence.DecidedAt = evidence.DecidedAt.UTC()
	transmission, err := s.store.GetTransmission(ctx, principal.TenantRef, evidence.PlanRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return EvidenceRecord{}, ErrNotFound
		}
		return EvidenceRecord{}, errors.Join(ErrUnavailable, err)
	}
	if transmission.Status == StatusRevoked {
		return EvidenceRecord{}, ErrTransmissionRevoked
	}
	// Exact operation binding: the decision must name the transmitted plan
	// digest and the exact capability + parameter hash it approved.
	if evidence.PlanHash != transmission.PlanHash || evidence.Capability != transmission.Capability || evidence.ParameterHash != transmission.ParameterHash {
		return EvidenceRecord{}, errors.Join(ErrEvidenceRejected, errors.New("evidence does not bind the transmitted operation"))
	}
	// Provenance: the decision must come from the authority that authored
	// the transmitted plan.
	if evidence.ApproverAuthority != transmission.Authority {
		return EvidenceRecord{}, errors.Join(ErrEvidenceRejected, errors.New("evidence authority does not match the transmitted plan authority"))
	}
	now := s.now().UTC()
	if now.After(transmission.ExpiresAt) {
		return EvidenceRecord{}, ErrEvidenceExpired
	}
	if evidence.DecidedAt.After(now.Add(evidenceDecisionSkew)) {
		return EvidenceRecord{}, errors.Join(ErrEvidenceRejected, errors.New("evidence decided_at is in the future"))
	}
	if evidence.DecidedAt.After(transmission.ExpiresAt) {
		return EvidenceRecord{}, ErrEvidenceExpired
	}
	// Attestation: the SDK structural validation above is the local floor; a
	// wired verifier additionally checks the signature against registered
	// authority keys (Task 0F/0G seam — nil never weakens the local checks).
	if s.attestations != nil {
		if err := s.attestations.VerifyEvidenceAttestation(ctx, principal.TenantRef, evidence); err != nil {
			return EvidenceRecord{}, errors.Join(ErrEvidenceRejected, err)
		}
	}
	evidenceHash := CanonicalEvidenceHash(evidence)
	if evidenceHash == "" {
		return EvidenceRecord{}, ErrUnavailable
	}
	// The SUBMISSION act is audited before the store write (audit-before-
	// persist doctrine): every submission leaves lineage, including ones the
	// store then rejects as replays. Its ref is bound onto the record row.
	auditRef, err := s.audit.AppendApprovalAudit(ctx, AuditEvent{
		TenantRef:    principal.TenantRef,
		PrincipalRef: principal.PrincipalRef,
		Action:       auditActionEvidenceSubmitted,
		PlanRef:      evidence.PlanRef,
		Decision:     string(evidence.Decision),
		Details:      map[string]any{"approval_ref": evidence.ApprovalRef, "approver_authority": evidence.ApproverAuthority},
	})
	if err != nil || auditRef == "" {
		return EvidenceRecord{}, errors.Join(ErrUnavailable, errors.New("approval evidence audit append failed"), err)
	}
	record := EvidenceRecord{
		TenantRef:    principal.TenantRef,
		Evidence:     evidence,
		EvidenceHash: evidenceHash,
		AuditRefID:   auditRef,
		RecordedAt:   now,
	}
	stored, created, err := s.store.RecordEvidence(ctx, record)
	if err != nil {
		switch {
		case errors.Is(err, ErrEvidenceReplay), errors.Is(err, ErrTransmissionRevoked), errors.Is(err, ErrNotFound):
			return EvidenceRecord{}, err
		}
		return EvidenceRecord{}, errors.Join(ErrUnavailable, err)
	}
	if created {
		// The ACCEPTANCE marker is appended only after the atomic store write
		// succeeded, so the trail distinguishes accepted evidence from
		// rejected submissions. Fail closed if it cannot be appended: the row
		// is durably stored with its submission lineage and an identical
		// resubmission lands on the idempotent duplicate path (the
		// submitted-without-recorded gap is Task 0G reconciliation material).
		if _, err := s.audit.AppendApprovalAudit(ctx, AuditEvent{
			TenantRef:    principal.TenantRef,
			PrincipalRef: principal.PrincipalRef,
			Action:       auditActionEvidenceRecorded,
			PlanRef:      evidence.PlanRef,
			Decision:     string(evidence.Decision),
			Details:      map[string]any{"approval_ref": evidence.ApprovalRef},
		}); err != nil {
			return EvidenceRecord{}, errors.Join(ErrUnavailable, errors.New("approval evidence acceptance audit append failed"), err)
		}
	}
	return stored, nil
}

// GetStatus returns the transmission diagnostics view for the caller's
// tenant.
func (s *Service) GetStatus(ctx context.Context, principal runtime.PrincipalContext, planRef string) (Transmission, error) {
	if err := s.guard(ctx); err != nil {
		return Transmission{}, err
	}
	if err := principal.Validate(); err != nil {
		return Transmission{}, errors.Join(ErrInvalidInput, err)
	}
	if err := runtime.ValidateHandle(planRef, runtime.HandleApprovalPlan); err != nil {
		return Transmission{}, errors.Join(ErrInvalidInput, err)
	}
	transmission, err := s.store.GetTransmission(ctx, principal.TenantRef, planRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Transmission{}, ErrNotFound
		}
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	return transmission, nil
}

// Revoke marks a transmission revoked (terminal, idempotent): recorded
// evidence becomes unusable for Task 0F and later evidence is rejected.
func (s *Service) Revoke(ctx context.Context, principal runtime.PrincipalContext, planRef, reason string) (Transmission, error) {
	if err := s.guard(ctx); err != nil {
		return Transmission{}, err
	}
	if err := principal.Validate(); err != nil {
		return Transmission{}, errors.Join(ErrInvalidInput, err)
	}
	if err := runtime.ValidateHandle(planRef, runtime.HandleApprovalPlan); err != nil {
		return Transmission{}, errors.Join(ErrInvalidInput, err)
	}
	if !canonical(reason) || len(reason) > maxRevocationReasonBytes || hasControlBytes(reason) {
		return Transmission{}, errors.Join(ErrInvalidInput, errors.New("revocation reason must be canonical, control-free and at most 1024 bytes"))
	}
	existing, err := s.store.GetTransmission(ctx, principal.TenantRef, planRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Transmission{}, ErrNotFound
		}
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	if existing.Status == StatusRevoked {
		return existing, nil
	}
	auditRef, err := s.audit.AppendApprovalAudit(ctx, AuditEvent{
		TenantRef:    principal.TenantRef,
		PrincipalRef: principal.PrincipalRef,
		Action:       auditActionRevoke,
		PlanRef:      planRef,
		Decision:     "revoked",
		Details:      map[string]any{"reason": reason},
	})
	if err != nil || auditRef == "" {
		return Transmission{}, errors.Join(ErrUnavailable, errors.New("approval revocation audit append failed"), err)
	}
	revocationID := s.newID("aprvk_")
	if revocationID == "" {
		return Transmission{}, ErrUnavailable
	}
	revoked, err := s.store.Revoke(ctx, principal.TenantRef, planRef, reason, revocationID, s.now().UTC())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Transmission{}, ErrNotFound
		}
		return Transmission{}, errors.Join(ErrUnavailable, err)
	}
	return revoked, nil
}

func (s *Service) guard(ctx context.Context) error {
	if s == nil || s.store == nil || s.channel == nil || s.audit == nil || s.now == nil || s.newID == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

// verifyDecisionProvider enforces the caller trust gate: first-party callers
// may transmit; certified third parties require the wired certified-
// decision-provider verification; untrusted callers never reach the
// approval plane.
func (s *Service) verifyDecisionProvider(ctx context.Context, principal runtime.PrincipalContext, plan runtime.ApprovalPlanRef) error {
	switch principal.TrustClass {
	case runtime.TrustFirstParty:
		return nil
	case runtime.TrustCertifiedThirdParty:
		if s.providers == nil {
			return errors.Join(ErrCallerUntrusted, errors.New("certified third-party transmission requires the wired decision-provider verification (Task 0F seam); nil wiring fails closed"))
		}
		if err := s.providers.VerifyDecisionProvider(ctx, principal.TenantRef, principal, plan); err != nil {
			return errors.Join(ErrCallerUntrusted, err)
		}
		return nil
	default:
		return ErrCallerUntrusted
	}
}

func randomOpaqueID(prefix string) string {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}
