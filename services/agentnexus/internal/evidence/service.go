package evidence

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// Audit actions of the evidence lineage (mirrors internal/audit vocabulary).
const (
	auditActionLocated = "evidence_located"
	auditActionRead    = "evidence_read"
)

// Coded deny reasons. They appear in logs and audit details (support
// metadata); they never carry content or source topology.
const (
	denyNotResolvable       = "not_resolvable"
	denyConnectorCapability = "connector_capability_required"
	denyPolicy              = "policy_denied"
	denyHandleUnknown       = "handle_unknown"
	denyCrossActor          = "cross_actor"
	denyCrossClient         = "cross_client"
	denyCrossRelease        = "cross_release"
	denyCrossContext        = "cross_context"
	denyPurposeDrift        = "purpose_drift"
	denyHandleExpired       = "handle_expired"
	denyRevoked             = "revoked"
	denyContentExpired      = "content_expired"
	denySourceDeleted       = "source_deleted"
	denySourceVersionStale  = "source_version_stale"
	denyBindingRebound      = "binding_rebound"
	denyCachedRead          = "cached_read_not_permitted"
	// Verification-read denials (GA Task 0D amendment). Coded reasons only:
	// the caller learns "deny", the lineage learns why.
	denyNeedMismatch           = "verification_need_mismatch"
	denyObservationUnsupported = "observation_authority_undeclared"
	denyObservationStale       = "observation_freshness_expired"
	denyActionUnbound          = "action_binding_mismatch"
)

const (
	defaultMaxContentBytes = 1 << 20 // bounded staging: 1 MiB of normalized plaintext
	defaultMaxHandleTTL    = 24 * time.Hour
	maxPurposeBytes        = 1024
	maxNeedIDBytes         = 128
	// maxDataNeedsPerRequest bounds how many data needs one locate may carry;
	// each need fetches, stages and audits independently, so the count is a
	// resource bound, not a business rule.
	maxDataNeedsPerRequest = 32
	// retentionSweepBatch bounds one retention-sweep query; SweepRetention
	// loops until the tenant is drained.
	retentionSweepBatch = 100
)

// Service is the semantic evidence service.
type Service struct {
	store           Store
	objects         ObjectStore
	keys            KeyProvider
	source          ContentSource
	decider         CapabilityDecider
	audit           AuditSink
	logger          *slog.Logger
	now             func() time.Time
	newID           func(prefix string) string
	maxContentBytes int
	maxHandleTTL    time.Duration
	// signer signs observation receipts (GA Task 0D amendment). Nil-guarded
	// like the other production ports: unwired, verification-purpose reads
	// fail CLOSED while ordinary reads are unaffected.
	signer ObservationSigner
	// actionBinding is the OPTIONAL GA Task 0F seam (authoritative
	// Action-binding verification); nil until Task 0F wires it, without
	// weakening the local checks.
	actionBinding ActionBindingVerifier
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

// WithLogger overrides the service logger. Log lines carry only refs, hashes,
// versions and coded reasons.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithMaxContentBytes bounds the normalized plaintext staged per data need.
func WithMaxContentBytes(limit int) Option {
	return func(s *Service) {
		if limit > 0 {
			s.maxContentBytes = limit
		}
	}
}

// WithMaxHandleTTL caps the handle lifetime a request may ask for.
func WithMaxHandleTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.maxHandleTTL = ttl
		}
	}
}

// WithObservationSigner wires the observation signing port (GA Task 0D
// amendment). Without it, verification-purpose reads fail closed.
func WithObservationSigner(signer ObservationSigner) Option {
	return func(s *Service) { s.signer = signer }
}

// WithActionBindingVerifier wires the GA Task 0F authoritative Action-binding
// check into verification-purpose reads. Absent wiring, the service performs
// the local self-consistency checks only (never a silent stand-in pass).
func WithActionBindingVerifier(verifier ActionBindingVerifier) Option {
	return func(s *Service) { s.actionBinding = verifier }
}

// NewService builds the evidence service over its ports.
func NewService(store Store, objects ObjectStore, keys KeyProvider, source ContentSource, decider CapabilityDecider, audit AuditSink, opts ...Option) *Service {
	svc := &Service{
		store:           store,
		objects:         objects,
		keys:            keys,
		source:          source,
		decider:         decider,
		audit:           audit,
		logger:          slog.Default(),
		now:             func() time.Time { return time.Now().UTC() },
		newID:           randomOpaqueID,
		maxContentBytes: defaultMaxContentBytes,
		maxHandleTTL:    defaultMaxHandleTTL,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func (s *Service) ready() error {
	if s == nil || s.store == nil || s.objects == nil || s.keys == nil || s.source == nil || s.decider == nil || s.audit == nil {
		return ErrUnavailable
	}
	return nil
}

// LocateResult is the public locate outcome: the work-case handle plus the
// opaque evidence handles.
type LocateResult struct {
	BusinessContextRef string                   `json:"business_context_ref"`
	Evidence           []runtime.EvidenceHandle `json:"evidence"`
}

// ReadResult is the read outcome. A cached response ALWAYS states the source
// version, the as-of time and the explicit served-from-cache marker; a deny
// carries the decision only. ObservationReceipt is present ONLY on an
// allowed verification-purpose read (GA Task 0D amendment) - ordinary reads
// keep their exact prior shape.
type ReadResult struct {
	Decision           string                      `json:"decision"`
	Data               map[string]any              `json:"data,omitempty"`
	SourceVersion      int64                       `json:"source_version,omitempty"`
	AsOf               time.Time                   `json:"as_of,omitzero"`
	ServedFromCache    bool                        `json:"served_from_cache,omitempty"`
	ContinuationRef    string                      `json:"continuation_ref,omitempty"`
	ObservationReceipt *runtime.ObservationReceipt `json:"observation_receipt,omitempty"`
}

// RegisterSourceBinding installs (or updates) one private semantic registry
// row. It is an administrative operation: nothing here is caller-reachable.
func (s *Service) RegisterSourceBinding(ctx context.Context, binding SourceBinding) (SourceBinding, error) {
	if err := s.ready(); err != nil {
		return SourceBinding{}, err
	}
	if !canonical(binding.TenantRef) || !canonical(binding.DataClass) || !canonical(binding.SourceRef) ||
		!canonical(binding.AccessCapability) || !canonical(binding.ResourceType) || !canonical(binding.ResourceID) ||
		hasControlBytes(binding.SourceRef) || binding.RetentionTTL < 0 || binding.SourceVersion < 0 {
		return SourceBinding{}, ErrInvalidRequest
	}
	// The observation-authority declaration is all-or-nothing: a frozen tier
	// WITH a positive freshness bound, or neither. A tier without a bound
	// (unbounded observations) and a bound without a tier (freshness under no
	// declared authority) are both undeclarable, as is any non-frozen tier
	// literal.
	if binding.AuthorityTier != "" || binding.FreshnessBound != 0 {
		if !validAuthorityTier(binding.AuthorityTier) || binding.FreshnessBound <= 0 {
			return SourceBinding{}, errors.Join(ErrInvalidRequest, errors.New("observation authority declares a frozen tier together with a positive freshness bound"))
		}
	}
	now := s.now()
	if binding.ID == "" {
		binding.ID = s.newID("esb_")
	}
	if !canonical(binding.ID) {
		return SourceBinding{}, ErrUnavailable
	}
	if binding.SourceVersion == 0 {
		binding.SourceVersion = 1
	}
	binding.Deleted = false
	binding.CreatedAt = now
	binding.UpdatedAt = now
	stored, err := s.store.UpsertSourceBinding(ctx, binding)
	if err != nil {
		return SourceBinding{}, errors.Join(ErrUnavailable, err)
	}
	return stored, nil
}

// InvalidateSourceVersion advances a source's version: every handle bound to
// the prior version fails CLOSED at read time (no stale fallback).
func (s *Service) InvalidateSourceVersion(ctx context.Context, tenantRef, dataClass string) (SourceBinding, error) {
	if err := s.ready(); err != nil {
		return SourceBinding{}, err
	}
	if !canonical(tenantRef) || !canonical(dataClass) {
		return SourceBinding{}, ErrInvalidRequest
	}
	binding, err := s.store.BumpSourceVersion(ctx, tenantRef, dataClass, s.now())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return SourceBinding{}, ErrNotFound
		}
		return SourceBinding{}, errors.Join(ErrUnavailable, err)
	}
	s.logger.InfoContext(ctx, "evidence.source_invalidated",
		slog.String("tenant_ref", tenantRef),
		slog.String("data_class", dataClass),
		slog.Int64("source_version", binding.SourceVersion),
	)
	return binding, nil
}

// DeleteSource tombstones a source: reads of its handles and new locates fail
// closed.
func (s *Service) DeleteSource(ctx context.Context, tenantRef, dataClass string) error {
	if err := s.ready(); err != nil {
		return err
	}
	if !canonical(tenantRef) || !canonical(dataClass) {
		return ErrInvalidRequest
	}
	if _, err := s.store.MarkSourceDeleted(ctx, tenantRef, dataClass, s.now()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return errors.Join(ErrUnavailable, err)
	}
	s.logger.InfoContext(ctx, "evidence.source_deleted",
		slog.String("tenant_ref", tenantRef),
		slog.String("data_class", dataClass),
	)
	return nil
}

// RevokeAuthorization appends an ACL revocation to an issued handle; every
// later read fails closed. Revocation is append-only and persists.
func (s *Service) RevokeAuthorization(ctx context.Context, tenantRef, evidenceRef, reason string) error {
	if err := s.ready(); err != nil {
		return err
	}
	if !canonical(tenantRef) || !canonical(evidenceRef) || hasControlBytes(reason) {
		return ErrInvalidRequest
	}
	if _, err := s.store.GetHandle(ctx, tenantRef, evidenceRef); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return errors.Join(ErrUnavailable, err)
	}
	event := HandleEvent{
		TenantRef:   tenantRef,
		ID:          s.newID("evt_"),
		EvidenceRef: evidenceRef,
		Kind:        HandleEventRevoked,
		Reason:      reason,
	}
	if !canonical(event.ID) {
		return ErrUnavailable
	}
	if _, err := s.store.AppendHandleEvent(ctx, event); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return errors.Join(ErrUnavailable, err)
	}
	s.logger.InfoContext(ctx, "evidence.authorization_revoked",
		slog.String("tenant_ref", tenantRef),
		slog.String("evidence_ref", evidenceRef),
	)
	return nil
}

// SweepRetention removes staged content whose raw-content retention TTL
// passed. The handle metadata (row, content hash, lineage) stays auditable;
// removal is recorded as an append-only content_expired event.
// The sweeper is purely JANITORIAL: reads already deny past the retention
// deadline (Read checks retention_expires_at directly), so a delayed or
// missing sweep can never extend data availability. Deleting a shared blob is
// safe by construction: handles sharing an object key (continuation pages)
// copy StagedAt/ExpiresAt/RetentionExpiresAt verbatim from their parent, so
// every sharer crosses the retention deadline at the same instant and no live
// handle can still be entitled to a swept blob.
func (s *Service) SweepRetention(ctx context.Context, tenantRef string) (int, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	if !canonical(tenantRef) {
		return 0, ErrInvalidRequest
	}
	removed := 0
	for {
		expired, err := s.store.ListRetentionExpired(ctx, tenantRef, s.now(), retentionSweepBatch)
		if err != nil {
			return removed, errors.Join(ErrUnavailable, err)
		}
		for _, handle := range expired {
			if err := s.objects.Delete(ctx, handle.ObjectKey); err != nil && !errors.Is(err, ErrObjectNotFound) {
				return removed, errors.Join(ErrUnavailable, err)
			}
			event := HandleEvent{
				TenantRef:   tenantRef,
				ID:          s.newID("evt_"),
				EvidenceRef: handle.EvidenceRef,
				Kind:        HandleEventContentExpired,
				Reason:      "raw-content retention expired",
			}
			if !canonical(event.ID) {
				return removed, ErrUnavailable
			}
			if _, err := s.store.AppendHandleEvent(ctx, event); err != nil {
				return removed, errors.Join(ErrUnavailable, err)
			}
			removed++
			s.logger.InfoContext(ctx, "evidence.content_retention_expired",
				slog.String("tenant_ref", tenantRef),
				slog.String("evidence_ref", handle.EvidenceRef),
				slog.String("content_hash", handle.ContentHash),
			)
		}
		if len(expired) < retentionSweepBatch {
			return removed, nil
		}
	}
}

// stagedNeed is one authorized, fetched and bounded data need awaiting
// persistence (locate phase B).
type stagedNeed struct {
	need      runtime.DataNeed
	binding   SourceBinding
	plaintext []byte
	hash      string
	count     int64
	pageLimit int64
}

// Locate resolves business-semantic data needs to opaque evidence handles.
// Resolution is PRIVATE: nothing connector-shaped crosses into results,
// errors, audit details or logs. A single denied need fails the whole locate
// closed (no silent partial results).
func (s *Service) Locate(ctx context.Context, principal runtime.PrincipalContext, authz Authorization, req runtime.EvidenceRequest) (LocateResult, error) {
	if err := s.ready(); err != nil {
		return LocateResult{}, err
	}
	if err := principal.Validate(); err != nil {
		return LocateResult{}, errors.Join(ErrInvalidRequest, err)
	}
	if err := req.Validate(); err != nil {
		return LocateResult{}, errors.Join(ErrInvalidRequest, err)
	}
	now := s.now()
	if !req.ExpiresAt.After(now) {
		return LocateResult{}, errors.Join(ErrInvalidRequest, errors.New("request is expired"))
	}
	if len(req.DataNeeds) > maxDataNeedsPerRequest {
		return LocateResult{}, errors.Join(ErrInvalidRequest, errors.New("too many data needs in one request"))
	}
	expiresAt := req.ExpiresAt
	if ceiling := now.Add(s.maxHandleTTL); expiresAt.After(ceiling) {
		expiresAt = ceiling
	}
	businessContextRef := req.BusinessContextRef
	if businessContextRef == "" {
		businessContextRef = s.newID(runtime.HandleWorkCase)
	}
	if err := runtime.ValidateHandle(businessContextRef, runtime.HandleWorkCase); err != nil {
		return LocateResult{}, errors.Join(ErrUnavailable, err)
	}

	// Phase A: authorize, fetch and bound every need BEFORE anything persists,
	// so a denial never leaves partial state behind.
	staged := make([]stagedNeed, 0, len(req.DataNeeds))
	for _, need := range req.DataNeeds {
		one, err := s.resolveNeed(ctx, principal, authz, req, need, now)
		if err != nil {
			return LocateResult{}, err
		}
		staged = append(staged, one)
	}

	key, err := s.keys.ContentKey(ctx, principal.TenantRef)
	if err != nil {
		return LocateResult{}, errors.Join(ErrUnavailable, err)
	}

	// Phase B: stage ciphertext, append authorization lineage and persist the
	// handle bindings. Any failure rolls the already-persisted parts back
	// (objects deleted, handles revoked) and the locate fails closed. The
	// compensation runs on a cancellation-immune context: a caller-cancelled
	// request must still clean up what it already persisted.
	var stagedKeys []string
	var createdRefs []string
	cleanup := func() {
		cleanupCtx := context.WithoutCancel(ctx)
		for _, objectKey := range stagedKeys {
			_ = s.objects.Delete(cleanupCtx, objectKey)
		}
		for _, ref := range createdRefs {
			_, _ = s.store.AppendHandleEvent(cleanupCtx, HandleEvent{
				TenantRef: principal.TenantRef, ID: s.newID("evt_"),
				EvidenceRef: ref, Kind: HandleEventRevoked, Reason: "locate aborted",
			})
		}
	}
	result := LocateResult{BusinessContextRef: businessContextRef, Evidence: make([]runtime.EvidenceHandle, 0, len(staged))}
	for _, one := range staged {
		objectKey := s.newID("obj_")
		evidenceRef := s.newID(runtime.HandleEvidence)
		if !canonical(objectKey) || !canonical(evidenceRef) {
			cleanup()
			return LocateResult{}, ErrUnavailable
		}
		// The ciphertext is bound to tenant and object key through GCM
		// additional data: a blob swapped across tenants or object keys fails
		// authenticated decryption. The OBJECT key (not the evidence ref) is
		// the binding because continuation handles legitimately share it.
		ciphertext, err := seal(key.Key, one.plaintext, contentAAD(principal.TenantRef, objectKey))
		if err != nil {
			cleanup()
			return LocateResult{}, errors.Join(ErrUnavailable, err)
		}
		if err := s.objects.Put(ctx, objectKey, ciphertext); err != nil {
			cleanup()
			return LocateResult{}, errors.Join(ErrUnavailable, err)
		}
		stagedKeys = append(stagedKeys, objectKey)

		// Authorization lineage is REQUIRED: without a recorded lineage head
		// no handle is issued.
		auditRef, err := s.audit.AppendEvidenceAudit(ctx, AuditEvent{
			TenantRef:    principal.TenantRef,
			PrincipalRef: principal.PrincipalRef,
			Action:       auditActionLocated,
			ResourceType: "evidence_handle",
			ResourceID:   evidenceRef,
			TraceID:      req.TraceID,
			Details: map[string]any{
				"decision":             DecisionAllow,
				"data_class":           one.binding.DataClass,
				"need_id":              one.need.NeedID,
				"purpose":              one.need.Purpose,
				"source_version":       one.binding.SourceVersion,
				"content_hash":         one.hash,
				"org_version":          authz.OrgVersion,
				"business_context_ref": businessContextRef,
				"agent_release_ref":    principal.AgentReleaseRef,
			},
		})
		if err != nil || auditRef == "" {
			cleanup()
			return LocateResult{}, errors.Join(ErrUnavailable, errors.New("authorization lineage append failed"))
		}

		handle := Handle{
			TenantRef:          principal.TenantRef,
			EvidenceRef:        evidenceRef,
			PrincipalRef:       principal.PrincipalRef,
			AgentClientRef:     principal.AgentClientRef,
			AgentReleaseRef:    principal.AgentReleaseRef,
			OrgVersion:         authz.OrgVersion,
			DataClass:          one.binding.DataClass,
			BindingID:          one.binding.ID,
			SourceVersion:      one.binding.SourceVersion,
			Purpose:            one.need.Purpose,
			BusinessContextRef: businessContextRef,
			ContentHash:        one.hash,
			ContentBytes:       int64(len(one.plaintext)),
			RecordCount:        one.count,
			RecordOffset:       0,
			PageLimit:          one.pageLimit,
			ObjectKey:          objectKey,
			KeyRef:             key.Ref,
			AuthorizationRef:   auditRef,
			Lineage:            []string{auditRef},
			CachedReadAllowed:  one.binding.CachedReadAllowed,
			StagedAt:           now,
			ExpiresAt:          expiresAt,
		}
		// Raw content never outlives the handle: retention defaults to the
		// handle expiry and a configured binding TTL may only SHORTEN it, so
		// every staged blob has a deterministic deletion deadline (the sweeper
		// then has no orphans to miss).
		handle.RetentionExpiresAt = expiresAt
		if ttl := one.binding.RetentionTTL; ttl > 0 {
			if deadline := now.Add(ttl); deadline.Before(handle.RetentionExpiresAt) {
				handle.RetentionExpiresAt = deadline
			}
		}
		if _, err := s.store.CreateHandle(ctx, handle); err != nil {
			cleanup()
			return LocateResult{}, errors.Join(ErrUnavailable, err)
		}
		createdRefs = append(createdRefs, evidenceRef)

		result.Evidence = append(result.Evidence, runtime.EvidenceHandle{
			EvidenceRef: evidenceRef,
			DataClass:   one.binding.DataClass,
			Summary:     fmt.Sprintf("%d record(s) as of source version %d", one.count, one.binding.SourceVersion),
			ExpiresAt:   expiresAt,
		})
		s.logger.InfoContext(ctx, "evidence.located",
			slog.String("tenant_ref", principal.TenantRef),
			slog.String("evidence_ref", evidenceRef),
			slog.String("data_class", one.binding.DataClass),
			slog.Int64("source_version", one.binding.SourceVersion),
			slog.String("content_hash", one.hash),
		)
	}
	return result, nil
}

// resolveNeed authorizes and privately resolves ONE data need. Denials are
// audited best-effort with coded reasons; error text never carries topology.
func (s *Service) resolveNeed(ctx context.Context, principal runtime.PrincipalContext, authz Authorization, req runtime.EvidenceRequest, need runtime.DataNeed, now time.Time) (stagedNeed, error) {
	if !canonical(need.NeedID) || hasControlBytes(need.NeedID) || len(need.NeedID) > maxNeedIDBytes {
		return stagedNeed{}, errors.Join(ErrInvalidRequest, errors.New("need_id is not canonical"))
	}
	if !canonical(need.Purpose) || hasControlBytes(need.Purpose) || len(need.Purpose) > maxPurposeBytes {
		return stagedNeed{}, errors.Join(ErrInvalidRequest, errors.New("purpose is not canonical"))
	}
	// One request carries ONE justification: every need must declare the same
	// purpose as the request envelope. Divergent per-need purposes would let a
	// single envelope smuggle justifications past review, so drift is invalid
	// (not merely denied). The agreed purpose binds to the handle, is recorded
	// in the authorization lineage and is re-checked verbatim at read time.
	if need.Purpose != req.Purpose {
		return stagedNeed{}, errors.Join(ErrInvalidRequest, errors.New("need purpose conflicts with the request purpose"))
	}
	for _, prohibited := range prohibitedUses(req, need) {
		if need.Purpose == prohibited {
			return stagedNeed{}, errors.Join(ErrInvalidRequest, errors.New("purpose is prohibited for this need"))
		}
	}

	binding, err := s.store.GetSourceBinding(ctx, principal.TenantRef, need.DataClass)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return stagedNeed{}, s.denyLocate(ctx, principal, req, need, denyNotResolvable)
		}
		return stagedNeed{}, errors.Join(ErrUnavailable, err)
	}
	if binding.Deleted {
		return stagedNeed{}, s.denyLocate(ctx, principal, req, need, denyNotResolvable)
	}
	// The AstraClaw boundary: a connector-backed data class requires the
	// credential-derived connector capability.
	if binding.connectorBacked() && !authz.ConnectorCapabilityAllowed {
		return stagedNeed{}, s.denyLocate(ctx, principal, req, need, denyConnectorCapability)
	}
	decision, err := s.decider.Evaluate(ctx, policy.CapabilityRequest{
		TenantRef:        principal.TenantRef,
		PrincipalRef:     principal.PrincipalRef,
		SealedOrgVersion: authz.OrgVersion,
		ResourceType:     policy.ResourceType(binding.ResourceType),
		ResourceID:       binding.ResourceID,
		Capability:       policy.Capability(binding.AccessCapability),
	})
	if err != nil {
		return stagedNeed{}, errors.Join(ErrUnavailable, err)
	}
	if decision.Decision != policy.DecisionAllow {
		return stagedNeed{}, s.denyLocate(ctx, principal, req, need, denyPolicy)
	}

	// The staging bound travels INTO the source so a well-behaved source stops
	// early instead of materializing an over-limit dataset in memory.
	records, err := s.source.FetchEvidence(ctx, ContentRequest{
		TenantRef: principal.TenantRef,
		SourceRef: binding.SourceRef,
		DataClass: binding.DataClass,
		Fields:    need.Fields,
		MaxBytes:  s.maxContentBytes,
	})
	if err != nil {
		if errors.Is(err, ErrContentTooLarge) {
			return stagedNeed{}, fmt.Errorf("%w: source stopped at the staging bound (%d bytes)", ErrContentTooLarge, s.maxContentBytes)
		}
		return stagedNeed{}, errors.Join(ErrUnavailable, errors.New("source fetch failed"))
	}
	records = projectRecords(records, stagingFields(need))
	plaintext, err := json.Marshal(records)
	if err != nil {
		return stagedNeed{}, errors.Join(ErrUnavailable, err)
	}
	// Post-hoc BACKSTOP against a misbehaving source that ignored MaxBytes:
	// oversized content is an explicit error, NEVER a silent truncation.
	if s.maxContentBytes > 0 && len(plaintext) > s.maxContentBytes {
		return stagedNeed{}, fmt.Errorf("%w: normalized content is %d bytes (bound %d)", ErrContentTooLarge, len(plaintext), s.maxContentBytes)
	}
	sum := sha256.Sum256(plaintext)
	return stagedNeed{
		need:      need,
		binding:   binding,
		plaintext: plaintext,
		hash:      hex.EncodeToString(sum[:]),
		count:     int64(len(records)),
		pageLimit: pageLimit(req, need),
	}, nil
}

// denyLocate records the coded denial (best-effort lineage, ref-only log) and
// returns the public fail-closed error.
func (s *Service) denyLocate(ctx context.Context, principal runtime.PrincipalContext, req runtime.EvidenceRequest, need runtime.DataNeed, reason string) error {
	_, _ = s.audit.AppendEvidenceAudit(ctx, AuditEvent{
		TenantRef:    principal.TenantRef,
		PrincipalRef: principal.PrincipalRef,
		Action:       auditActionLocated,
		ResourceType: "evidence_need",
		ResourceID:   need.DataClass,
		TraceID:      req.TraceID,
		Details:      map[string]any{"decision": DecisionDeny, "reason": reason},
	})
	s.logger.WarnContext(ctx, "evidence.locate_denied",
		slog.String("tenant_ref", principal.TenantRef),
		slog.String("data_class", need.DataClass),
		slog.String("reason", reason),
	)
	return errors.Join(ErrDenied, errors.New(reason))
}

// Read serves one located evidence handle under the full server-side binding.
// Every mismatch, expiry, revocation, deletion or staleness fails CLOSED as a
// typed deny; cached responses always state source version and as-of time.
func (s *Service) Read(ctx context.Context, principal runtime.PrincipalContext, authz Authorization, req runtime.EvidenceReadRequest) (ReadResult, error) {
	if err := s.ready(); err != nil {
		return ReadResult{}, err
	}
	if err := principal.Validate(); err != nil {
		return ReadResult{}, errors.Join(ErrInvalidRequest, err)
	}
	if err := req.Validate(); err != nil {
		return ReadResult{}, errors.Join(ErrInvalidRequest, err)
	}
	now := s.now()
	if !req.ExpiresAt.After(now) {
		return ReadResult{}, errors.Join(ErrInvalidRequest, errors.New("request is expired"))
	}
	if !canonical(req.Purpose) || hasControlBytes(req.Purpose) || len(req.Purpose) > maxPurposeBytes {
		return ReadResult{}, errors.Join(ErrInvalidRequest, errors.New("purpose is not canonical"))
	}

	// Verification-purpose coupling (GA Task 0D amendment), re-enforced here
	// even though the SDK validators already reject detached shapes (defense
	// in depth: the service is also called directly). The signer nil-guard
	// runs BEFORE any handle or content is touched: an unwired signing port
	// fails the verification read closed with zero data egress.
	declared := req.VerificationBinding
	if declared != nil {
		if req.Purpose != runtime.PurposeVerification {
			return ReadResult{}, errors.Join(ErrInvalidRequest, errors.New("a verification binding requires the verification purpose"))
		}
		if err := validateVerificationBinding(*declared); err != nil {
			return ReadResult{}, errors.Join(ErrInvalidRequest, err)
		}
		if s.signer == nil {
			return ReadResult{}, errors.Join(ErrUnavailable, errors.New("observation signer is not wired; verification-purpose reads fail closed"))
		}
	} else if req.Purpose == runtime.PurposeVerification {
		return ReadResult{}, errors.Join(ErrInvalidRequest, errors.New("the verification purpose requires a verification binding"))
	}

	handle, err := s.store.GetHandle(ctx, principal.TenantRef, req.EvidenceRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return s.denyRead(ctx, principal, req, Handle{}, denyHandleUnknown), nil
		}
		return ReadResult{}, errors.Join(ErrUnavailable, err)
	}

	// Full binding checks, strictest first; the caller learns only "deny".
	switch {
	case handle.PrincipalRef != principal.PrincipalRef:
		return s.denyRead(ctx, principal, req, handle, denyCrossActor), nil
	case handle.AgentClientRef != principal.AgentClientRef:
		return s.denyRead(ctx, principal, req, handle, denyCrossClient), nil
	case handle.AgentReleaseRef != principal.AgentReleaseRef:
		return s.denyRead(ctx, principal, req, handle, denyCrossRelease), nil
	case handle.BusinessContextRef != req.BusinessContextRef:
		return s.denyRead(ctx, principal, req, handle, denyCrossContext), nil
	case handle.Purpose != req.Purpose:
		return s.denyRead(ctx, principal, req, handle, denyPurposeDrift), nil
	case !now.Before(handle.ExpiresAt):
		return s.denyRead(ctx, principal, req, handle, denyHandleExpired), nil
	case !handle.RetentionExpiresAt.IsZero() && !now.Before(handle.RetentionExpiresAt):
		// The raw-content retention deadline is enforced HERE, at read time:
		// the sweep is purely janitorial and a delayed sweep never extends
		// data availability.
		return s.denyRead(ctx, principal, req, handle, denyContentExpired), nil
	}

	events, err := s.store.ListHandleEvents(ctx, principal.TenantRef, handle.EvidenceRef)
	if err != nil {
		return ReadResult{}, errors.Join(ErrUnavailable, err)
	}
	for _, event := range events {
		switch event.Kind {
		case HandleEventRevoked:
			return s.denyRead(ctx, principal, req, handle, denyRevoked), nil
		case HandleEventContentExpired:
			return s.denyRead(ctx, principal, req, handle, denyContentExpired), nil
		}
	}

	binding, err := s.store.GetSourceBinding(ctx, principal.TenantRef, handle.DataClass)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return s.denyRead(ctx, principal, req, handle, denySourceDeleted), nil
		}
		return ReadResult{}, errors.Join(ErrUnavailable, err)
	}
	switch {
	case binding.Deleted:
		return s.denyRead(ctx, principal, req, handle, denySourceDeleted), nil
	case binding.ID != handle.BindingID:
		return s.denyRead(ctx, principal, req, handle, denyBindingRebound), nil
	case binding.SourceVersion != handle.SourceVersion:
		// The source moved on: a cached handle NEVER serves stale content.
		return s.denyRead(ctx, principal, req, handle, denySourceVersionStale), nil
	case binding.connectorBacked() && !authz.ConnectorCapabilityAllowed:
		return s.denyRead(ctx, principal, req, handle, denyConnectorCapability), nil
	case !binding.CachedReadAllowed || !handle.CachedReadAllowed:
		// Serving staged (cached) content requires the EXPLICIT grant.
		return s.denyRead(ctx, principal, req, handle, denyCachedRead), nil
	}

	// Verification-read binding checks (GA Task 0D amendment), all against
	// SERVER-SIDE truth. Cache policy: in this plane every read serves
	// locate-staged content, so the fresh source resolution IS the locate
	// staging - a verification read may mint only under the explicit
	// cached-read grant (enforced above), on the CURRENT source version
	// (enforced above: a moved-on source denies), and while the staging
	// instant is still inside the registry-declared freshness bound. The
	// receipt then states observed_at = staging instant, never the mint
	// instant, so it never claims fresher than reality.
	if declared != nil {
		switch {
		case handle.DataClass != declared.DataClass:
			// The caller-declared need expectation conflicts with the
			// resolved read: a mismatched verification need fails closed.
			return s.denyRead(ctx, principal, req, handle, denyNeedMismatch), nil
		case !validAuthorityTier(binding.AuthorityTier) || binding.FreshnessBound <= 0:
			// No declared observation authority to derive: the service never
			// invents a tier and never accepts one from the caller.
			return s.denyRead(ctx, principal, req, handle, denyObservationUnsupported), nil
		case !now.Before(handle.StagedAt.Add(binding.FreshnessBound)):
			// The staged observation aged past its declared freshness bound;
			// minting would claim fresher than reality.
			return s.denyRead(ctx, principal, req, handle, denyObservationStale), nil
		}
		if s.actionBinding != nil {
			// GA Task 0F seam: the wired verifier is authoritative for the
			// Action side of the binding (stored Action, parameter hash,
			// declared postcondition/need membership).
			if err := s.actionBinding.VerifyActionBinding(ctx, principal.TenantRef, *declared); err != nil {
				return s.denyRead(ctx, principal, req, handle, denyActionUnbound), nil
			}
		}
	}

	// Re-evaluate the capability against the CURRENT sealed org version: an
	// organization/ACL change since locate fails closed here.
	decision, err := s.decider.Evaluate(ctx, policy.CapabilityRequest{
		TenantRef:        principal.TenantRef,
		PrincipalRef:     principal.PrincipalRef,
		SealedOrgVersion: authz.OrgVersion,
		ResourceType:     policy.ResourceType(binding.ResourceType),
		ResourceID:       binding.ResourceID,
		Capability:       policy.Capability(binding.AccessCapability),
	})
	if err != nil {
		return ReadResult{}, errors.Join(ErrUnavailable, err)
	}
	if decision.Decision != policy.DecisionAllow {
		return s.denyRead(ctx, principal, req, handle, denyPolicy), nil
	}

	ciphertext, err := s.objects.Get(ctx, handle.ObjectKey)
	if err != nil {
		return ReadResult{}, errors.Join(ErrUnavailable, err)
	}
	key, err := s.keys.KeyByRef(ctx, principal.TenantRef, handle.KeyRef)
	if err != nil {
		return ReadResult{}, errors.Join(ErrUnavailable, err)
	}
	plaintext, err := open(key.Key, ciphertext, contentAAD(handle.TenantRef, handle.ObjectKey))
	if err != nil {
		return ReadResult{}, errors.Join(ErrUnavailable, errors.New("staged content failed authenticated decryption"))
	}
	sum := sha256.Sum256(plaintext)
	if hex.EncodeToString(sum[:]) != handle.ContentHash {
		s.logger.ErrorContext(ctx, "evidence.content_integrity_failure",
			slog.String("tenant_ref", principal.TenantRef),
			slog.String("evidence_ref", handle.EvidenceRef),
		)
		return ReadResult{}, errors.Join(ErrUnavailable, errors.New("staged content hash mismatch"))
	}
	var records []Record
	if err := json.Unmarshal(plaintext, &records); err != nil {
		return ReadResult{}, errors.Join(ErrUnavailable, err)
	}

	// Pagination window: bounded pages end in an explicit continuation
	// handle; content is never silently truncated.
	offset := handle.RecordOffset
	if offset > int64(len(records)) {
		offset = int64(len(records))
	}
	window := records[offset:]
	// The locate-time page bound (handle.PageLimit) is a CEILING: a read
	// request may narrow the page but never raise it above what locate bound.
	limit := handle.PageLimit
	if req.Constraints != nil && req.Constraints.MaxResults > 0 {
		if limit == 0 || req.Constraints.MaxResults < limit {
			limit = req.Constraints.MaxResults
		}
	}
	page := window
	continuationRef := ""
	if limit > 0 && int64(len(window)) > limit {
		page = window[:limit]
		continuationRef = s.newID(runtime.HandleEvidence)
		if !canonical(continuationRef) {
			return ReadResult{}, ErrUnavailable
		}
		continuation := handle
		continuation.EvidenceRef = continuationRef
		continuation.RecordOffset = offset + limit
		continuation.Lineage = append(append([]string(nil), handle.Lineage...), handle.EvidenceRef)
		continuation.CreatedAt = time.Time{}
		if _, err := s.store.CreateHandle(ctx, continuation); err != nil {
			return ReadResult{}, errors.Join(ErrUnavailable, err)
		}
	}
	page = projectRecords(page, req.Fields)

	// The lineage append of an ALLOWED read is mandatory: no unaudited data
	// egress. A verification read records its declared binding in the same
	// lineage entry (refs and ids only) and the entry's reference becomes the
	// receipt's audit_ref_id, so the observation ref is generated first.
	observationRef := ""
	details := map[string]any{
		"decision":             DecisionAllow,
		"data_class":           handle.DataClass,
		"source_version":       handle.SourceVersion,
		"content_hash":         handle.ContentHash,
		"org_version":          authz.OrgVersion,
		"business_context_ref": handle.BusinessContextRef,
		"record_count":         int64(len(page)),
		"served_from_cache":    true,
	}
	if continuationRef != "" {
		details["continuation_ref"] = continuationRef
	}
	if declared != nil {
		observationRef = s.newID(runtime.HandleObservation)
		if !canonical(observationRef) {
			return ReadResult{}, ErrUnavailable
		}
		details["action_ref"] = declared.ActionRef
		details["postcondition_id"] = declared.PostconditionID
		details["verification_need_id"] = declared.VerificationNeedID
		details["observation_ref"] = observationRef
		details["observation_authority"] = binding.AuthorityTier
	}
	auditRef, err := s.audit.AppendEvidenceAudit(ctx, AuditEvent{
		TenantRef:    principal.TenantRef,
		PrincipalRef: principal.PrincipalRef,
		Action:       auditActionRead,
		ResourceType: "evidence_handle",
		ResourceID:   handle.EvidenceRef,
		TraceID:      req.TraceID,
		Details:      details,
	})
	if err != nil || auditRef == "" {
		return ReadResult{}, errors.Join(ErrUnavailable, errors.New("read lineage append failed"))
	}

	// Mint the signed observation receipt of an allowed verification read. A
	// verification read that cannot produce its receipt fails CLOSED: the
	// caller asked for a verified observation, not for bare data.
	var receipt *runtime.ObservationReceipt
	if declared != nil {
		minted, err := s.mintObservationReceipt(ctx, observationRef, *declared, handle, binding, auditRef)
		if err != nil {
			return ReadResult{}, err
		}
		receipt = &minted
		s.logger.InfoContext(ctx, "evidence.observation_minted",
			slog.String("tenant_ref", principal.TenantRef),
			slog.String("observation_ref", minted.ObservationRef),
			slog.String("evidence_ref", minted.EvidenceRef),
			slog.String("action_ref", minted.ActionRef),
			slog.String("authority", minted.Authority),
			slog.Int64("source_version", minted.SourceVersion),
			slog.String("observation_hash", minted.ObservationHash),
		)
	}

	s.logger.InfoContext(ctx, "evidence.read",
		slog.String("tenant_ref", principal.TenantRef),
		slog.String("evidence_ref", handle.EvidenceRef),
		slog.String("data_class", handle.DataClass),
		slog.Int64("source_version", handle.SourceVersion),
		slog.String("content_hash", handle.ContentHash),
		slog.String("decision", DecisionAllow),
	)
	return ReadResult{
		Decision:           DecisionAllow,
		Data:               map[string]any{"records": page},
		SourceVersion:      handle.SourceVersion,
		AsOf:               handle.StagedAt,
		ServedFromCache:    true,
		ContinuationRef:    continuationRef,
		ObservationReceipt: receipt,
	}, nil
}

// denyRead records the coded denial (best-effort) and returns the bare typed
// deny. The public envelope carries the decision only — reasons stay in the
// lineage, and neither carries content or topology.
func (s *Service) denyRead(ctx context.Context, principal runtime.PrincipalContext, req runtime.EvidenceReadRequest, handle Handle, reason string) ReadResult {
	details := map[string]any{"decision": DecisionDeny, "reason": reason}
	if handle.DataClass != "" {
		details["data_class"] = handle.DataClass
		details["content_hash"] = handle.ContentHash
		details["source_version"] = handle.SourceVersion
	}
	_, _ = s.audit.AppendEvidenceAudit(ctx, AuditEvent{
		TenantRef:    principal.TenantRef,
		PrincipalRef: principal.PrincipalRef,
		Action:       auditActionRead,
		ResourceType: "evidence_handle",
		ResourceID:   req.EvidenceRef,
		TraceID:      req.TraceID,
		Details:      details,
	})
	s.logger.WarnContext(ctx, "evidence.read_denied",
		slog.String("tenant_ref", principal.TenantRef),
		slog.String("evidence_ref", req.EvidenceRef),
		slog.String("reason", reason),
	)
	return ReadResult{Decision: DecisionDeny}
}

// prohibitedUses merges the request- and need-level prohibited purposes.
func prohibitedUses(req runtime.EvidenceRequest, need runtime.DataNeed) []string {
	var out []string
	if req.Constraints != nil {
		out = append(out, req.Constraints.ProhibitedUses...)
	}
	if need.Constraints != nil {
		out = append(out, need.Constraints.ProhibitedUses...)
	}
	return out
}

// pageLimit resolves the persisted default page bound of a handle.
func pageLimit(req runtime.EvidenceRequest, need runtime.DataNeed) int64 {
	if need.Constraints != nil && need.Constraints.MaxResults > 0 {
		return need.Constraints.MaxResults
	}
	if req.Constraints != nil && req.Constraints.MaxResults > 0 {
		return req.Constraints.MaxResults
	}
	return 0
}

// stagingFields resolves the field projection applied at staging time
// (data minimization: only fields the need may use are staged).
func stagingFields(need runtime.DataNeed) []string {
	var allowed []string
	if need.Constraints != nil {
		allowed = need.Constraints.AllowedFields
	}
	switch {
	case len(need.Fields) > 0 && len(allowed) > 0:
		allowedSet := make(map[string]bool, len(allowed))
		for _, field := range allowed {
			allowedSet[field] = true
		}
		var out []string
		for _, field := range need.Fields {
			if allowedSet[field] {
				out = append(out, field)
			}
		}
		if out == nil {
			out = []string{}
		}
		return out
	case len(need.Fields) > 0:
		return need.Fields
	default:
		return allowed
	}
}

// projectRecords projects records onto the requested fields (nil/empty =
// every field).
func projectRecords(records []Record, fields []string) []Record {
	if fields == nil {
		return records
	}
	if len(fields) == 0 {
		out := make([]Record, len(records))
		for i := range records {
			out[i] = Record{}
		}
		return out
	}
	out := make([]Record, 0, len(records))
	for _, record := range records {
		projected := Record{}
		for _, field := range fields {
			if value, ok := record[field]; ok {
				projected[field] = value
			}
		}
		out = append(out, projected)
	}
	return out
}

// contentAAD binds a sealed blob to its tenant and OBJECT key (continuation
// handles legitimately share the object, so the evidence ref is deliberately
// not part of the binding).
func contentAAD(tenantRef, objectKey string) []byte {
	return []byte(tenantRef + "|" + objectKey)
}

// aesGCM enforces the documented AES-256 strength: a shorter key (AES-128/192
// would silently downgrade) is rejected outright.
func aesGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("content key must be exactly 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext with AES-256-GCM bound to additionalData; the
// returned blob is nonce||ciphertext. Object stores only ever receive this
// sealed form.
func seal(key, plaintext, additionalData []byte) ([]byte, error) {
	gcm, err := aesGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, additionalData), nil
}

// open authenticates and decrypts a sealed blob under its binding.
func open(key, blob, additionalData []byte) ([]byte, error) {
	gcm, err := aesGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("sealed blob is truncated")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, additionalData)
}
