// Package agent is the GA Task 6 outbound Connector Agent: the central
// Connector Worker's durable-execution core (internal/connectors/worker) run at
// the CUSTOMER EDGE over an outbound-initiated mTLS session. It differs from the
// central Worker only in TRANSPORT and TOPOLOGY, never in the execution, receipt
// or observation invariants — it drives every dispatch through the worker's
// exported, safety-critical helpers (ValidateBinding, BuildHostOperation,
// ClassifyHostResult, BuildSignedActionReceipt, ProduceObservation) and the
// shared isolated host (internal/connectors/host), so the edge can never fork
// the C1 provenance rules.
//
// The agent DIALS OUT (it never binds a listener), keeping the connector and its
// credentials LOCAL; it reaches the authoritative central Action state over the
// outbound session (a worker.ActionPlane bridge). Its Task 6 additions over the
// central Worker are: an outbound-only mTLS session with revocation/rotation
// teardown, a bounded local intake queue with backpressure, an edge DURABLE
// journal so a disconnect/restart resumes the SAME Action/VerificationNeed
// instead of re-executing or dropping observations, and a signed self-update
// with rollback verified against an EXTERNAL trust anchor.
//
// Fail closed: every deferred concrete dependency (the Postgres BindingResolver,
// the evidence-backed ObservationProducer, the central ActionPlane responder and
// the concrete durable edge-journal store all land in the Task 7 connector-
// qualification work) is nil-guarded and reported not-ready — there is no
// pass-stub and no fabricated receipt, mirroring the central Worker (Task 5).
package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
)

// DurableName is the stable JetStream durable-consumer name the outbound
// Connector Agent binds on actions.SubjectActionDispatch. Every intake is then
// re-checked against the agent's tenant/binding Pin, so the durable consumer
// never delivers work outside the agent's pinned scope to the isolated host.
const DurableName = "connector-agent"

// fetchBatch and fetchWait bound one durable pull; the bounded intake queue
// applies backpressure so no more than the queue can hold is ever fetched.
const (
	fetchBatch = 16
	fetchWait  = 2 * time.Second
)

// Agent orchestration errors. Transient failures (a dropped session, a
// persistence outage) surface as errors so the durable pull leaves the dispatch
// for redelivery; terminal decisions surface as a worker.ProcessResult Outcome
// with a nil error.
var (
	// ErrNotReady marks an agent whose fail-closed dependencies are not all wired
	// (a nil BindingResolver / ObservationProducer / ReceiptSigner / ActionPlane /
	// EdgeJournal). It is never a pass-stub.
	ErrNotReady = errors.New("connector agent not ready")
	// ErrInvalidConfig marks a structurally invalid agent configuration.
	ErrInvalidConfig = errors.New("connector agent configuration invalid")
	// ErrOutsidePin marks a dispatch whose tenant/capability is outside the
	// agent's pinned scope: it is rejected and NEVER executed.
	ErrOutsidePin = errors.New("dispatch is outside the connector agent's tenant/binding pin")
	// ErrRecordReceipt marks a failure to durably journal a minted ActionReceipt
	// at the edge BEFORE the central apply; it is transient (do not ack).
	ErrRecordReceipt = errors.New("edge journal failed to record the action receipt")
)

// Pin is the agent's frozen tenant/binding scope. Every intake must fall within
// it: a dispatch for another tenant, or for a capability the agent is not bound
// to, is rejected and never reaches the isolated host.
type Pin struct {
	TenantRef    string
	Capabilities []string
}

func (p Pin) validate() error {
	if p.TenantRef == "" {
		return errors.Join(ErrInvalidConfig, errors.New("agent pin requires a tenant_ref"))
	}
	if len(p.Capabilities) == 0 {
		return errors.Join(ErrInvalidConfig, errors.New("agent pin requires at least one bound capability"))
	}
	return nil
}

// authorize reports whether (tenantRef, capability) is within the pin.
func (p Pin) authorize(tenantRef, capability string) error {
	if tenantRef != p.TenantRef {
		return errors.Join(ErrOutsidePin, errors.New("dispatch tenant is outside the agent's pinned tenant"))
	}
	for _, c := range p.Capabilities {
		if c == capability {
			return nil
		}
	}
	return errors.Join(ErrOutsidePin, errors.New("dispatch capability is outside the agent's pinned binding set"))
}

// EdgeJournal is the agent's LOCAL durable record of what a dispatch has already
// produced, keyed by (tenant, action_ref, dispatch_ref) for the minted
// ActionReceipt and by (tenant, action_ref, need_id) for each produced
// ObservationReceipt. It is what makes a disconnect/restart RESUME the SAME
// Action/VerificationNeed instead of re-executing or dropping observations. The
// concrete durable edge store lands in Task 7; until then this port is nil
// (CheckReady fails closed) and tests supply an in-memory fake — never a
// pass-stub.
type EdgeJournal interface {
	LoadReceipt(ctx context.Context, tenantRef, actionRef, dispatchRef string) (runtime.ActionReceipt, bool, error)
	RecordReceipt(ctx context.Context, tenantRef, actionRef, dispatchRef string, receipt runtime.ActionReceipt) error
	LoadObservation(ctx context.Context, tenantRef, actionRef, needID string) (runtime.ObservationReceipt, bool, error)
	RecordObservation(ctx context.Context, tenantRef, actionRef, needID string, receipt runtime.ObservationReceipt) error
}

// ClientTLSProvider builds the outbound mTLS client config and follows material
// rotations. *transportsecurity.Manager satisfies it. The agent uses ONLY the
// client (dialing) side — it never serves — and re-establishes on every accepted
// rotation so a revoked peer is never silently kept alive.
type ClientTLSProvider interface {
	ClientTLSConfig(peers sdk.PeerAuthorization, serverName string) (*tls.Config, error)
	IdentityURI() string
	OnRotate(fn func())
	Reload() error
}

// Transport is one established outbound session connection. The agent only ever
// obtains a Transport by DIALING; it never accepts one.
type Transport interface {
	Connected() bool
	Close() error
}

// Dialer establishes the outbound session transport from the pinned mTLS client
// config. Production uses a NATS-over-mTLS dialer; unit tests inject a fake. The
// agent NEVER binds a listener — this is the only way it obtains a connection.
type Dialer interface {
	Dial(ctx context.Context, tlsConfig *tls.Config) (Transport, error)
}

// HealthView is the agent's OUTWARD health surface. By construction it carries
// NO connector topology (no connector instance id, endpoint, resource, table/API
// path or credential ref): those never appear on any Agent-facing surface.
type HealthView struct {
	Connected           bool
	AgentVersion        string
	IdentityURI         string
	InFlight            int
	LastHeartbeat       time.Time
	DurableConsumer     string
	ExecutionPlaneReady bool
	PendingSeam         string
}

// Config constructs a Session. ActionPlane, Resolver, Signer, Observations and
// Journal are the fail-closed dependencies; Identity supplies the first-party
// principal (reused from the central Worker for one identity vocabulary); Pin is
// the tenant/binding scope. The transport members (TLS, Peers, ServerName,
// Dialer) are required only to Establish/Run over a live outbound session; the
// exactly-once pipeline is unit-tested with an injected ActionPlane.
type Config struct {
	ActionPlane  worker.ActionPlane
	Resolver     worker.BindingResolver
	Signer       worker.ReceiptSigner
	Observations worker.ObservationProducer
	Journal      EdgeJournal
	Identity     worker.Identity
	Pin          Pin

	TLS        ClientTLSProvider
	Peers      sdk.PeerAuthorization
	ServerName string
	Dialer     Dialer
	QueueBound int

	Version     string
	IdentityURI string
	Updater     *Updater
}

// Session is the outbound Connector Agent: an outbound-initiated mTLS session
// plus the resumable durable-execution pipeline.
type Session struct {
	actions      worker.ActionPlane
	resolver     worker.BindingResolver
	signer       worker.ReceiptSigner
	observations worker.ObservationProducer
	journal      EdgeJournal
	identity     worker.Identity
	pin          Pin

	tls        ClientTLSProvider
	peers      sdk.PeerAuthorization
	serverName string
	dialer     Dialer
	queueBound int

	version     string
	identityURI string
	updater     *Updater

	logger   *slog.Logger
	now      func() time.Time
	newID    func(prefix string) string
	inflight *inflightSet

	mu            sync.Mutex
	transport     Transport
	connected     bool
	lastHeartbeat time.Time
}

// Option configures a Session.
type Option func(*Session)

// WithClock overrides the agent clock.
func WithClock(clock func() time.Time) Option {
	return func(s *Session) {
		if clock != nil {
			s.now = clock
		}
	}
}

// WithIDGenerator overrides the opaque identifier generator (receipt refs).
func WithIDGenerator(newID func(prefix string) string) Option {
	return func(s *Session) {
		if newID != nil {
			s.newID = newID
		}
	}
}

// WithLogger overrides the agent logger. Log lines carry refs, statuses and
// coded reasons only — never connector topology or secret material.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Session) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// New builds an outbound Connector Agent. ActionPlane, a valid Identity and a
// valid Pin are mandatory; the fail-closed dependencies (Resolver, Signer,
// Observations, Journal) may be nil at construction but make CheckReady report
// not-ready so production never serves a dispatch with a missing seam.
func New(cfg Config, opts ...Option) (*Session, error) {
	if cfg.ActionPlane == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("agent requires an action plane"))
	}
	if err := validateAgentIdentity(cfg.Identity); err != nil {
		return nil, err
	}
	if err := cfg.Pin.validate(); err != nil {
		return nil, err
	}
	s := &Session{
		actions:      cfg.ActionPlane,
		resolver:     cfg.Resolver,
		signer:       cfg.Signer,
		observations: cfg.Observations,
		journal:      cfg.Journal,
		identity:     cfg.Identity,
		pin:          cfg.Pin,
		tls:          cfg.TLS,
		peers:        cfg.Peers,
		serverName:   cfg.ServerName,
		dialer:       cfg.Dialer,
		queueBound:   cfg.QueueBound,
		version:      cfg.Version,
		identityURI:  cfg.IdentityURI,
		updater:      cfg.Updater,
		logger:       slog.Default(),
		now:          func() time.Time { return time.Now().UTC() },
		newID:        randomOpaqueID,
		inflight:     newInflightSet(),
	}
	if s.queueBound <= 0 {
		s.queueBound = fetchBatch
	}
	for _, opt := range opts {
		opt(s)
	}
	// Re-establish on every accepted material rotation: a revoked peer must never
	// be silently kept alive on a pooled connection.
	if s.tls != nil {
		s.tls.OnRotate(s.HandleRotation)
	}
	return s, nil
}

// validateAgentIdentity checks the reused central-Worker Identity so the agent's
// first-party principal lineage is complete (it is never sourced from a dispatch).
func validateAgentIdentity(i worker.Identity) error {
	if i.PrincipalRef == "" || i.AgentClientRef == "" || i.AgentReleaseRef == "" || i.OrgSnapshotRef == "" {
		return errors.Join(ErrInvalidConfig, errors.New("agent identity requires principal_ref, agent_client_ref, agent_release_ref and org_snapshot_ref"))
	}
	return nil
}

// randomOpaqueID mints an opaque handle with the given prefix (receipt refs).
func randomOpaqueID(prefix string) string {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}

// CheckReady reports whether every fail-closed dependency is wired. A nil
// BindingResolver / ObservationProducer / ReceiptSigner / EdgeJournal is a
// documented seam pending Task 7 and fails closed here — never a pass-stub. The
// production command must not serve dispatches until this returns nil.
func (s *Session) CheckReady(ctx context.Context) error {
	if s == nil || s.actions == nil {
		return ErrNotReady
	}
	if s.resolver == nil {
		return errors.Join(ErrNotReady, errors.New("no binding resolver wired (concrete Postgres resolver lands in Task 7)"))
	}
	if s.signer == nil {
		return errors.Join(ErrNotReady, errors.New("no receipt signer wired; an unsigned ActionReceipt can never complete an action"))
	}
	if s.observations == nil {
		return errors.Join(ErrNotReady, errors.New("no observation producer wired (concrete evidence-backed producer lands in Task 7)"))
	}
	if s.journal == nil {
		return errors.Join(ErrNotReady, errors.New("no edge journal wired (concrete durable edge store lands in Task 7)"))
	}
	// Present is not the same as runnable. The shared Postgres resolver composed
	// without a HostFactory resolves every binding and then refuses transiently,
	// so an agent serving with it would retry every dispatch forever. The edge
	// runs INSIDE the customer's network, so it must be at least as strict as the
	// centre: ask the resolver before accepting work.
	if probe, ok := s.resolver.(worker.ResolverReadiness); ok {
		if err := probe.CheckReady(ctx); err != nil {
			// The resolver's own not-ready sentinel is the worker package's; this
			// surface answers with the agent's, so both are carried.
			return errors.Join(ErrNotReady, err)
		}
	}
	return nil
}

// principalFor builds the connector-agent SYSTEM principal for one tenant. The
// tenant comes from the (server-authored) dispatch; every other field is the
// agent's own first-party identity, never derived from Agent input.
func (s *Session) principalFor(tenantRef string) runtime.PrincipalContext {
	now := s.now().UTC()
	return runtime.PrincipalContext{
		TenantRef:       tenantRef,
		PrincipalRef:    s.identity.PrincipalRef,
		AgentClientRef:  s.identity.AgentClientRef,
		AgentReleaseRef: s.identity.AgentReleaseRef,
		TrustClass:      runtime.TrustFirstParty,
		OrgSnapshotRef:  s.identity.OrgSnapshotRef,
		VerifiedAt:      now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
}

// Establish dials the outbound session. It builds the pinned mTLS client config
// (mutual identity is not opt-out) and hands it to the dialer; the agent NEVER
// binds a listener. It fails closed if the client config cannot be expressed.
func (s *Session) Establish(ctx context.Context) error {
	if s.dialer == nil {
		return errors.Join(ErrInvalidConfig, errors.New("establish requires an outbound dialer; the agent never binds a listener"))
	}
	var cfg *tls.Config
	if s.tls != nil {
		if s.serverName == "" {
			return errors.Join(ErrInvalidConfig, errors.New("mutual TLS requires a server name for hostname verification"))
		}
		// Mutual identity has no opt-out: the pinned PeerAuthorization authorizes
		// the central server identity and the client always presents its cert.
		c, err := s.tls.ClientTLSConfig(s.peers, s.serverName)
		if err != nil {
			return err // fail closed: the client cannot express its mTLS material
		}
		cfg = c
	}
	tr, err := s.dialer.Dial(ctx, cfg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.transport != nil {
		_ = s.transport.Close()
	}
	s.transport = tr
	s.connected = true
	s.lastHeartbeat = s.now()
	s.mu.Unlock()
	return nil
}

// HandleRotation is fired after every accepted material rotation (revocation /
// re-key): it tears the live session down so a revoked peer cannot keep a
// connection, and flags any in-flight uncertain Action result_unknown (never a
// fabricated verdict). A subsequent re-establish must not duplicate any external
// operation — the edge journal + the durable executing barrier guarantee it.
func (s *Session) HandleRotation() {
	s.mu.Lock()
	tr := s.transport
	s.transport = nil
	s.connected = false
	s.mu.Unlock()
	if tr != nil {
		_ = tr.Close()
	}
	// Flag any in-flight uncertain Action result_unknown: after a teardown the host
	// may have run but the outcome cannot be attested over the dropped session, so
	// it is result_unknown — never a fabricated verdict. A subsequent re-establish +
	// redelivery re-applies a journaled receipt (no duplicate) or resolves to
	// result_unknown, never a blind re-run.
	principal := s.principalFor(s.pin.TenantRef)
	for _, ref := range s.inflight.snapshot() {
		if _, err := s.actions.MarkResultUnknown(context.Background(), principal, ref); err != nil {
			s.logger.Warn("agent.rotation_result_unknown_failed", slog.String("action_ref", ref), slog.String("error", err.Error()))
		}
		s.inflight.release(ref)
	}
}

// Health returns the agent's OUTWARD health view. By construction it carries no
// connector topology (no connector instance id, endpoint, resource, table/API
// path or credential ref).
func (s *Session) Health() HealthView {
	s.mu.Lock()
	connected := s.connected
	lastHB := s.lastHeartbeat
	s.mu.Unlock()
	version := s.version
	if s.updater != nil {
		version = s.updater.ActiveVersion()
	}
	ready := s.CheckReady(context.Background()) == nil
	pending := ""
	if !ready {
		pending = "not_ready(pending_task7:binding_resolver,observation_producer,action_plane_responder,edge_journal)"
	}
	return HealthView{
		Connected:           connected,
		AgentVersion:        version,
		IdentityURI:         s.identityURI,
		InFlight:            s.inflight.size(),
		LastHeartbeat:       lastHB,
		DurableConsumer:     DurableName,
		ExecutionPlaneReady: ready,
		PendingSeam:         pending,
	}
}

// ProcessDispatch is the exactly-once, RESUMABLE orchestration of ONE dispatch
// intent at the customer edge. A returned error is TRANSIENT (nak for redelivery
// / resume); a nil error with a worker.ProcessResult is a terminal decision
// (ack). It never executes twice, never fabricates a receipt, never asserts a
// business Outcome and never lets connector topology reach an Agent surface.
func (s *Session) ProcessDispatch(ctx context.Context, msg actions.DispatchMessage) (worker.ProcessResult, error) {
	principal := s.principalFor(msg.TenantRef)
	action, err := s.actions.GetAction(ctx, principal, msg.ActionRef)
	if err != nil {
		if errors.Is(err, actions.ErrNotFound) {
			// No such action for this tenant: a forged or stale dispatch. Reject.
			s.logger.WarnContext(ctx, "agent.dispatch_unknown_action", slog.String("action_ref", msg.ActionRef))
			return worker.ProcessResult{Outcome: worker.OutcomeRejected}, nil
		}
		return worker.ProcessResult{}, err // transient (a dropped session) -> nak/resume
	}
	// Exact digest/binding + grant validation — the central Worker's rules, reused.
	if err := worker.ValidateBinding(msg, action); err != nil {
		s.logger.WarnContext(ctx, "agent.dispatch_binding_rejected",
			slog.String("action_ref", msg.ActionRef), slog.String("error", err.Error()))
		return worker.ProcessResult{Outcome: worker.OutcomeRejected}, nil
	}
	// Tenant/binding pin: a dispatch for another tenant, or for a capability the
	// agent is not bound to, is rejected and NEVER reaches the isolated host.
	if err := s.pin.authorize(action.TenantRef, action.Capability); err != nil {
		s.logger.WarnContext(ctx, "agent.dispatch_outside_pin",
			slog.String("action_ref", msg.ActionRef), slog.String("error", err.Error()))
		return worker.ProcessResult{Outcome: worker.OutcomeRejected}, nil
	}
	// An action being reconciled out of band must never be blindly re-executed.
	if actions.AwaitingReconciliation(action.Status) {
		return worker.ProcessResult{Outcome: worker.OutcomeSkipped}, nil
	}

	switch action.Status {
	case actions.StatusSucceeded:
		// Terminal succeeded: if declared VerificationNeeds are not all journaled,
		// RESUME the remaining observations; otherwise an idempotent no-op (dedup).
		// Take in-process ownership SYMMETRICALLY with the dispatched branch so two
		// concurrent redeliveries of a succeeded Action cannot both drive the same
		// not-yet-journaled need (the "connector/producer invoked at most once
		// across all resume paths" invariant holds uniformly, not just for the
		// execution path). A non-concurrent replay acquires cleanly and dedups.
		if !s.inflight.acquire(msg.ActionRef) {
			return worker.ProcessResult{Outcome: worker.OutcomeSkipped}, nil
		}
		defer s.inflight.release(msg.ActionRef)
		return s.resumeObservations(ctx, principal, action, msg)
	case actions.StatusFailed:
		// Already terminal: a redelivery is an idempotent no-op, no second receipt.
		return worker.ProcessResult{Outcome: worker.OutcomeDeduped}, nil
	case actions.StatusExecuting:
		if s.inflight.owns(msg.ActionRef) {
			// A concurrent sibling in THIS process owns the execution; defer to it.
			return worker.ProcessResult{Outcome: worker.OutcomeSkipped}, nil
		}
		// The barrier was crossed by a prior attempt: resume from the edge journal.
		return s.resumeExecuting(ctx, principal, action, msg)
	case actions.StatusDispatched:
		if !s.inflight.acquire(msg.ActionRef) {
			return worker.ProcessResult{Outcome: worker.OutcomeSkipped}, nil
		}
		defer s.inflight.release(msg.ActionRef)
		return s.executeAndComplete(ctx, principal, action, msg)
	default:
		// granted / awaiting_approval / requested / compensating / human_takeover:
		// not an executable dispatch state.
		return worker.ProcessResult{Outcome: worker.OutcomeSkipped}, nil
	}
}

// executeAndComplete owns a dispatched Action end to end at the edge: resolve the
// PRIVATE binding, cross the durable executing barrier, invoke the shared
// isolated host locally, journal the minted receipt at the edge BEFORE the
// central apply, complete the Action and drive the declared observations. Every
// uncertain or unattestable outcome fails closed to result_unknown — never a
// fabricated receipt, never a re-run.
func (s *Session) executeAndComplete(ctx context.Context, principal runtime.PrincipalContext, action actions.Action, msg actions.DispatchMessage) (worker.ProcessResult, error) {
	// Resolve the PRIVATE binding BEFORE the barrier, so a resolver outage leaves
	// the Action dispatched (retryable) with no barrier and no side effect.
	rb, err := s.resolver.Resolve(ctx, action.TenantRef, action.Capability)
	if err != nil {
		if errors.Is(err, host.ErrDigestMismatch) {
			// A stale/digest-swapped package is a PERMANENT refusal (fail closed),
			// never executed and never a receipt — not a transient retry.
			s.logger.WarnContext(ctx, "agent.stale_package_refused", slog.String("action_ref", action.ActionRef))
			return worker.ProcessResult{Outcome: worker.OutcomeRejected}, nil
		}
		return worker.ProcessResult{}, errors.Join(errors.New("binding resolution failed"), err) // transient
	}
	if rb.Host == nil {
		return worker.ProcessResult{}, errors.Join(ErrNotReady, errors.New("resolved binding has no host runner"))
	}

	// Durable barrier: dispatched -> executing. After this the side effect may run,
	// so a crash/disconnect before completion becomes result_unknown (or a
	// journaled-receipt re-apply), never a blind retry.
	if _, err := s.actions.MarkExecuting(ctx, principal, action.ActionRef); err != nil {
		if errors.Is(err, actions.ErrForbiddenTransition) {
			return s.reclassify(ctx, principal, action.ActionRef)
		}
		return worker.ProcessResult{}, err // transient (disconnect before execution leaves dispatched)
	}

	result, status, uncertain := runOnHost(ctx, rb, action, msg)
	if uncertain {
		s.logger.WarnContext(ctx, "agent.host_outcome_uncertain",
			slog.String("action_ref", action.ActionRef), slog.String("host_status", result.Status.String()))
		return s.flagResultUnknown(ctx, principal, action.ActionRef)
	}

	receipt, err := worker.BuildSignedActionReceipt(ctx, s.signer, s.newID, s.now, action, status, result)
	if err != nil {
		s.logger.ErrorContext(ctx, "agent.receipt_production_failed",
			slog.String("action_ref", action.ActionRef), slog.String("error", err.Error()))
		return s.flagResultUnknown(ctx, principal, action.ActionRef)
	}

	// Journal the receipt at the EDGE, durably, BEFORE the central apply, so a
	// disconnect after execution re-applies the SAME receipt on resume rather than
	// re-running the connector. A journal outage is transient: fail closed (do not
	// apply centrally without a durable edge record).
	if err := s.journal.RecordReceipt(ctx, action.TenantRef, action.ActionRef, msg.DispatchRef, receipt); err != nil {
		return worker.ProcessResult{}, errors.Join(ErrRecordReceipt, err)
	}

	completed, err := s.actions.IngestReceipt(ctx, principal, msg.DispatchRef, receipt)
	if err != nil {
		if errors.Is(err, actions.ErrForbiddenTransition) {
			return s.reclassify(ctx, principal, action.ActionRef)
		}
		// Executed and journaled, but the central apply was lost: transient. The
		// resume path re-applies the journaled receipt — no duplicate.
		return worker.ProcessResult{}, err
	}

	res := worker.ProcessResult{Outcome: worker.OutcomeCompleted, ActionReceipt: &receipt}
	if completed.Status == actions.StatusSucceeded {
		receipts, _, transientErr, obsErr := s.driveObservations(ctx, action)
		if transientErr != nil {
			// Do NOT ack: observations are incomplete. Redelivery resumes the rest.
			return worker.ProcessResult{}, transientErr
		}
		res.ObservationReceipts = receipts
		res.ObservationErr = obsErr
	}
	return res, nil
}

// resumeExecuting recovers an Action left executing by a prior attempt. If the
// edge journal holds the minted receipt for this dispatch, it re-applies it
// (idempotent on dispatch_ref) — the connector is NEVER re-run. If no receipt was
// durably journaled, the host may have run but cannot be attested, so it is
// result_unknown (never a blind retry). This is the disconnect-after-execution
// resume.
func (s *Session) resumeExecuting(ctx context.Context, principal runtime.PrincipalContext, action actions.Action, msg actions.DispatchMessage) (worker.ProcessResult, error) {
	receipt, ok, err := s.journal.LoadReceipt(ctx, action.TenantRef, action.ActionRef, msg.DispatchRef)
	if err != nil {
		return worker.ProcessResult{}, err // transient (journal outage)
	}
	if !ok {
		return s.flagResultUnknown(ctx, principal, action.ActionRef)
	}
	completed, err := s.actions.IngestReceipt(ctx, principal, msg.DispatchRef, receipt)
	if err != nil {
		if errors.Is(err, actions.ErrForbiddenTransition) {
			return s.reclassify(ctx, principal, action.ActionRef)
		}
		return worker.ProcessResult{}, err // transient
	}
	res := worker.ProcessResult{Outcome: worker.OutcomeCompleted, ActionReceipt: &receipt}
	if completed.Status == actions.StatusSucceeded {
		receipts, _, transientErr, obsErr := s.driveObservations(ctx, action)
		if transientErr != nil {
			return worker.ProcessResult{}, transientErr
		}
		res.ObservationReceipts = receipts
		res.ObservationErr = obsErr
	}
	return res, nil
}

// resumeObservations resumes the declared postcondition observations of an
// already-succeeded Action. If any remain, it produces exactly those and returns
// the full deduplicated set; if all are already journaled, it is an idempotent
// no-op (dedup). The connector is never touched here — the technical execution
// already completed.
func (s *Session) resumeObservations(ctx context.Context, principal runtime.PrincipalContext, action actions.Action, msg actions.DispatchMessage) (worker.ProcessResult, error) {
	receipts, produced, transientErr, obsErr := s.driveObservations(ctx, action)
	if transientErr != nil {
		return worker.ProcessResult{}, transientErr
	}
	res := worker.ProcessResult{ObservationReceipts: receipts, ObservationErr: obsErr}
	if rec, ok, _ := s.journal.LoadReceipt(ctx, action.TenantRef, action.ActionRef, msg.DispatchRef); ok {
		res.ActionReceipt = &rec
	}
	if produced > 0 {
		res.Outcome = worker.OutcomeCompleted
	} else {
		res.Outcome = worker.OutcomeDeduped
	}
	return res, nil
}

// driveObservations produces the exact deduplicated ObservationReceipt set for
// the Action's declared VerificationNeeds, loading any already-journaled need
// from the edge journal (never re-observing it) and producing the rest through
// the central Worker's ProduceObservation (one integrity source of truth). A
// need already produced on a prior delivery is loaded; a need that cannot be
// observed right now is deferred as transientErr (do not ack; resume it); a
// structurally-detached/mis-bound need is surfaced as obsErr, never fabricated
// and never a poison loop. The connector is invoked at most once per logical
// Action across all disconnect/replay/resume paths.
func (s *Session) driveObservations(ctx context.Context, action actions.Action) (receipts []runtime.ObservationReceipt, produced int, transientErr error, obsErr error) {
	if len(action.VerificationNeeds) == 0 {
		return nil, 0, nil, nil
	}
	record := func(dst *error, err error) {
		if *dst == nil {
			*dst = err
		}
	}
	seen := make(map[string]bool, len(action.VerificationNeeds))
	for _, need := range action.VerificationNeeds {
		if seen[need.NeedID] {
			continue // dedup to the exact declared set
		}
		if rec, ok, err := s.journal.LoadObservation(ctx, action.TenantRef, action.ActionRef, need.NeedID); err != nil {
			record(&transientErr, err)
			continue
		} else if ok {
			seen[need.NeedID] = true
			receipts = append(receipts, rec)
			continue
		}
		rec, err := worker.ProduceObservation(ctx, s.observations, action.TenantRef, action, need)
		if err != nil {
			if errors.Is(err, worker.ErrObservationRejected) {
				// A structurally-detached/mis-bound need can never be observed:
				// surface it, never fabricate, never loop forever.
				record(&obsErr, err)
			} else {
				// A transient outage (a dropped session/producer): defer this need.
				s.logger.WarnContext(ctx, "agent.observation_deferred",
					slog.String("action_ref", action.ActionRef),
					slog.String("verification_need_id", need.NeedID), slog.String("error", err.Error()))
				record(&transientErr, err)
			}
			continue
		}
		if err := s.journal.RecordObservation(ctx, action.TenantRef, action.ActionRef, need.NeedID, rec); err != nil {
			record(&transientErr, err)
			continue
		}
		seen[need.NeedID] = true
		produced++
		receipts = append(receipts, rec)
	}
	return receipts, produced, transientErr, obsErr
}

// flagResultUnknown transitions the action to result_unknown. A concurrent
// completion that already made the action terminal is an idempotent dedup.
func (s *Session) flagResultUnknown(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (worker.ProcessResult, error) {
	if _, err := s.actions.MarkResultUnknown(ctx, principal, actionRef); err != nil {
		if errors.Is(err, actions.ErrForbiddenTransition) {
			return worker.ProcessResult{Outcome: worker.OutcomeDeduped}, nil
		}
		return worker.ProcessResult{}, err // transient -> nak
	}
	return worker.ProcessResult{Outcome: worker.OutcomeResultUnknown}, nil
}

// reclassify re-reads an action after losing a transition race and returns the
// idempotent outcome: a terminal action is a dedup; anything else is skipped.
func (s *Session) reclassify(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (worker.ProcessResult, error) {
	action, err := s.actions.GetAction(ctx, principal, actionRef)
	if err != nil {
		return worker.ProcessResult{}, err
	}
	switch action.Status {
	case actions.StatusSucceeded, actions.StatusFailed:
		return worker.ProcessResult{Outcome: worker.OutcomeDeduped}, nil
	default:
		return worker.ProcessResult{Outcome: worker.OutcomeSkipped}, nil
	}
}

// Run is the durable pull loop with a bounded local intake queue: it fetches at
// most the queue's available capacity (backpressure), processes each dispatch
// through the resumable pipeline and acks only after the result is durably
// applied. Un-acked work stays owed on the durable consumer, never dropped.
func (s *Session) Run(ctx context.Context, source worker.DispatchSource) error {
	if source == nil {
		return errors.Join(ErrInvalidConfig, errors.New("run requires a dispatch source"))
	}
	q := newIntakeQueue(s.queueBound)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := s.fetchInto(ctx, source, q); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logger.WarnContext(ctx, "agent.fetch_failed", slog.String("error", err.Error()))
		}
		delivery, ok := q.poll()
		if !ok {
			if !sleepCtx(ctx, 20*time.Millisecond) {
				return ctx.Err()
			}
			continue
		}
		s.handleDelivery(ctx, delivery)
	}
}

// fetchInto pulls up to the queue's AVAILABLE capacity (never more) so the local
// intake buffer can never grow unbounded and no durably-owed dispatch is dropped.
// A full queue means the agent STOPS fetching (backpressure) until it drains.
func (s *Session) fetchInto(ctx context.Context, source worker.DispatchSource, q *intakeQueue) (int, error) {
	budget := q.available()
	if budget <= 0 {
		return 0, nil // backpressure: the buffer is full, stop fetching
	}
	n := budget
	if n > fetchBatch {
		n = fetchBatch
	}
	deliveries, err := source.Fetch(ctx, n, fetchWait)
	if err != nil {
		return 0, err
	}
	offered := 0
	for _, d := range deliveries {
		if !q.offer(d) {
			break // never exceed the bound; leftover stays owed on the durable consumer
		}
		offered++
	}
	return offered, nil
}

// handleDelivery processes one delivery and acks/naks it.
func (s *Session) handleDelivery(ctx context.Context, delivery worker.Delivery) {
	res, err := s.ProcessDispatch(ctx, delivery.Message())
	if err != nil {
		s.logger.WarnContext(ctx, "agent.process_transient_error",
			slog.String("action_ref", delivery.Message().ActionRef), slog.String("error", err.Error()))
		_ = delivery.Nak()
		return
	}
	if res.Outcome == worker.OutcomeRejected {
		s.logger.WarnContext(ctx, "agent.dispatch_rejected", slog.String("action_ref", delivery.Message().ActionRef))
	}
	_ = delivery.Ack()
}

// --- bounded intake queue ---------------------------------------------------

// intakeQueue is the agent's bounded local buffer of pulled-but-unprocessed
// dispatches. offer returns false when full (backpressure), so the buffer never
// grows past its bound and durably-owed work is never dropped.
type intakeQueue struct {
	mu    sync.Mutex
	items []worker.Delivery
	bound int
}

func newIntakeQueue(bound int) *intakeQueue {
	if bound <= 0 {
		bound = fetchBatch
	}
	return &intakeQueue{bound: bound}
}

func (q *intakeQueue) available() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bound - len(q.items)
}

func (q *intakeQueue) length() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

func (q *intakeQueue) offer(d worker.Delivery) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.bound {
		return false
	}
	q.items = append(q.items, d)
	return true
}

func (q *intakeQueue) poll() (worker.Delivery, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, false
	}
	d := q.items[0]
	q.items = q.items[1:]
	return d, true
}

// --- in-process inflight set ------------------------------------------------

// inflightSet tracks action refs currently executing in THIS agent process, so a
// concurrent redelivery of an in-flight action defers to the owning goroutine
// instead of misreading its executing status as a crash. Cross-process crash
// recovery is handled durably by the executing-status barrier + the edge
// journal, not by this set.
type inflightSet struct {
	mu  sync.Mutex
	set map[string]struct{}
}

func newInflightSet() *inflightSet { return &inflightSet{set: map[string]struct{}{}} }

func (s *inflightSet) acquire(actionRef string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, busy := s.set[actionRef]; busy {
		return false
	}
	s.set[actionRef] = struct{}{}
	return true
}

func (s *inflightSet) release(actionRef string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.set, actionRef)
}

func (s *inflightSet) owns(actionRef string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.set[actionRef]
	return ok
}

func (s *inflightSet) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.set))
	for ref := range s.set {
		out = append(out, ref)
	}
	return out
}

func (s *inflightSet) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.set)
}

// sleepCtx sleeps for d or until ctx is cancelled; it reports false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
