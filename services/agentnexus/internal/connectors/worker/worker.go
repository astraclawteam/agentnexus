// Package worker is the GA Task 5 central Connector Worker: the durable
// execution plane between the Task 0F Action state machine and the Task 4
// isolated connector host. It performs a durable pull of dispatch intents from
// the Action Outbox (NATS JetStream), and for each one:
//
//   - validates the exact digest/binding + grant against the stored Action
//     (never trusting an Agent-supplied connector id — the private customer
//     binding is resolved SERVER-SIDE from the Action's tenant + semantic
//     capability),
//   - marks the Action executing as the durable "about to run" barrier (so a
//     crash after possible execution becomes result_unknown, never a blind
//     retry),
//   - resolves the private binding and invokes the isolated host (which itself
//     acquires the operation-scoped Secret Handle),
//   - writes the execution result to the durable Inbox atomically (dedup on
//     result id) and produces a signed ActionReceipt, completing the Action via
//     the Action service,
//   - and, for each declared postcondition VerificationNeed, produces a
//     SEPARATELY canonicalized, signed ObservationReceipt through the Task 0D
//     evidence verification-read path — exactly the declared needs, deduplicated.
//
// Authority boundary (frozen, non-negotiable): the worker NEVER accepts an
// arbitrary connector instance id from an Agent message, NEVER lets connector
// topology (instance id, endpoint, table/API path, credentials) reach an
// Agent-facing message or receipt, and NEVER asserts a business Outcome — an
// ActionReceipt proves TECHNICAL execution only and an ObservationReceipt proves
// a bounded authoritative observation only. Exactly one logical Action yields one
// authoritative ActionReceipt and the exact deduplicated ObservationReceipt set;
// duplicate dispatch, NATS redelivery and worker restart are idempotent.
//
// Fail closed: every deferred concrete dependency is nil-guarded and reported
// not-ready — there is no pass-stub and no fake shipped to production, mirroring
// the 0F ReceiptVerifier / 0D ActionBindingVerifier seams. The action plane, the
// receipt signer and the Postgres BindingResolver are composed by
// app.NewPostgresWorkerSeams; the evidence-backed ObservationProducer is the one
// dependency with no implementation anywhere in this build (it lands with the
// Task 7 connector-qualification work), so CheckReady still refuses and no
// deployment can put this worker on the stream.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	"github.com/nats-io/nats.go"
)

// DurableName is the stable JetStream durable-consumer name the connector worker
// binds on actions.SubjectActionDispatch. It reuses 0F's subject/stream; only the
// durable consumer identity is introduced here (0F defined none).
const DurableName = "connector-worker"

// fetchBatch and fetchWait bound one durable pull.
const (
	fetchBatch = 16
	fetchWait  = 2 * time.Second
)

// Worker orchestration errors. Transient failures (persistence/transport
// outages) surface as errors so the durable pull leaves the message for
// redelivery; terminal decisions surface as an Outcome with a nil error.
var (
	// ErrNotReady marks a worker whose fail-closed dependencies are not all
	// wired (a nil BindingResolver / ObservationProducer / ReceiptSigner /
	// ActionPlane, or an unready Secret Provider). It is never a pass-stub.
	ErrNotReady = errors.New("connector worker not ready")
	// ErrInvalidConfig marks a structurally invalid worker configuration.
	ErrInvalidConfig = errors.New("connector worker configuration invalid")
)

// ActionPlane is the subset of the Task 0F *actions.Service the worker drives.
// *actions.Service satisfies it directly. The worker never touches the actions
// Store directly: every transition flows through the audited, state-machine-
// guarded service.
type ActionPlane interface {
	GetAction(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error)
	MarkExecuting(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error)
	IngestReceipt(ctx context.Context, principal runtime.PrincipalContext, resultID string, receipt runtime.ActionReceipt) (actions.Action, error)
	MarkResultUnknown(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error)
}

// SecretReadiness is the production-readiness probe of the Secret Provider
// (internal/secrets.Client satisfies it). A missing or unreachable provider is a
// hard not-ready, never a silent downgrade to plaintext.
type SecretReadiness interface {
	CheckReady(ctx context.Context) error
}

// Identity is the connector-worker system identity under which the worker
// completes technical execution. It is a first-party SERVER-SIDE actor, never an
// Agent identity and never sourced from a dispatch message; it is bound as the
// principal of the completion/result_unknown audit lineage.
type Identity struct {
	PrincipalRef    string
	AgentClientRef  string
	AgentReleaseRef string
	OrgSnapshotRef  string
}

func (i Identity) validate() error {
	if i.PrincipalRef == "" || i.AgentClientRef == "" || i.AgentReleaseRef == "" || i.OrgSnapshotRef == "" {
		return errors.Join(ErrInvalidConfig, errors.New("worker identity requires principal_ref, agent_client_ref, agent_release_ref and org_snapshot_ref"))
	}
	return nil
}

// Config constructs a Worker. Actions, Resolver, Host wiring (via Resolver),
// Signer, Observations and Identity are the fail-closed dependencies; Secrets is
// the readiness probe.
type Config struct {
	Actions      ActionPlane
	Resolver     BindingResolver
	Signer       ReceiptSigner
	Observations ObservationProducer
	Secrets      SecretReadiness
	Identity     Identity
}

// Worker executes durable Actions through the isolated connector host.
type Worker struct {
	actions      ActionPlane
	resolver     BindingResolver
	signer       ReceiptSigner
	observations ObservationProducer
	secrets      SecretReadiness
	identity     Identity
	logger       *slog.Logger
	now          func() time.Time
	newID        func(prefix string) string
	inflight     *inflightSet
}

// Option configures a Worker.
type Option func(*Worker)

// WithClock overrides the worker clock.
func WithClock(clock func() time.Time) Option {
	return func(w *Worker) {
		if clock != nil {
			w.now = clock
		}
	}
}

// WithIDGenerator overrides the opaque identifier generator (receipt refs).
func WithIDGenerator(newID func(prefix string) string) Option {
	return func(w *Worker) {
		if newID != nil {
			w.newID = newID
		}
	}
}

// WithLogger overrides the worker logger. Log lines carry refs, statuses and
// coded reasons only — never connector topology or secret material.
func WithLogger(logger *slog.Logger) Option {
	return func(w *Worker) {
		if logger != nil {
			w.logger = logger
		}
	}
}

// New builds a connector worker. Actions and Identity are mandatory; the
// fail-closed dependencies (Resolver, Signer, Observations) may be nil at
// construction but make CheckReady report not-ready so production never serves
// with a missing seam.
func New(cfg Config, opts ...Option) (*Worker, error) {
	if cfg.Actions == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("worker requires an action plane"))
	}
	if err := cfg.Identity.validate(); err != nil {
		return nil, err
	}
	w := &Worker{
		actions:      cfg.Actions,
		resolver:     cfg.Resolver,
		signer:       cfg.Signer,
		observations: cfg.Observations,
		secrets:      cfg.Secrets,
		identity:     cfg.Identity,
		logger:       slog.Default(),
		now:          func() time.Time { return time.Now().UTC() },
		newID:        randomOpaqueID,
		inflight:     newInflightSet(),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// CheckReady reports whether every fail-closed dependency is wired and the
// Secret Provider is reachable. A nil BindingResolver / ObservationProducer /
// ReceiptSigner is a documented seam pending Task 7 and fails closed here —
// never a pass-stub. main() must not serve dispatches until this returns nil.
func (w *Worker) CheckReady(ctx context.Context) error {
	if w == nil || w.actions == nil {
		return ErrNotReady
	}
	if w.resolver == nil {
		return errors.Join(ErrNotReady, errors.New("no binding resolver wired (the concrete PostgresBindingResolver is in this package; see app.NewPostgresWorkerSeams for the composition)"))
	}
	if w.signer == nil {
		return errors.Join(ErrNotReady, errors.New("no receipt signer wired; an unsigned ActionReceipt can never complete an action"))
	}
	if w.observations == nil {
		return errors.Join(ErrNotReady, errors.New("no observation producer wired (concrete evidence-backed producer lands in Task 7)"))
	}
	if w.secrets != nil {
		if err := w.secrets.CheckReady(ctx); err != nil {
			return errors.Join(ErrNotReady, err)
		}
	}
	return nil
}

// principalFor builds the connector-worker SYSTEM principal for one tenant. The
// tenant comes from the (server-authored) dispatch message; every other field is
// the worker's own first-party identity. It is never derived from Agent input.
func (w *Worker) principalFor(tenantRef string) runtime.PrincipalContext {
	now := w.now().UTC()
	return runtime.PrincipalContext{
		TenantRef:       tenantRef,
		PrincipalRef:    w.identity.PrincipalRef,
		AgentClientRef:  w.identity.AgentClientRef,
		AgentReleaseRef: w.identity.AgentReleaseRef,
		TrustClass:      runtime.TrustFirstParty,
		OrgSnapshotRef:  w.identity.OrgSnapshotRef,
		VerifiedAt:      now.Add(-time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
}

// Delivery is one pulled dispatch intent from the durable transport. The worker
// acks ONLY after the result is durably applied; a transient failure naks so the
// broker redelivers (at-least-once), and the durable inbox dedups the redelivery.
type Delivery interface {
	Message() actions.DispatchMessage
	Ack() error
	Nak() error
}

// DispatchSource is the durable pull transport (a JetStream pull consumer bound
// to actions.SubjectActionDispatch). Fetch blocks up to maxWait for up to n
// intents.
type DispatchSource interface {
	Fetch(ctx context.Context, n int, maxWait time.Duration) ([]Delivery, error)
}

// Run is the durable pull loop: it fetches dispatch intents, processes each
// through the exactly-once orchestration and acks only after the result is
// durably applied. It returns when ctx is cancelled. A transient processing
// failure naks the delivery so JetStream redelivers it (and the durable inbox
// dedups any at-least-once duplicate).
func (w *Worker) Run(ctx context.Context, source DispatchSource) error {
	if source == nil {
		return errors.Join(ErrInvalidConfig, errors.New("run requires a dispatch source"))
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		deliveries, err := source.Fetch(ctx, fetchBatch, fetchWait)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			w.logger.WarnContext(ctx, "worker.fetch_failed", slog.String("error", err.Error()))
			if !sleepCtx(ctx, 20*time.Millisecond) {
				return ctx.Err()
			}
			continue
		}
		if len(deliveries) == 0 {
			if !sleepCtx(ctx, 20*time.Millisecond) {
				return ctx.Err()
			}
			continue
		}
		for _, delivery := range deliveries {
			w.handleDelivery(ctx, delivery)
		}
	}
}

// handleDelivery processes one delivery and acks/naks it. A transient error naks
// (redeliver); every terminal decision (completed, deduped, result_unknown,
// rejected, skipped) acks — a rejected poison intent is logged and acked, never
// redelivered forever.
func (w *Worker) handleDelivery(ctx context.Context, delivery Delivery) {
	msg := delivery.Message()
	res, err := w.ProcessDispatch(ctx, msg)
	if err != nil {
		w.logger.WarnContext(ctx, "worker.process_transient_error",
			slog.String("action_ref", msg.ActionRef), slog.String("error", err.Error()))
		_ = delivery.Nak()
		return
	}
	if res.Outcome == OutcomeRejected {
		w.logger.WarnContext(ctx, "worker.dispatch_rejected", slog.String("action_ref", msg.ActionRef))
	}
	_ = delivery.Ack()
}

// ProcessDispatch is the exactly-once orchestration of ONE dispatch intent. It
// is the unit-tested core of the worker. A returned error is TRANSIENT (the
// caller should nak for redelivery); a nil error with an Outcome is a terminal
// decision (ack). It never executes twice, never fabricates a receipt and never
// asserts a business Outcome.
func (w *Worker) ProcessDispatch(ctx context.Context, msg actions.DispatchMessage) (ProcessResult, error) {
	principal := w.principalFor(msg.TenantRef)
	action, err := w.actions.GetAction(ctx, principal, msg.ActionRef)
	if err != nil {
		if errors.Is(err, actions.ErrNotFound) {
			// No such action for this tenant: a forged or stale dispatch. Reject —
			// never execute; acking a poison intent is safe.
			w.logger.WarnContext(ctx, "worker.dispatch_unknown_action", slog.String("action_ref", msg.ActionRef))
			return ProcessResult{Outcome: OutcomeRejected}, nil
		}
		return ProcessResult{}, err // transient -> nak
	}
	// Exact digest/binding + grant validation. A mismatch is a poison intent that
	// must never execute.
	if err := ValidateBinding(msg, action); err != nil {
		w.logger.WarnContext(ctx, "worker.dispatch_binding_rejected",
			slog.String("action_ref", msg.ActionRef), slog.String("error", err.Error()))
		return ProcessResult{Outcome: OutcomeRejected}, nil
	}

	// An action whose true outcome is being reconciled out of band must never be
	// blindly re-executed by a redelivered dispatch.
	if actions.AwaitingReconciliation(action.Status) {
		return ProcessResult{Outcome: OutcomeSkipped}, nil
	}

	switch action.Status {
	case actions.StatusSucceeded, actions.StatusFailed:
		// Already terminal: an at-least-once redelivery / worker restart is an
		// idempotent no-op — no second side effect, no second receipt.
		return ProcessResult{Outcome: OutcomeDeduped}, nil
	case actions.StatusExecuting:
		if w.inflight.owns(msg.ActionRef) {
			// A concurrent sibling in THIS process owns the execution; defer to it.
			return ProcessResult{Outcome: OutcomeSkipped}, nil
		}
		// The action was left executing by a prior worker/run: the side effect may
		// already have happened, so it is result_unknown — never a blind re-run.
		return w.flagResultUnknown(ctx, principal, msg.ActionRef)
	case actions.StatusDispatched:
		// Proceed to execution below.
	default:
		// granted / awaiting_approval / requested / compensating / human_takeover:
		// not an executable dispatch state.
		return ProcessResult{Outcome: OutcomeSkipped}, nil
	}

	// Take in-process ownership BEFORE the durable executing barrier so a
	// concurrent sibling defers instead of racing MarkExecuting.
	if !w.inflight.acquire(msg.ActionRef) {
		return ProcessResult{Outcome: OutcomeSkipped}, nil
	}
	defer w.inflight.release(msg.ActionRef)
	return w.executeAndComplete(ctx, principal, action, msg)
}

// flagResultUnknown transitions the action to result_unknown (a crash after
// possible execution, an uncertain host outcome, or an unattestable completion).
// A concurrent completion that already made the action terminal is an idempotent
// dedup, not an unknown.
func (w *Worker) flagResultUnknown(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (ProcessResult, error) {
	if _, err := w.actions.MarkResultUnknown(ctx, principal, actionRef); err != nil {
		if errors.Is(err, actions.ErrForbiddenTransition) {
			return ProcessResult{Outcome: OutcomeDeduped}, nil
		}
		return ProcessResult{}, err // transient -> nak
	}
	return ProcessResult{Outcome: OutcomeResultUnknown}, nil
}

// reclassify re-reads an action after losing a transition race and returns the
// idempotent outcome: a terminal action is a dedup; an action another executor
// owns/advanced is skipped (never re-run).
func (w *Worker) reclassify(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (ProcessResult, error) {
	action, err := w.actions.GetAction(ctx, principal, actionRef)
	if err != nil {
		return ProcessResult{}, err
	}
	switch action.Status {
	case actions.StatusSucceeded, actions.StatusFailed:
		return ProcessResult{Outcome: OutcomeDeduped}, nil
	default:
		return ProcessResult{Outcome: OutcomeSkipped}, nil
	}
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

// NATSDispatchSource is the production DispatchSource: a JetStream pull consumer
// bound to actions.SubjectActionDispatch. Each Delivery acks/naks the underlying
// JetStream message, so the worker acks only after a result is durably applied.
type NATSDispatchSource struct {
	sub    *nats.Subscription
	logger *slog.Logger
}

// NewNATSDispatchSource binds the durable pull consumer on the dispatch subject.
func NewNATSDispatchSource(js nats.JetStreamContext, streamName string, logger *slog.Logger) (*NATSDispatchSource, error) {
	if js == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("nats dispatch source requires a JetStream context"))
	}
	if logger == nil {
		logger = slog.Default()
	}
	sub, err := js.PullSubscribe(actions.SubjectActionDispatch, DurableName, nats.BindStream(streamName))
	if err != nil {
		return nil, err
	}
	return &NATSDispatchSource{sub: sub, logger: logger}, nil
}

// Fetch pulls up to n durable dispatch intents. A malformed payload is terminated
// (never redelivered as poison) and skipped; a fetch timeout returns no intents.
func (s *NATSDispatchSource) Fetch(ctx context.Context, n int, maxWait time.Duration) ([]Delivery, error) {
	msgs, err := s.sub.Fetch(n, nats.MaxWait(maxWait), nats.Context(ctx))
	if err != nil {
		if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]Delivery, 0, len(msgs))
	for _, msg := range msgs {
		decoded, decErr := actions.DecodeDispatchMessage(msg.Data)
		if decErr != nil {
			s.logger.WarnContext(ctx, "worker.dispatch_decode_failed", slog.String("error", decErr.Error()))
			_ = msg.Term()
			continue
		}
		out = append(out, &natsDelivery{msg: msg, decoded: decoded})
	}
	return out, nil
}

type natsDelivery struct {
	msg     *nats.Msg
	decoded actions.DispatchMessage
}

func (d *natsDelivery) Message() actions.DispatchMessage { return d.decoded }
func (d *natsDelivery) Ack() error                       { return d.msg.Ack() }
func (d *natsDelivery) Nak() error                       { return d.msg.Nak() }

// BuildHostOperation assembles the isolated-host operation from the resolved
// PRIVATE binding and the stored Action. The parameter payload is not persisted
// by 0F (only its hash is), so Input is empty; the connector reads what it needs
// from the resolved resource under the operation-scoped Secret Handle the host
// acquires. No Agent-supplied value reaches this operation.
//
// It is EXPORTED as the single operation-assembly source of truth: the outbound
// Connector Agent (Task 6) builds its host.Operation through this exact function
// so the edge and the center dispatch the identical operation to the shared
// isolated host, never a forked assembly.
func BuildHostOperation(action actions.Action, msg actions.DispatchMessage, rb ResolvedBinding) host.Operation {
	return host.Operation{
		RequestID:     msg.DispatchRef,
		Capability:    action.Capability,
		Resource:      rb.Resource,
		Operation:     rb.Operation,
		Action:        rb.OperationAction,
		CredentialRef: rb.CredentialRef,
	}
}
