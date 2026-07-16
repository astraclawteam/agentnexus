package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
)

// ErrBindingRejected marks a dispatch intent whose exact binding does not match
// the stored Action (capability, parameter hash or grant), or an Action that
// cannot legitimately be executed. The worker fails closed: it NEVER executes a
// rejected dispatch and never fabricates a receipt.
var ErrBindingRejected = errors.New("dispatch binding rejected")

// HostRunner runs one connector operation in the Task 4 isolated host and always
// returns a bounded Result (it never returns an error and never propagates a
// panic). *host.Supervisor satisfies it directly.
type HostRunner interface {
	Run(ctx context.Context, op host.Operation) host.Result
}

// ResolvedBinding is the PRIVATE, server-side resolution of an Action's tenant +
// semantic capability onto a runnable connector operation. Every field is
// server-side truth derived from the CustomerBinding and the pinned ProductPack;
// NONE of it (the connector ref, resource, operation, credential ref) ever
// reaches an Agent-facing message or receipt.
type ResolvedBinding struct {
	// Host is the isolated host bound to the resolved connector instance.
	Host HostRunner
	// Resource, Operation and OperationAction are the connector-internal
	// operation coordinates the pack/binding map the capability onto.
	Resource        string
	Operation       string
	OperationAction string
	// CredentialRef is the opaque secret reference the host redeems for an
	// operation-scoped Secret Handle; it is never a secret value.
	CredentialRef string
	// ConnectorRef is the private connector instance identity, kept for internal
	// audit/logging ONLY — it must never appear in an Agent-facing surface.
	ConnectorRef string
}

// BindingResolver privately resolves an Action's tenant + semantic capability
// onto the customer's server-side connector binding. It NEVER accepts a connector
// id from the caller; an unknown, ambiguous or unavailable binding fails closed.
// The concrete resolver over connector_products/connector_bindings lands in the
// Task 7 connector-qualification work; until then this port is nil (CheckReady
// fails closed) and unit/integration tests supply a fixed test resolver.
type BindingResolver interface {
	Resolve(ctx context.Context, tenantRef, capability string) (ResolvedBinding, error)
}

// ValidateBinding enforces the exact digest/binding + grant checks of a dispatch
// intent against the stored Action. A mismatch is ErrBindingRejected — the
// worker never executes it. It binds capability, parameter hash and the one-use
// grant; the connector topology is deliberately absent from the message and is
// resolved privately, so there is nothing agent-supplied to trust here.
//
// It is EXPORTED as the single binding-validation source of truth: the outbound
// Connector Agent (Task 6) enforces the SAME exact-binding + one-use-grant rules
// on every intake so a dispatch that does not bind the stored Action is rejected
// and never executed, identically at the edge and at the center.
func ValidateBinding(msg actions.DispatchMessage, action actions.Action) error {
	switch {
	case msg.ActionRef != action.ActionRef:
		return errors.Join(ErrBindingRejected, errors.New("dispatch action_ref does not match the stored action"))
	case msg.Capability != action.Capability:
		return errors.Join(ErrBindingRejected, errors.New("dispatch capability does not bind the stored action"))
	case msg.ParameterHash != action.ParameterHash:
		return errors.Join(ErrBindingRejected, errors.New("dispatch parameter hash does not bind the stored action"))
	case action.GrantRef == "" || msg.GrantRef != action.GrantRef:
		return errors.Join(ErrBindingRejected, errors.New("dispatch grant does not bind the stored action's one-use grant"))
	}
	return nil
}

// executeAndComplete owns a dispatched Action end to end: it resolves the private
// binding, crosses the durable executing barrier, invokes the isolated host and
// completes the Action with a signed ActionReceipt (plus the declared
// ObservationReceipt set on success). Every uncertain or unattestable outcome
// fails closed to result_unknown — never a fabricated receipt, never a re-run.
func (w *Worker) executeAndComplete(ctx context.Context, principal runtime.PrincipalContext, action actions.Action, msg actions.DispatchMessage) (ProcessResult, error) {
	// Resolve the PRIVATE binding BEFORE the durable executing barrier, so a
	// resolver outage leaves the Action dispatched (retryable) with no barrier and
	// no side effect.
	rb, err := w.resolver.Resolve(ctx, action.TenantRef, action.Capability)
	if err != nil {
		return ProcessResult{}, errors.Join(errors.New("binding resolution failed"), err) // transient -> nak
	}
	if rb.Host == nil {
		return ProcessResult{}, errors.Join(ErrNotReady, errors.New("resolved binding has no host runner"))
	}

	// Durable barrier: dispatched -> executing. After this the side effect may run,
	// so a crash before completion becomes result_unknown, never a blind retry.
	if _, err := w.actions.MarkExecuting(ctx, principal, action.ActionRef); err != nil {
		if errors.Is(err, actions.ErrForbiddenTransition) {
			return w.reclassify(ctx, principal, action.ActionRef) // lost the barrier race
		}
		return ProcessResult{}, err // transient -> nak
	}

	result := rb.Host.Run(ctx, BuildHostOperation(action, msg, rb))
	status, uncertain := ClassifyHostResult(result.Status)
	if uncertain {
		// A pending external receipt or an unspecified outcome: the side effect's
		// success cannot be authoritatively determined, so it is result_unknown.
		w.logger.WarnContext(ctx, "worker.host_outcome_uncertain",
			slog.String("action_ref", action.ActionRef), slog.String("host_status", result.Status.String()))
		return w.flagResultUnknown(ctx, principal, action.ActionRef)
	}

	receipt, err := w.buildSignedReceipt(ctx, action, status, result)
	if err != nil {
		// Executed, but no verifiable receipt can be produced (a signing/integrity
		// outage): fail closed to result_unknown — never fabricate, never re-run.
		w.logger.ErrorContext(ctx, "worker.receipt_production_failed",
			slog.String("action_ref", action.ActionRef), slog.String("error", err.Error()))
		return w.flagResultUnknown(ctx, principal, action.ActionRef)
	}

	// The dispatch ref is the stable inbox dedup key: an at-least-once redelivery
	// of the SAME dispatch carries the SAME ref, so the durable inbox applies the
	// result exactly once.
	completed, err := w.actions.IngestReceipt(ctx, principal, msg.DispatchRef, receipt)
	if err != nil {
		if errors.Is(err, actions.ErrForbiddenTransition) {
			return w.reclassify(ctx, principal, action.ActionRef) // a concurrent completion won
		}
		// Executed and signed, but the durable apply failed: result_unknown.
		w.logger.ErrorContext(ctx, "worker.receipt_ingest_failed",
			slog.String("action_ref", action.ActionRef), slog.String("error", err.Error()))
		return w.flagResultUnknown(ctx, principal, action.ActionRef)
	}

	res := ProcessResult{Outcome: OutcomeCompleted, ActionReceipt: &receipt}
	// Post-action verification runs ONLY after a succeeded technical execution (a
	// failed execution has no post-state to observe); the ObservationReceipt set is
	// exactly the deduplicated declared VerificationNeeds.
	if completed.Status == actions.StatusSucceeded {
		res.ObservationReceipts, res.ObservationErr = w.produceObservations(ctx, principal.TenantRef, action)
	}
	return res, nil
}

// inflightSet tracks action refs currently executing in THIS worker process, so
// a concurrent redelivery of an in-flight action defers to the owning goroutine
// instead of misreading its executing status as a crash. Cross-process crash
// recovery is handled durably by the executing-status barrier, not by this set.
type inflightSet struct {
	mu  sync.Mutex
	set map[string]struct{}
}

func newInflightSet() *inflightSet { return &inflightSet{set: map[string]struct{}{}} }

// acquire records ownership of actionRef and reports whether THIS caller won it
// (false ⇒ a sibling goroutine already owns it).
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
