package worker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
)

// Receipt/observation production errors (fail-closed, never fabricated).
var (
	// ErrReceiptProduction marks a failure to build or sign a verifiable
	// ActionReceipt after execution; the worker fails closed to result_unknown
	// rather than complete with an unverifiable or fabricated receipt.
	ErrReceiptProduction = errors.New("action receipt production failed")
	// ErrObservationRejected marks a declared postcondition probe that could not
	// produce a bound, valid ObservationReceipt (a detached need or a producer
	// that returned a receipt not binding the declared need). It is surfaced,
	// never fabricated.
	ErrObservationRejected = errors.New("observation receipt rejected")
)

// Outcome is the terminal classification of processing one dispatch intent.
type Outcome string

const (
	// OutcomeCompleted marks a genuine completion: a verified signed ActionReceipt
	// was ingested (to the succeeded or failed technical terminal status).
	OutcomeCompleted Outcome = "completed"
	// OutcomeResultUnknown marks an uncertain outcome flagged result_unknown (a
	// crash after possible execution, a waiting-external-receipt host outcome, or
	// a post-execution integrity failure). Blind retry is forbidden; the only path
	// forward is reconciliation.
	OutcomeResultUnknown Outcome = "result_unknown"
	// OutcomeDeduped marks a redelivery of an already-terminal Action: an
	// idempotent no-op, no second side effect and no second receipt.
	OutcomeDeduped Outcome = "deduped"
	// OutcomeRejected marks a dispatch intent whose binding/grant did not match
	// the stored Action: never executed, never a receipt.
	OutcomeRejected Outcome = "rejected"
	// OutcomeSkipped marks a dispatch not actionable by this delivery (a concurrent
	// sibling in this process owns the execution, or the Action is already being
	// reconciled).
	OutcomeSkipped Outcome = "skipped"
)

// ProcessResult reports what processing one dispatch intent produced. Exactly one
// authoritative ActionReceipt (on a genuine completion) and the exact deduplicated
// ObservationReceipt set declared by the Action's VerificationNeeds (on a
// succeeded completion). ObservationErr surfaces a non-fabricating verification
// failure without un-completing the technically-authoritative Action.
type ProcessResult struct {
	Outcome             Outcome
	ActionReceipt       *runtime.ActionReceipt
	ObservationReceipts []runtime.ObservationReceipt
	ObservationErr      error
}

// ReceiptSigner signs the canonical ActionReceipt pre-image
// (actions.CanonicalActionReceipt) with the connector-host signing key. The
// worker is the technical-execution authority for the ActionReceipt; the signer's
// public half is registered in the actions ReceiptVerifier's key resolver so the
// produced receipt verifies. *audit.Ed25519AuditSigner satisfies it. A nil signer
// fails closed at CheckReady — an unsigned receipt can never complete an Action.
type ReceiptSigner interface {
	Sign(ctx context.Context, canonical []byte) (runtime.Signature, error)
}

// ObservationProducer performs ONE declared postcondition probe as a Task 0D
// evidence verification-purpose read and returns the SEPARATELY canonicalized,
// signed ObservationReceipt. The worker owns only the orchestration invariants
// (invoke exactly the declared VerificationNeeds, one receipt per need, dedup to
// the exact declared set, fail closed on error — never fabricate); the evidence
// plane performs the authoritative bounded read AND signs the ObservationReceipt.
// The concrete evidence-backed producer lands in Task 7; until then the port is
// nil (CheckReady fails closed) and tests supply a fake.
type ObservationProducer interface {
	Observe(ctx context.Context, tenantRef string, binding runtime.VerificationBinding) (runtime.ObservationReceipt, error)
}

// ClassifyHostResult maps a bounded host Result status onto the technical
// terminal action status. uncertain=true marks an outcome whose side-effect
// success cannot be authoritatively determined — those become result_unknown,
// NEVER a fabricated terminal receipt, leaving reconciliation as the only path
// forward (result_unknown -> reconciling is a legal state-machine edge; failed ->
// reconciling is NOT, so a mis-classified timeout would foreclose recovery).
//
// It is EXPORTED as the single provenance source of truth: the edge Connector
// Agent (Task 6) classifies host outcomes through this exact function so the
// outbound durable-execution plane can never fork the C1 provenance rules.
//
// The distinction is PROVENANCE, decided by the host: failed / denied /
// denied_policy are DEFINITE technical failures with no committed side effect — a
// connector-REPORTED failure verdict, a clean connector denial, or a host policy
// denial evaluated BEFORE the connector ran — so a signed failed receipt is
// honest. The host narrowed StatusFailed to exactly those (C1): a post-dispatch
// abnormal outcome no longer masquerades as failed.
//
// resource_exhausted, execution_uncertain and waiting_external_receipt are all
// UNCERTAIN: a wall-clock/memory cutoff with the adapter left running, a
// post-dispatch panic/transport/cancellation/malformed-response with no verdict,
// or a write pending an external receipt — in each the external side effect MAY
// have committed. Asserting a definite verdict there could be false AND would
// foreclose reconciliation (failed -> reconciling is not a legal edge), so they
// fail closed to result_unknown — never a fabricated verdict, never a blind retry.
func ClassifyHostResult(status host.Status) (runtime.ActionStatus, bool) {
	switch status {
	case host.StatusSucceeded:
		return runtime.StatusSucceeded, false
	case host.StatusFailed, host.StatusDenied, host.StatusDeniedPolicy:
		return runtime.StatusFailed, false
	default: // StatusExecutionUncertain, StatusResourceExhausted, StatusWaitingExternalReceipt, StatusUnspecified
		return "", true
	}
}

// buildSignedReceipt builds and signs the authoritative ActionReceipt for one
// technically-completed execution. It delegates to the exported
// BuildSignedActionReceipt so the central Worker and the edge Connector Agent
// (Task 6) share ONE receipt-production path.
func (w *Worker) buildSignedReceipt(ctx context.Context, action actions.Action, status runtime.ActionStatus, result host.Result) (runtime.ActionReceipt, error) {
	return BuildSignedActionReceipt(ctx, w.signer, w.newID, w.now, action, status, result)
}

// BuildSignedActionReceipt builds and signs the authoritative ActionReceipt for
// one technically-completed execution. The connector output is HASH-BOUND, never
// embedded, so the Agent-facing receipt attests the exact result bytes without
// carrying the payload (or its shape, or any connector topology). It binds the
// exact action operation (action_ref + capability + parameter_hash) and the
// declared receipt schema, so the actions ReceiptVerifier accepts it.
//
// It is EXPORTED as the single receipt-production source of truth: the outbound
// Connector Agent (Task 6) mints its edge-journaled ActionReceipt through this
// exact function (with a real ed25519 signer registered in the central
// ReceiptVerifier) so a receipt produced at the customer edge verifies centrally
// and never diverges from the central Worker's receipt shape.
func BuildSignedActionReceipt(ctx context.Context, signer ReceiptSigner, newID func(prefix string) string, now func() time.Time, action actions.Action, status runtime.ActionStatus, result host.Result) (runtime.ActionReceipt, error) {
	receipt := runtime.ActionReceipt{
		ReceiptRef:    newID("rcp_"),
		ActionRef:     action.ActionRef,
		Status:        status,
		Capability:    action.Capability,
		ParameterHash: action.ParameterHash,
		ReceiptSchema: action.ExpectedReceiptSchema,
		IssuedAt:      now().UTC(),
	}
	if len(result.Output) > 0 {
		sum := sha256.Sum256(result.Output)
		receipt.ResultHash = "sha256:" + hex.EncodeToString(sum[:])
	}
	if err := receipt.Validate(); err != nil {
		return runtime.ActionReceipt{}, errors.Join(ErrReceiptProduction, err)
	}
	canonical, err := actions.CanonicalActionReceipt(receipt)
	if err != nil {
		return runtime.ActionReceipt{}, errors.Join(ErrReceiptProduction, err)
	}
	signature, err := signer.Sign(ctx, canonical)
	if err != nil {
		return runtime.ActionReceipt{}, errors.Join(ErrReceiptProduction, err)
	}
	if err := signature.Validate(); err != nil {
		return runtime.ActionReceipt{}, errors.Join(ErrReceiptProduction, err)
	}
	receipt.Signature = &signature
	return receipt, nil
}

// produceObservations invokes ONLY the declared postcondition probes and returns
// the exact deduplicated ObservationReceipt set for the Action's declared
// VerificationNeeds. Each need is verified through the Task 0D evidence
// verification-read (which performs the authoritative bounded read and signs the
// ObservationReceipt); the worker never signs an observation and never fabricates
// one. A need that cannot be authoritatively observed is surfaced as an error and
// left out of the set — the technically-authoritative ActionReceipt is
// independent and stays complete.
func (w *Worker) produceObservations(ctx context.Context, tenantRef string, action actions.Action) ([]runtime.ObservationReceipt, error) {
	if len(action.VerificationNeeds) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(action.VerificationNeeds))
	var receipts []runtime.ObservationReceipt
	var firstErr error
	record := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, need := range action.VerificationNeeds {
		if seen[need.NeedID] {
			continue // dedup to the exact declared set
		}
		receipt, err := ProduceObservation(ctx, w.observations, tenantRef, action, need)
		if err != nil {
			// Fail closed: never fabricate a receipt for a need that could not be
			// authoritatively observed (a deny, a detached/rebinding mismatch, or a
			// receipt that does not bind the declared need).
			w.logger.WarnContext(ctx, "worker.observation_failed",
				slog.String("action_ref", action.ActionRef),
				slog.String("verification_need_id", need.NeedID),
				slog.String("error", err.Error()))
			record(err)
			continue
		}
		seen[need.NeedID] = true
		receipts = append(receipts, receipt)
	}
	return receipts, firstErr
}

// ProduceObservation performs ONE declared postcondition probe and returns the
// bound, valid ObservationReceipt for it. It enforces the same integrity rules
// the central Worker owns: only a need bound to a DECLARED postcondition may be
// verified (a detached need is rejected before Observe, never produced), the
// producer's returned receipt MUST bind exactly this action + need, and the
// receipt must validate. A failure is surfaced, NEVER fabricated.
//
// It is EXPORTED as the single observation-integrity source of truth: the
// outbound Connector Agent (Task 6) drives each declared VerificationNeed
// through this exact function so an edge-produced ObservationReceipt set is
// bound and deduplicated by the identical rules and never forks the guards.
func ProduceObservation(ctx context.Context, producer ObservationProducer, tenantRef string, action actions.Action, need runtime.VerificationNeed) (runtime.ObservationReceipt, error) {
	// Defense in depth: only a need bound to a DECLARED postcondition may be
	// verified; a detached need is never produced (the producer is not invoked).
	if !postconditionDeclared(action, need.PostconditionID) {
		return runtime.ObservationReceipt{}, errors.Join(ErrObservationRejected, errors.New("verification need does not bind a declared postcondition"))
	}
	binding := runtime.VerificationBinding{
		ActionRef:          action.ActionRef,
		ParameterHash:      action.ParameterHash,
		PostconditionID:    need.PostconditionID,
		VerificationNeedID: need.NeedID,
		DataClass:          need.DataClass,
	}
	receipt, err := producer.Observe(ctx, tenantRef, binding)
	if err != nil {
		return runtime.ObservationReceipt{}, err
	}
	// Integrity: the produced receipt must bind exactly this need and action.
	if receipt.ActionRef != action.ActionRef || receipt.ParameterHash != action.ParameterHash ||
		receipt.PostconditionID != need.PostconditionID || receipt.VerificationNeedID != need.NeedID {
		return runtime.ObservationReceipt{}, errors.Join(ErrObservationRejected, errors.New("observation receipt does not bind the declared need"))
	}
	if err := receipt.Validate(); err != nil {
		return runtime.ObservationReceipt{}, errors.Join(ErrObservationRejected, err)
	}
	return receipt, nil
}

// postconditionDeclared reports whether id is a declared postcondition of the
// Action (the worker only ever verifies declared postcondition/need pairs).
func postconditionDeclared(action actions.Action, id string) bool {
	for _, p := range action.Postconditions {
		if p.PostconditionID == id {
			return true
		}
	}
	return false
}

// randomOpaqueID mints an opaque handle with the given prefix (receipt refs).
func randomOpaqueID(prefix string) string {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}
