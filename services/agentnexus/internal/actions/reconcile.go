package actions

import (
	"context"
	"errors"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// BeginReconciliation advances result_unknown -> reconciling. Reconciliation
// queries the connector/inbox for the TRUE outcome of a side effect whose result
// was lost; it never guesses and never blindly re-dispatches.
func (s *Service) BeginReconciliation(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	return s.simpleTransition(ctx, principal, actionRef, StatusResultUnknown, StatusReconciling, auditActionReconciling, "reconciliation started")
}

// ResolveReconciliation advances reconciling -> succeeded|failed once the true
// outcome is determined. A succeeded resolution requires the verified execution
// receipt the reconciliation query recovered (the same completion seam as the
// live path); a failed resolution records the reason.
func (s *Service) ResolveReconciliation(ctx context.Context, principal runtime.PrincipalContext, actionRef string, outcome runtime.ActionStatus, receipt *runtime.ActionReceipt) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	if _, ok := terminalReceiptStatus(outcome); !ok {
		return Action{}, errors.Join(ErrInvalidInput, errors.New("reconciliation resolves only to a technical succeeded/failed outcome"))
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	if action.Status != StatusReconciling {
		return Action{}, ErrForbiddenTransition
	}
	if outcome == StatusSucceeded {
		if receipt == nil {
			return Action{}, errors.Join(ErrReceiptRejected, errors.New("a succeeded reconciliation requires the recovered execution receipt"))
		}
		to, err := s.verifyReceipt(ctx, principal.TenantRef, action, *receipt)
		if err != nil {
			return Action{}, err
		}
		if to != StatusSucceeded {
			return Action{}, errors.Join(ErrReceiptRejected, errors.New("recovered receipt does not attest a succeeded execution"))
		}
		reconcileBinding := bindingOf(action)
		reconcileBinding.ReceiptRef = receipt.ReceiptRef
		if _, err := s.appendAudit(ctx, principal, reconcileBinding, auditActionReconciled, actionRef, StatusReconciling, StatusSucceeded, map[string]any{"receipt_ref": receipt.ReceiptRef}); err != nil {
			return Action{}, err
		}
		result := Result{TenantRef: principal.TenantRef, ResultID: "reconcile:" + actionRef, ActionRef: actionRef, Receipt: *receipt}
		resolved, _, err := s.store.IngestResult(ctx, result, StatusSucceeded, s.now().UTC())
		if err != nil {
			return Action{}, mapTransitionErr(err)
		}
		return resolved, nil
	}
	return s.transition(ctx, principal, bindingOf(action), actionRef, StatusReconciling, StatusFailed, auditActionReconciled, "reconciliation determined a failed technical result")
}
