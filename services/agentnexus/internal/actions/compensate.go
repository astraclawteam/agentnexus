package actions

import (
	"context"
	"errors"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// Compensate initiates the SEPARATELY AUTHORIZED compensation of an action whose
// side effect may have executed. Compensation is not a magic rollback: it mints
// a NEW governed Action for the declared compensation capability, which flows
// through its own grant, dispatch and execution/observation receipts. The
// original action moves to compensating.
//
// Idempotent: re-triggering returns the same compensation Action (keyed by the
// original action_ref). An action that declared no compensation reference cannot
// be compensated.
func (s *Service) Compensate(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	original, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	if original.CompensationRef == "" {
		return Action{}, ErrCompensationUndeclared
	}
	if !compensable(original.Status) && original.Status != StatusCompensating {
		return Action{}, ErrForbiddenTransition
	}

	compIdem := "cmp:" + original.ActionRef
	if existing, err := s.store.GetByIdempotencyKey(ctx, principal.TenantRef, compIdem); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Action{}, errors.Join(ErrUnavailable, err)
	}

	now := s.now().UTC()
	compRef := s.newID("act_")
	if runtime.ValidateHandle(compRef, runtime.HandleAction) != nil {
		return Action{}, ErrUnavailable
	}
	auditRef, err := s.appendAudit(ctx, principal, auditBinding{Capability: original.CompensationRef, RiskAuthority: original.RiskAuthority}, auditActionRequested, compRef, "", StatusRequested, map[string]any{"capability": original.CompensationRef, "compensation_of": original.ActionRef})
	if err != nil {
		return Action{}, err
	}
	compensation := Action{
		TenantRef:             principal.TenantRef,
		ActionRef:             compRef,
		Status:                StatusRequested,
		BusinessContextRef:    original.BusinessContextRef,
		Capability:            original.CompensationRef,
		ParameterHash:         original.ParameterHash,
		IdempotencyKey:        compIdem,
		RiskAuthority:         original.RiskAuthority,
		RiskLevel:             original.RiskLevel,
		CompensationOf:        original.ActionRef,
		ExpectedReceiptSchema: original.ExpectedReceiptSchema,
		ExpiresAt:             original.ExpiresAt,
		AuditRefID:            auditRef,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	stored, created, err := s.store.PutRequested(ctx, compensation)
	if err != nil {
		return Action{}, mapTransitionErr(err)
	}
	if created && original.Status != StatusCompensating {
		if _, err := s.appendAudit(ctx, principal, bindingOf(original), auditActionCompensating, original.ActionRef, original.Status, StatusCompensating, map[string]any{"compensation_ref": compRef}); err != nil {
			return Action{}, err
		}
		if _, err := s.store.Transition(ctx, principal.TenantRef, original.ActionRef, original.Status, StatusCompensating, "compensation initiated", now); err != nil {
			return Action{}, mapTransitionErr(err)
		}
	}
	return stored, nil
}
