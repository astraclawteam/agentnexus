package actions

import (
	"context"
	"errors"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// ErrBindingMismatch marks a post-action verification binding that does not
// authoritatively match a stored Action: the action_ref is unknown, the
// parameter hash differs, or the declared postcondition/verification-need pair
// (and its data class) is not a member of the Action's declared bindings.
var ErrBindingMismatch = errors.New("action binding mismatch")

// actionReader is the minimal read port the binding verifier needs; the
// PostgresStore and MemoryStore both satisfy it.
type actionReader interface {
	GetAction(ctx context.Context, tenantRef, actionRef string) (Action, error)
}

// BindingVerifier is the GA Task 0F implementation of the evidence
// ActionBindingVerifier seam (evidence.ActionBindingVerifier). It
// AUTHORITATIVELY checks a verification-purpose read's declared binding against
// the stored Action: the action exists under the tenant, the parameter hash
// equals the Action's, and the postcondition_id / verification_need_id are
// members of the Action's DECLARED Postconditions/VerificationNeeds (with the
// need bound to that postcondition and carrying the same business-semantic data
// class). It never inspects observation content, connector topology or a
// business Outcome — only the server-side binding facts of the Action.
type BindingVerifier struct{ store actionReader }

// NewBindingVerifier builds the verifier over the actions store.
func NewBindingVerifier(store actionReader) *BindingVerifier {
	return &BindingVerifier{store: store}
}

// VerifyActionBinding satisfies evidence.ActionBindingVerifier. A mismatch is
// ErrBindingMismatch (the evidence service maps it to its action_binding_mismatch
// denial); a persistence outage is ErrUnavailable (fail closed).
func (v *BindingVerifier) VerifyActionBinding(ctx context.Context, tenantRef string, binding runtime.VerificationBinding) error {
	if v == nil || v.store == nil {
		return ErrUnavailable
	}
	action, err := v.store.GetAction(ctx, tenantRef, binding.ActionRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errors.Join(ErrBindingMismatch, errors.New("no such action for the verified tenant"))
		}
		return errors.Join(ErrUnavailable, err)
	}
	if action.ParameterHash != binding.ParameterHash {
		return errors.Join(ErrBindingMismatch, errors.New("parameter hash does not match the stored action"))
	}
	if !action.hasPostcondition(binding.PostconditionID) {
		return errors.Join(ErrBindingMismatch, errors.New("postcondition_id is not a declared postcondition of the action"))
	}
	need, ok := action.verificationNeed(binding.VerificationNeedID)
	if !ok {
		return errors.Join(ErrBindingMismatch, errors.New("verification_need_id is not a declared need of the action"))
	}
	if need.PostconditionID != binding.PostconditionID {
		return errors.Join(ErrBindingMismatch, errors.New("verification need does not bind the declared postcondition"))
	}
	if need.DataClass != binding.DataClass {
		return errors.Join(ErrBindingMismatch, errors.New("verification need data class does not match the declared binding"))
	}
	return nil
}
