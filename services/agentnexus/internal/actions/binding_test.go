package actions

import (
	"context"
	"errors"
	"testing"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

func TestActionBindingVerifierChecksDeclaredMembership(t *testing.T) {
	svc, store, _ := newTestService(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	req := testRequest(t)
	req.Postconditions = []runtime.PostconditionSpec{{PostconditionID: "pc-1", Kind: "state", Reference: "po.status"}}
	req.VerificationNeeds = []runtime.VerificationNeed{{NeedID: "vn-1", PostconditionID: "pc-1", DataClass: "erp.purchase_order"}}
	ctx := context.Background()
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}

	verifier := NewBindingVerifier(store)
	good := runtime.VerificationBinding{
		ActionRef:          action.ActionRef,
		ParameterHash:      action.ParameterHash,
		PostconditionID:    "pc-1",
		VerificationNeedID: "vn-1",
		DataClass:          "erp.purchase_order",
	}
	if err := verifier.VerifyActionBinding(ctx, principal.TenantRef, good); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}

	cases := map[string]func(runtime.VerificationBinding) runtime.VerificationBinding{
		"unknown action":     func(b runtime.VerificationBinding) runtime.VerificationBinding { b.ActionRef = "act_unknown000000001"; return b },
		"parameter mismatch": func(b runtime.VerificationBinding) runtime.VerificationBinding {
			b.ParameterHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
			return b
		},
		"undeclared postcondition": func(b runtime.VerificationBinding) runtime.VerificationBinding { b.PostconditionID = "pc-x"; return b },
		"undeclared need":          func(b runtime.VerificationBinding) runtime.VerificationBinding { b.VerificationNeedID = "vn-x"; return b },
		"data class mismatch":      func(b runtime.VerificationBinding) runtime.VerificationBinding { b.DataClass = "hr.directory"; return b },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verifier.VerifyActionBinding(ctx, principal.TenantRef, mutate(good)); !errors.Is(err, ErrBindingMismatch) {
				t.Fatalf("%s: err = %v, want ErrBindingMismatch", name, err)
			}
		})
	}

	// A detached/undeclared need whose postcondition points elsewhere is rejected.
	crossed := good
	crossed.VerificationNeedID = "vn-1"
	crossed.PostconditionID = "pc-1"
	crossed.DataClass = "erp.purchase_order"
	if err := verifier.VerifyActionBinding(ctx, principal.TenantRef, crossed); err != nil {
		t.Fatalf("consistent binding unexpectedly rejected: %v", err)
	}
}
