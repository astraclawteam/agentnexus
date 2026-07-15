package actions

import (
	"context"
	"errors"
	"testing"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// fakeDecisionProvider is a wired certified-decision-provider verifier for the
// trust tests: it records the calls and returns a configured error.
type fakeDecisionProvider struct {
	err   error
	calls int
}

func (f *fakeDecisionProvider) VerifyDecisionProvider(_ context.Context, _ string, _ runtime.PrincipalContext, _, _ string) error {
	f.calls++
	return f.err
}

// A valid registered FIRST-PARTY RiskDecision passes WITHOUT AgentNexus
// rewriting the domain risk or the approval path: the decision-provider verifier
// is never consulted for a first party, and the stored operation binding is the
// caller's unchanged capability + parameter hash.
func TestRiskDecisionTrustFirstPartyPassesWithoutRewrite(t *testing.T) {
	provider := &fakeDecisionProvider{err: errors.New("must not be called for a first party")}
	svc, _, _ := newTestService(t, WithDecisionProviderVerifier(provider))
	principal := testPrincipal(runtime.TrustFirstParty)
	req := testRequest(t)
	ctx := context.Background()

	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	granted, err := svc.Grant(ctx, principal, action.ActionRef)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("decision provider consulted %d times for a first party; risk authority must not be re-derived", provider.calls)
	}
	if granted.Capability != req.Capability || granted.ParameterHash != req.ParameterHash {
		t.Fatalf("granted operation rewritten: %+v", granted)
	}
}

// A CERTIFIED THIRD-PARTY decision reaches a side effect ONLY combined with the
// wired certified-decision-provider verification (the technical-safety floor);
// the nil seam fails closed and never becomes a silent pass.
func TestRiskDecisionTrustCertifiedThirdPartyRequiresDecisionProvider(t *testing.T) {
	principal := testPrincipal(runtime.TrustCertifiedThirdParty)
	ctx := context.Background()

	// nil seam: a certified third party cannot reach a grant.
	nilSvc, _, _ := newTestService(t)
	action, err := nilSvc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction (nil seam): %v", err)
	}
	if _, err := nilSvc.Grant(ctx, principal, action.ActionRef); !errors.Is(err, ErrCallerUntrusted) {
		t.Fatalf("nil decision-provider seam err = %v, want ErrCallerUntrusted (never a silent pass)", err)
	}

	// wired seam that PASSES: the certified third party proceeds through the same
	// technical floor (grant + one-use dispatch) with no AgentNexus approver
	// selection.
	provider := &fakeDecisionProvider{}
	svc, store, _ := newTestService(t, WithDecisionProviderVerifier(provider))
	granted := mustGranted(t, svc, principal, testRequest(t))
	if provider.calls == 0 {
		t.Fatal("wired decision provider was never consulted for a certified third party")
	}
	if granted.Status != StatusGranted {
		t.Fatalf("certified third party status = %q, want granted", granted.Status)
	}
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(store.Grants()) != 1 {
		t.Fatalf("certified third party minted %d grants, want exactly one one-use grant", len(store.Grants()))
	}

	// wired seam that DENIES: fails closed.
	deny := &fakeDecisionProvider{err: errors.New("uncertified provider")}
	denySvc, _, _ := newTestService(t, WithDecisionProviderVerifier(deny))
	denied, err := denySvc.RequestAction(ctx, principal, testRequest(t))
	if err != nil {
		t.Fatalf("RequestAction (deny seam): %v", err)
	}
	if _, err := denySvc.Grant(ctx, principal, denied.ActionRef); !errors.Is(err, ErrCallerUntrusted) {
		t.Fatalf("denied decision-provider err = %v, want ErrCallerUntrusted", err)
	}
}

// An UNTRUSTED caller can never reach a side effect: it fails closed regardless
// of the seam wiring.
func TestRiskDecisionTrustUntrustedCannotReachSideEffect(t *testing.T) {
	provider := &fakeDecisionProvider{}
	svc, store, _ := newTestService(t, WithDecisionProviderVerifier(provider))
	principal := testPrincipal(runtime.TrustUntrusted)
	ctx := context.Background()

	action, err := svc.RequestAction(ctx, principal, testRequest(t))
	// An untrusted caller is denied at request or at grant, but MUST never reach
	// a grant/dispatch.
	if err == nil {
		if _, grantErr := svc.Grant(ctx, principal, action.ActionRef); !errors.Is(grantErr, ErrCallerUntrusted) {
			t.Fatalf("untrusted grant err = %v, want ErrCallerUntrusted", grantErr)
		}
	} else if !errors.Is(err, ErrCallerUntrusted) {
		t.Fatalf("untrusted request err = %v, want ErrCallerUntrusted", err)
	}
	if len(store.Grants()) != 0 {
		t.Fatal("an untrusted caller minted a grant; a side effect must be unreachable")
	}
}
