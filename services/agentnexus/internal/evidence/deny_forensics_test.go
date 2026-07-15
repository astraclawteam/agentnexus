package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// GA Task 0F fold-in (deferred from the plan's 0E->0F deny-path enrichment): a
// DENIED verification-purpose read must record the exact Action binding it was
// evaluated against, so a forensic reviewer can see WHY/WHAT was denied - not
// just the coded reason. The enrichment is scoped to the verification-binding
// denials and records ONLY the binding's business-semantic refs/ids; it never
// records topology, connector detail, content or trusted identity, and it
// never changes the deny DECISION.

// assertDenyBindingForensics asserts the last lineage event is a deny whose
// Details carry the declared binding's business-semantic refs/ids by the same
// key names the ALLOW-path lineage already uses (action_ref/postcondition_id/
// verification_need_id), plus the parameter hash and the DECLARED data class
// under its own key (binding_data_class, distinct from the resolved handle
// data_class).
func assertDenyBindingForensics(t *testing.T, f *evidenceFixture, want runtime.VerificationBinding) {
	t.Helper()
	events := f.audit.Events()
	if len(events) == 0 {
		t.Fatal("expected a deny lineage event")
	}
	last := events[len(events)-1]
	if last.Details["decision"] != DecisionDeny {
		t.Fatalf("last lineage event is not a deny: %+v", last.Details)
	}
	for key, wantVal := range map[string]any{
		"action_ref":           want.ActionRef,
		"parameter_hash":       want.ParameterHash,
		"postcondition_id":     want.PostconditionID,
		"verification_need_id": want.VerificationNeedID,
		"binding_data_class":   want.DataClass,
	} {
		if got := last.Details[key]; got != wantVal {
			t.Errorf("deny lineage %s = %v, want the declared binding value %v", key, got, wantVal)
		}
	}
}

func TestVerificationDenyRecordsBindingForensics(t *testing.T) {
	t.Parallel()

	// The case the plan named explicitly: an Action-binding rejection
	// (action_binding_mismatch) must record the declared binding refs/ids so
	// forensics can see which Action binding was rejected.
	t.Run("action binding mismatch records the declared binding refs", func(t *testing.T) {
		verifier := &recordingActionBindingVerifier{err: errors.New("no such action")}
		f := newVerificationFixture(t, WithActionBindingVerifier(verifier))
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil {
			t.Fatalf("verifier rejection must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny {
			t.Fatalf("verifier rejection must fail closed: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyActionUnbound)
		assertDenyBindingForensics(t, f.evidenceFixture, *verificationBlock())
	})

	// A DIFFERENT verification-binding denial records the same forensics, so
	// the enrichment is not narrowly action_binding-only. The declared class
	// here is deliberately the CLAIMED one (distinct from the resolved handle
	// class), proving binding_data_class carries the declared value while the
	// pre-existing data_class still carries the resolved handle class.
	t.Run("need mismatch records the declared claimed binding refs", func(t *testing.T) {
		f := newVerificationFixture(t)
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		req := f.verificationRead(located.BusinessContextRef, handle.EvidenceRef)
		req.VerificationBinding.DataClass = openClass
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), req)
		if err != nil {
			t.Fatalf("need mismatch must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny {
			t.Fatalf("need mismatch must fail closed: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyNeedMismatch)
		assertDenyBindingForensics(t, f.evidenceFixture, *req.VerificationBinding)
		last := f.audit.Events()[len(f.audit.Events())-1]
		if last.Details["binding_data_class"] != openClass {
			t.Fatalf("binding_data_class = %v, want the DECLARED class %q", last.Details["binding_data_class"], openClass)
		}
		if last.Details["data_class"] != verifyClass {
			t.Fatalf("data_class = %v, want the RESOLVED handle class %q (both must be preserved)", last.Details["data_class"], verifyClass)
		}
	})

	// A freshness-expiry denial records the forensics too.
	t.Run("observation staleness records the declared binding refs", func(t *testing.T) {
		f := newVerificationFixture(t)
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		*f.now = f.now.Add(verifyFreshness + time.Second)
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil {
			t.Fatalf("stale observation must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny {
			t.Fatalf("stale observation must fail closed: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyObservationStale)
		assertDenyBindingForensics(t, f.evidenceFixture, *verificationBlock())
	})
}
