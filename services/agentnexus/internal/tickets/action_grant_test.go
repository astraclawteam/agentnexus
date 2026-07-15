package tickets

import (
	"errors"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

const (
	agTestWorkCase = "wc_0123456789abcdef"
	agTestGrantRef = "grant_0123456789abcdef"
	agTestHash     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// The GA Task 0F Action grant is a one-use runtime.StepGrant bound to a
// business-semantic capability + parameter hash + business context, TTL-capped,
// and is minted as canonically valid. It is a DIFFERENT mechanism from the
// legacy resource-scoped dream_evidence grant, which stays untouched.
func TestGrantActionOneUseMintBindsExactOperationAndCapsTTL(t *testing.T) {
	now := time.Now().UTC()
	grant, err := MintActionGrant(ActionGrantInput{
		GrantRef:           agTestGrantRef,
		BusinessContextRef: agTestWorkCase,
		Capability:         "erp.purchase_order.approve",
		ParameterHash:      agTestHash,
		TTL:                time.Hour, // exceeds the cap
	}, now)
	if err != nil {
		t.Fatalf("MintActionGrant: %v", err)
	}
	if !grant.OneUse {
		t.Fatal("an action grant must be one-use by contract")
	}
	if grant.Capability != "erp.purchase_order.approve" || grant.ParameterHash != agTestHash || grant.BusinessContextRef != agTestWorkCase {
		t.Fatalf("grant not bound to the exact operation: %+v", grant)
	}
	if grant.ExpiresAt.Sub(grant.IssuedAt) != MaxActionGrantTTL {
		t.Fatalf("grant TTL = %v, want capped at %v", grant.ExpiresAt.Sub(grant.IssuedAt), MaxActionGrantTTL)
	}
	if err := grant.Validate(); err != nil {
		t.Fatalf("minted grant is not canonically valid: %v", err)
	}
}

// A one-use action grant may be consumed exactly once; a second consumption is
// rejected (the Step Grant double-consumption invariant at the primitive level).
func TestGrantActionOneUseDoubleConsumptionRejected(t *testing.T) {
	now := time.Now().UTC()
	grant, err := MintActionGrant(ActionGrantInput{GrantRef: agTestGrantRef, BusinessContextRef: agTestWorkCase, Capability: "erp.purchase_order.approve", ParameterHash: agTestHash, TTL: time.Minute}, now)
	if err != nil {
		t.Fatalf("MintActionGrant: %v", err)
	}
	if err := ConsumeActionGrant(grant, now, false); err != nil {
		t.Fatalf("first consumption: %v", err)
	}
	if err := ConsumeActionGrant(grant, now, true); !errors.Is(err, ErrActionGrantConsumed) {
		t.Fatalf("second consumption err = %v, want ErrActionGrantConsumed", err)
	}
	// An expired grant is not consumable.
	if err := ConsumeActionGrant(grant, grant.ExpiresAt.Add(time.Second), false); !errors.Is(err, ErrInvalidActionGrant) {
		t.Fatalf("expired consumption err = %v, want ErrInvalidActionGrant", err)
	}
}

// The legacy resource-scoped grant scope is unchanged: dream_evidence:read only.
func TestGrantActionPrimitiveDoesNotDisturbLegacyResourceScope(t *testing.T) {
	if scope, ok := exactGrantScope("dream_evidence", "read"); !ok || scope != "dream:evidence:read" {
		t.Fatalf("legacy resource scope changed: scope=%q ok=%v", scope, ok)
	}
	if _, ok := exactGrantScope("erp.purchase_order.approve", "execute"); ok {
		t.Fatal("a capability must not resolve to a legacy resource scope; the two grant mechanisms are not conflated")
	}
	_ = runtime.StepGrant{}
}
