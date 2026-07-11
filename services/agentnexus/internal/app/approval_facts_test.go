package app

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
)

func TestHMACChangeFactsVerifierBindsEverySecurityField(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	now := time.Date(2026, 7, 11, 1, 0, 0, 0, time.UTC)
	base := verifiedFactsInput(now)
	signature, err := ComputeChangeFactsAttestation(secret, base)
	if err != nil {
		t.Fatal(err)
	}
	base.Signature = signature
	verifier, err := NewHMACChangeFactsVerifier(secret, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	facts, err := verifier.VerifyChangeFacts(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := approval.ClassifyVerifiedRisk(facts, approval.RiskLow, base.ResourceType, base.Action, approval.DefaultPolicy())
	if err != nil || assessment.Level != approval.RiskLow {
		t.Fatalf("valid assessment=%+v err=%v", assessment, err)
	}

	mutations := []struct {
		name string
		fn   func(*ChangeFactsVerificationInput)
	}{
		{name: "actor", fn: func(v *ChangeFactsVerificationInput) { v.ActorUserID = "attacker" }},
		{name: "enterprise", fn: func(v *ChangeFactsVerificationInput) { v.EnterpriseID = "other" }},
		{name: "resource", fn: func(v *ChangeFactsVerificationInput) { v.ResourceID = "other" }},
		{name: "idempotency", fn: func(v *ChangeFactsVerificationInput) { v.IdempotencyKeyHash = strings.Repeat("a", 64) }},
		{name: "fact", fn: func(v *ChangeFactsVerificationInput) { v.ImpactedUserCount++ }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			forged := base
			tt.fn(&forged)
			assertUnverifiedHigh(t, verifier, forged)
		})
	}
}

func TestHMACChangeFactsVerifierRejectsExpiredAndLongLivedAttestations(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	now := time.Date(2026, 7, 11, 1, 0, 0, 0, time.UTC)
	verifier, err := NewHMACChangeFactsVerifier(secret, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []ChangeFactsVerificationInput{
		func() ChangeFactsVerificationInput { v := verifiedFactsInput(now); v.FactsExpiresAt = now; return v }(),
		func() ChangeFactsVerificationInput {
			v := verifiedFactsInput(now)
			v.FactsExpiresAt = now.Add(-time.Second)
			return v
		}(),
		func() ChangeFactsVerificationInput {
			v := verifiedFactsInput(now)
			v.FactsExpiresAt = v.FactsIssuedAt.Add(5*time.Minute + time.Second)
			return v
		}(),
	} {
		sig, err := ComputeChangeFactsAttestation(secret, input)
		if err != nil {
			t.Fatal(err)
		}
		input.Signature = sig
		assertUnverifiedHigh(t, verifier, input)
	}
}

func TestHMACChangeFactsVerifierRequiresDeploymentSecret(t *testing.T) {
	if _, err := NewHMACChangeFactsVerifier([]byte("short"), time.Now); err == nil {
		t.Fatal("short secret accepted")
	}
	facts, err := (RejectChangeFactsVerifier{}).VerifyChangeFacts(context.Background(), verifiedFactsInput(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := approval.ClassifyVerifiedRisk(facts, approval.RiskLow, "knowledge", "knowledge.publish_low_risk", approval.DefaultPolicy())
	if err != nil || assessment.Level != approval.RiskHigh {
		t.Fatalf("assessment=%+v err=%v", assessment, err)
	}
}

func TestLoadChangeFactsVerifierFromSecretFileFailsSafe(t *testing.T) {
	if verifier, err := LoadChangeFactsVerifierFromFile("", time.Now); err != nil {
		t.Fatal(err)
	} else if _, ok := verifier.(RejectChangeFactsVerifier); !ok {
		t.Fatalf("verifier=%T", verifier)
	}
	path := t.TempDir() + "/approval.secret"
	if err := os.WriteFile(path, []byte(strings.Repeat("z", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if verifier, err := LoadChangeFactsVerifierFromFile(path, time.Now); err != nil {
		t.Fatal(err)
	} else if _, ok := verifier.(*HMACChangeFactsVerifier); !ok {
		t.Fatalf("verifier=%T", verifier)
	}
}

func verifiedFactsInput(now time.Time) ChangeFactsVerificationInput {
	return ChangeFactsVerificationInput{EnterpriseID: "enterprise-1", ActorUserID: "requester", OrgVersion: 7, OrgUnitID: "team", ResourceType: "knowledge", ResourceID: "article-1", Action: "knowledge.publish_low_risk", ChangedFields: []string{"title"}, ImpactedOrgUnitIDs: []string{"team"}, ImpactedUserCount: 1, PublishedBehaviorChange: false, ExternalSideEffect: false, FactsIssuedAt: now.Add(-time.Minute), FactsExpiresAt: now.Add(time.Minute), FactsNonce: "nonce-123456789012", IdempotencyKeyHash: strings.Repeat("b", 64)}
}

func assertUnverifiedHigh(t *testing.T, verifier ChangeFactsVerifier, input ChangeFactsVerificationInput) {
	t.Helper()
	facts, err := verifier.VerifyChangeFacts(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := approval.ClassifyVerifiedRisk(facts, approval.RiskLow, input.ResourceType, input.Action, approval.DefaultPolicy())
	if err != nil || assessment.Level != approval.RiskHigh || len(assessment.Reasons) != 1 || assessment.Reasons[0] != approval.RiskReasonUnverifiedChangeFacts {
		t.Fatalf("assessment=%+v err=%v", assessment, err)
	}
}
