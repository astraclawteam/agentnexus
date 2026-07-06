package audit

import "testing"

func TestHashChainVerification(t *testing.T) {
	first := NewEvent(EventInput{
		ID:           "audit_1",
		EnterpriseID: "ent_1",
		Action:       "read",
		Decision:     "allow",
		InputHash:    "sha256:input",
		OutputHash:   "sha256:output",
	}, "")
	second := NewEvent(EventInput{
		ID:           "audit_2",
		EnterpriseID: "ent_1",
		Action:       "mask",
		Decision:     "allow_with_masking",
		InputHash:    "sha256:input2",
		OutputHash:   "sha256:output2",
	}, first.EventHash)

	if err := VerifyHashChain([]Event{first, second}); err != nil {
		t.Fatalf("VerifyHashChain returned error: %v", err)
	}

	second.Decision = "deny"
	if err := VerifyHashChain([]Event{first, second}); err == nil {
		t.Fatal("VerifyHashChain returned nil after tamper")
	}
}
