package gatewayagent

import (
	"strings"
	"testing"
)

// TestInstructionAdvertisesOnlyBuiltTools is the fix for a specific failure:
// the instruction used to name five capabilities while two tools existed, so
// the model was told to reach for three tools that were never registered. Its
// first move on those questions could only be a call that did not resolve.
//
// The assertion is a biconditional on purpose. Checking only that absent tools
// go unmentioned would pass for an instruction that mentions nothing at all,
// which is the other way to make the assistant useless.
func TestInstructionAdvertisesOnlyBuiltTools(t *testing.T) {
	tools, err := NewTools(NewPolicy(), &stubDiagnostics{})
	if err != nil {
		t.Fatalf("build tools: %v", err)
	}
	instruction := buildInstruction(tools)

	built := make(map[string]bool, len(tools))
	for _, tool := range tools {
		built[tool.Name()] = true
	}
	// Every capability the policy names, whether or not it has a tool today.
	for _, capability := range AllowedCapabilities {
		name := toolNamePrefix + string(capability)
		mentioned := strings.Contains(instruction, name)
		switch {
		case built[name] && !mentioned:
			t.Errorf("tool %q was built but the instruction never mentions it", name)
		case !built[name] && mentioned:
			t.Errorf("the instruction advertises %q, which no tool implements", name)
		}
	}
}

// TestInstructionFollowsTheAllowedToolSet: narrowing the policy must narrow
// what the model is told it can do. If it did not, a deployment could tighten
// the allow-list and still leave the model reaching for the removed tool.
func TestInstructionFollowsTheAllowedToolSet(t *testing.T) {
	tools, err := NewTools(policyAllowing(CapabilityExplainError), &stubDiagnostics{})
	if err != nil {
		t.Fatalf("build tools: %v", err)
	}
	instruction := buildInstruction(tools)
	if !strings.Contains(instruction, toolNamePrefix+"explain_error") {
		t.Error("the instruction omits the one tool that was built")
	}
	if strings.Contains(instruction, toolNamePrefix+"inspect_health") {
		t.Error("the instruction still advertises a tool the policy denied")
	}
}

// TestInstructionKeepsTheRefusals guards the half that is NOT generated. The
// generated tool list says what the assistant can do; these are the things it
// must decline, and regenerating the first half must never quietly drop them.
func TestInstructionKeepsTheRefusals(t *testing.T) {
	tools, err := NewTools(NewPolicy(), &stubDiagnostics{})
	if err != nil {
		t.Fatalf("build tools: %v", err)
	}
	instruction := buildInstruction(tools)
	// These mirror ForbiddenIntents in operator language. They are prose, not
	// the enforcement - the allow-list is - but an assistant that does not even
	// say no is a worse experience than one that does.
	for _, refusal := range []string{"issue grants", "execute", "read business data", "change policy", "install packages", "secret"} {
		if !strings.Contains(instruction, refusal) {
			t.Errorf("the instruction no longer refuses %q", refusal)
		}
	}
}
