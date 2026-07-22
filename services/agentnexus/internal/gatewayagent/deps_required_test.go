package gatewayagent

import (
	"context"
	"iter"
	"reflect"
	"testing"

	"google.golang.org/adk/v2/model"
	adksession "google.golang.org/adk/v2/session"
)

// This file is the gateway-agent half of the repo-wide wiring guard, and it
// deliberately does NOT use internal/wiring.
//
// The defect that guard exists for needs a dependency STRUCT: a field a
// composition root can leave unset while everything still compiles, fails
// closed, and stays green because every test sets the field itself. The
// assistant has no such struct. Its dependencies are positional arguments of
// NewAssistant, so leaving one out is a compile error at every call site, and
// the compiler is a stronger version of the "adding a field forces a decision"
// property than any reflection over an optional-set map. Building an
// AssistantDeps struct purely so there were something to reflect over would be
// copying the AgentAtlas shape rather than its purpose, and would trade a
// compile-time guarantee for a runtime one.
//
// What the compiler does NOT force is that each argument is CHECKED. A
// dependency can be passed, ignored, and the assistant will compose anyway with
// that feature quietly absent - the same silence, arriving through a different
// door. Policy is the live example: it is a struct, so nothing is nil, and a
// zero Policy allows no capability at all. An assistant built on one has every
// dependency present, reports ready, and has no tools; the empty-tool-set
// refusal in NewTools is the only thing standing between that and a shipped
// assistant that can ground nothing.
//
// So this asserts the property the guard would have bought, derived from the
// constructor's own signature rather than from a hand-maintained list.

// TestEveryAssistantDependencyIsRefusedWhenAbsent walks NewAssistant's parameter
// list by reflection and, for each position in turn, calls it with that one
// argument zeroed and every other valid. Each must be refused.
//
// Driving it off the signature is what makes it maintainable rather than
// another list to forget: a dependency added to NewAssistant is covered the
// moment it is added, and if it is accepted without a check this fails naming
// the position. A hand-written case per argument would have to be remembered,
// which is the failure mode being guarded against.
func TestEveryAssistantDependencyIsRefusedWhenAbsent(t *testing.T) {
	valid := []reflect.Value{
		reflect.ValueOf(stubLLM{}),
		reflect.ValueOf(NewPolicy()),
		reflect.ValueOf(DiagnosticsService(&stubDiagnostics{})),
		reflect.ValueOf(adksession.InMemoryService()),
	}
	constructor := reflect.ValueOf(NewAssistant)
	if got, want := constructor.Type().NumIn(), len(valid); got != want {
		t.Fatalf("NewAssistant takes %d arguments but this test supplies %d; a dependency was added without deciding whether its absence is refused", got, want)
	}
	// Sanity: the valid set really does compose, so a refusal below is caused by
	// the zeroed argument and not by a stale fixture.
	if assistant, err := NewAssistant(stubLLM{}, NewPolicy(), &stubDiagnostics{}, adksession.InMemoryService()); err != nil || assistant == nil {
		t.Fatalf("the fully supplied fixture does not compose: assistant=%v err=%v", assistant, err)
	}

	for position := 0; position < constructor.Type().NumIn(); position++ {
		paramType := constructor.Type().In(position)
		args := make([]reflect.Value, len(valid))
		copy(args, valid)
		// The zero value of an interface is nil; of Policy, a policy that allows
		// nothing. Both are "this dependency was not supplied", and both must be
		// refused rather than composed around.
		args[position] = reflect.Zero(paramType)

		results := constructor.Call(args)
		assistant, err := results[0].Interface(), results[1].Interface()
		if err == nil {
			t.Errorf("NewAssistant accepted a zero %s (argument %d): the assistant composes with that dependency absent", paramType, position)
		}
		if !results[0].IsNil() {
			t.Errorf("NewAssistant returned an assistant (%v) alongside its refusal of a zero %s", assistant, paramType)
		}
	}
}

// The zero Policy is the case a nil check cannot see and a reflection guard over
// nilable kinds would skip entirely. Pinning it separately, with the reason,
// because the generic test above would still pass if the refusal moved to some
// unrelated cause.
func TestAZeroPolicyIsRefusedRatherThanComposedWithNoTools(t *testing.T) {
	_, err := NewAssistant(stubLLM{}, Policy{}, &stubDiagnostics{}, adksession.InMemoryService())
	if err == nil {
		t.Fatal("a zero Policy composed an assistant; it would report ready and have no tools to ground any answer")
	}
	if _, toolErr := NewTools(Policy{}, &stubDiagnostics{}); toolErr == nil {
		t.Fatal("NewTools built a tool set from a policy that allows nothing")
	}
}

// stubLLM satisfies model.LLM without reaching a provider. It is never asked to
// generate: every test here stops at composition.
type stubLLM struct{}

func (stubLLM) Name() string { return "stub" }

func (stubLLM) GenerateContent(context.Context, *model.LLMRequest, bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {}
}
