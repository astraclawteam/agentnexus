package wiring

import (
	"reflect"
	"strings"
	"testing"
)

type sampleIface interface{ Do() }

type sampleConcrete struct{}

// sampleDeps covers every shape the engine has to classify: the three nilable
// dependency kinds, a non-nilable configuration value, and an unexported field.
type sampleDeps struct {
	Iface    sampleIface
	Fn       func() error
	Concrete *sampleConcrete
	Timeout  int
	hidden   sampleIface //nolint:unused // present so the guard is forced to skip it
}

func TestMissingRequiredNamesEveryNilDependencySorted(t *testing.T) {
	got := MissingRequired(sampleDeps{}, nil)
	want := []string{"Concrete", "Fn", "Iface"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingRequired() = %v, want %v", got, want)
	}
}

// The concrete-pointer case is the one AgentAtlas's interface-and-func-only
// reflection could not see. A guard that skipped it would answer "nothing
// missing" for a composition whose pointer dependency is nil, which is the exact
// silence this package exists to break.
func TestMissingRequiredSeesANilConcretePointer(t *testing.T) {
	deps := sampleDeps{Iface: stubIface{}, Fn: func() error { return nil }}
	got := MissingRequired(deps, nil)
	if !reflect.DeepEqual(got, []string{"Concrete"}) {
		t.Fatalf("MissingRequired() = %v, want the nil concrete pointer reported", got)
	}
}

func TestMissingRequiredIsEmptyWhenEveryDependencyIsSet(t *testing.T) {
	deps := sampleDeps{Iface: stubIface{}, Fn: func() error { return nil }, Concrete: &sampleConcrete{}}
	if got := MissingRequired(deps, nil); len(got) > 0 {
		t.Fatalf("MissingRequired() = %v, want none", got)
	}
}

func TestMissingRequiredSkipsDeclaredOptionalFields(t *testing.T) {
	got := MissingRequired(sampleDeps{}, map[string]string{"Concrete": "defaults downstream"})
	if !reflect.DeepEqual(got, []string{"Fn", "Iface"}) {
		t.Fatalf("MissingRequired() = %v, want the optional field excluded", got)
	}
}

// A non-nilable field can never be judged by reflection, so it must not appear
// in a result that a caller reads as "these are unwired".
func TestMissingRequiredIgnoresConfigurationValues(t *testing.T) {
	for _, name := range MissingRequired(sampleDeps{}, nil) {
		if name == "Timeout" || name == "hidden" {
			t.Fatalf("MissingRequired() reported %s, which it cannot decide emptiness for", name)
		}
	}
}

func TestStaleOptionalIsEmptyForAnExactSet(t *testing.T) {
	if got := StaleOptional(sampleDeps{}, map[string]string{"Iface": "a stated reason"}); len(got) > 0 {
		t.Fatalf("StaleOptional() = %v, want none", got)
	}
}

func TestStaleOptionalCatchesEveryWayAnEntryStopsMeaningAnything(t *testing.T) {
	stale := StaleOptional(sampleDeps{}, map[string]string{
		"Renamed": "the field this named was renamed away",
		"Timeout": "a value, never inspected",
		"Iface":   "",
	})
	for _, want := range []string{"Renamed", "Timeout", "Iface"} {
		if !containsSubstring(stale, want) {
			t.Errorf("StaleOptional() = %v, want it to flag %s", stale, want)
		}
	}
}

// Handing the guard something it cannot read must be loud. Returning an empty
// slice would read to every caller as "fully wired".
func TestMissingRequiredPanicsRatherThanPassingOnAValueItCannotRead(t *testing.T) {
	for name, deps := range map[string]any{
		"not a struct": "deps",
		"nil pointer":  (*sampleDeps)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("MissingRequired returned instead of panicking")
				}
			}()
			MissingRequired(deps, nil)
		})
	}
}

func TestMissingRequiredAcceptsAPointerToAStruct(t *testing.T) {
	if got := MissingRequired(&sampleDeps{}, nil); len(got) != 3 {
		t.Fatalf("MissingRequired(&deps) = %v, want the same three names as the value form", got)
	}
}

type stubIface struct{}

func (stubIface) Do() {}

func containsSubstring(haystack []string, needle string) bool {
	for _, item := range haystack {
		if strings.Contains(item, needle) {
			return true
		}
	}
	return false
}
