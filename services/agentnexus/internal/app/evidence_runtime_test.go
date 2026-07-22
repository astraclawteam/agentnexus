package app

import (
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
)

func evidenceKeyMaterial() []byte {
	key := make([]byte, evidence.ContentKeyBytes)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// An unconfigured deployment must yield the INTERFACE's own nil, not a typed
// nil pointer boxed into it. A typed nil is non-nil to both the dependency
// guard and newBrowserAuthHandler, which would register /v1/runtime/locate and
// /v1/runtime/read over a nil service and panic on the first request instead of
// answering 404.
func TestBuildEvidenceRuntimeIsUntypedNilWhenUnconfigured(t *testing.T) {
	runtime, err := buildEvidenceRuntime(nil, PostgresGatewayConfig{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("buildEvidenceRuntime with nothing configured: %v", err)
	}
	if runtime != nil {
		t.Fatal("an unconfigured evidence runtime must be a nil interface, not a typed nil")
	}
	// The dependency guard reads this field through reflection, so prove the
	// value it actually sees is nil too.
	deps := BrowserAuthDependencies{Evidence: runtime}
	if !contains(deps.MissingRequired(), "Evidence") && !isEvidenceExcused() {
		t.Fatal("an unconfigured Evidence field was not seen as nil by the wiring guard")
	}
}

func isEvidenceExcused() bool {
	_, excused := optionalGatewayDeps["Evidence"]
	return excused
}

// A partial set is a startup error, never a silent skip. An operator who
// supplied a staging root but no content key would otherwise get a plane that
// registers, accepts every locate, and fails it.
func TestBuildEvidenceRuntimeRejectsAPartialConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  PostgresGatewayConfig
		want string
	}{
		{"root only", PostgresGatewayConfig{EvidenceObjectRoot: t.TempDir()}, "EvidenceContentKeyRef"},
		{"root and ref, no key", PostgresGatewayConfig{
			EvidenceObjectRoot: t.TempDir(), EvidenceContentKeyRef: "evd-key-1",
		}, "EvidenceContentKey"},
		{"key without root", PostgresGatewayConfig{
			EvidenceContentKeyRef: "evd-key-1", EvidenceContentKey: evidenceKeyMaterial(),
		}, "EvidenceObjectRoot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, err := buildEvidenceRuntime(nil, tc.cfg, nil, nil, nil)
			if err == nil {
				t.Fatal("buildEvidenceRuntime accepted a partial configuration")
			}
			if runtime != nil {
				t.Error("a rejected configuration must not return a runtime")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error must name the missing field %s, got %v", tc.want, err)
			}
		})
	}
}

// Broken key material must be refused at composition, not at the first locate
// where it would surface as an opaque 503.
func TestBuildEvidenceRuntimeRejectsUnusableKeyMaterial(t *testing.T) {
	_, err := buildEvidenceRuntime(nil, PostgresGatewayConfig{
		EvidenceObjectRoot:    t.TempDir(),
		EvidenceContentKeyRef: "evd-key-1",
		EvidenceContentKey:    make([]byte, 16),
	}, nil, nil, nil)
	if err == nil {
		t.Fatal("buildEvidenceRuntime accepted a 16-byte content key")
	}
	if !strings.Contains(err.Error(), "content key") {
		t.Errorf("error should point at the content key, got %v", err)
	}
}

func TestBuildEvidenceRuntimeComposesWhenFullyConfigured(t *testing.T) {
	root := t.TempDir()
	runtime, err := buildEvidenceRuntime(nil, PostgresGatewayConfig{
		EvidenceObjectRoot:    root,
		EvidenceContentKeyRef: "evd-key-1",
		EvidenceContentKey:    evidenceKeyMaterial(),
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("buildEvidenceRuntime: %v", err)
	}
	if runtime == nil {
		t.Fatal("a fully configured deployment must get an evidence runtime")
	}
	// evidence.NewService fills every one of its six ports or none: ready()
	// returns ErrUnavailable if any is nil and every method calls it first, so a
	// non-nil service that was built with a missing port would 503 everything.
	// Constructing it here is what proves all six were supplied.
	deps := BrowserAuthDependencies{Evidence: runtime}
	if contains(deps.MissingRequired(), "Evidence") {
		t.Fatal("a composed evidence runtime was still seen as nil by the wiring guard")
	}
}
