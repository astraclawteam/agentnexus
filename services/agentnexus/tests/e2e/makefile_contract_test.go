package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeTestAuthRequiresLivePostgresDSNBeforeGoTest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	target := string(raw)
	start := strings.Index(target, "test-auth:")
	end := strings.Index(target[start:], "\ntest:")
	if start < 0 || end < 0 {
		t.Fatal("test-auth target missing")
	}
	target = target[start : start+end]
	gate := strings.Index(target, `$(error AGENTNEXUS_E2E_POSTGRES_DSN is required for live PostgreSQL acceptance)`)
	testCommand := strings.Index(target, "go test ./internal/browserauth ./internal/policy ./internal/approval ./internal/tickets ./internal/app ./tests/e2e -count=1")
	if gate < 0 || testCommand < 0 || gate > testCommand || strings.Contains(target, "test -n") || strings.Contains(target, "{ echo") {
		t.Fatalf("test-auth must fail before go test when live PostgreSQL DSN is absent:\n%s", target)
	}
}

func TestReleaseCIStartsRealPostgresAndCallsOnlyFailClosedAuthGate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", ".github", "workflows", "agentnexus-auth.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := strings.ToLower(string(raw))
	for _, required := range []string{"services:", "postgres:", "agentnexus_e2e_postgres_dsn", "make test-auth"} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("release auth workflow missing %q", required)
		}
	}
	if strings.Contains(workflow, "go test ./tests/e2e") {
		t.Fatal("CI must not bypass the fail-closed make test-auth release gate")
	}
}

func TestMaintenanceReleaseOrchestratorForcesCredentialMigrationOrder(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "release-auth.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ToLower(string(raw))
	ordered := []string{"stop_old", "backup", "migrate", "start_new", "verify"}
	last := -1
	for _, marker := range ordered {
		index := strings.Index(script, marker)
		if index <= last {
			t.Fatalf("release phase %q missing or out of order", marker)
		}
		last = index
	}
	for _, required := range []string{"maintenance", "old/new binary overlap is forbidden", "restore"} {
		if !strings.Contains(script, required) {
			t.Fatalf("release script missing fail-closed guard %q", required)
		}
	}
}
