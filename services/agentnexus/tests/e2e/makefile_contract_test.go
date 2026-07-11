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
