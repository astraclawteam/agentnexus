package actions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestActionSQLParametersCarryNoNULJoiner is the NUL lock-key regression guard
// (the same defect class as approvaltransport C1 / agenttrust): PostgreSQL
// rejects NUL bytes (0x00) in text parameters ("invalid byte sequence for
// encoding UTF8", SQLSTATE 22021), so no SQL parameter reachable from the SQL
// boundary of this package may ever be built from a NUL-joined key. The
// in-process Go map-key joiner is allowed ONLY in model.go (MemoryStore keys
// that never cross the SQL boundary). The per-action advisory lock takes the
// tenant and the action as two SEPARATE parameters in the two-int
// pg_advisory_xact_lock form instead.
func TestActionSQLParametersCarryNoNULJoiner(t *testing.T) {
	sqlBoundaryFiles := []string{
		"postgres.go",
		"service.go",
		"reconcile.go",
		"compensate.go",
		"outbox.go",
		"nats.go",
		filepath.Join("..", "..", "db", "queries", "actions.sql"),
		filepath.Join("..", "..", "db", "queries", "outbox.sql"),
		filepath.Join("..", "..", "db", "generated", "actions.sql.go"),
		filepath.Join("..", "..", "db", "generated", "outbox.sql.go"),
	}
	for _, file := range sqlBoundaryFiles {
		findings, err := scanActionNULJoiner(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			t.Errorf("NUL joiner reachable from the SQL boundary: %s", finding)
		}
	}
	lockSrc, err := os.ReadFile(filepath.Join("..", "..", "db", "generated", "actions.sql.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"hashtext('act:' || $1::text)", "hashtext($2::text)"} {
		if !strings.Contains(string(lockSrc), required) {
			t.Errorf("per-action advisory lock must take tenant and action as separate parameters; missing %q", required)
		}
	}
	if strings.Contains(string(lockSrc), "hashtextextended($1") {
		t.Error("single joined-parameter lock form must not return")
	}

	t.Run("positive control", func(t *testing.T) {
		dir := t.TempDir()
		planted := filepath.Join(dir, "planted.go")
		if err := os.WriteFile(planted, []byte("package planted\n\nfunc key(a, b string) string { return a + \"\x00\" + b }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		control, err := scanActionNULJoiner(planted)
		if err != nil {
			t.Fatal(err)
		}
		if len(control) == 0 {
			t.Fatal("the NUL-joiner scanner failed to detect a planted joiner")
		}
	})
}

// scanActionNULJoiner reports every line of file containing a literal NUL byte
// or the \x00 escape sequence (copied from the approvaltransport C1 guard).
func scanActionNULJoiner(file string) ([]string, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var findings []string
	for index, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "\x00") || strings.Contains(line, `\x00`) {
			findings = append(findings, file+":"+itoa(index+1))
		}
	}
	return findings, nil
}
