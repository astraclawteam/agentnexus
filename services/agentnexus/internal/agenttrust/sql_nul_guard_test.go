package agenttrust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentTrustSQLParametersCarryNoNULJoiner is the NUL lock-key regression
// guard (the same defect class as approvaltransport C1, task-0e D13):
// PostgreSQL rejects NUL bytes (0x00) in text parameters ("invalid byte
// sequence for encoding UTF8", SQLSTATE 22021), so no SQL parameter in this
// package may ever be built from a NUL-joined key. The in-process Go map-key
// joiners are allowed ONLY in model.go (clientKey/certKey - MemoryStore keys
// that never cross the SQL boundary). The certification advisory lock takes
// the tenant and the publisher/product coordinates as two SEPARATE
// parameters in the two-int pg_advisory_xact_lock form instead.
func TestAgentTrustSQLParametersCarryNoNULJoiner(t *testing.T) {
	sqlBoundaryFiles := []string{
		"postgres.go",
		"service.go",
		filepath.Join("..", "..", "db", "queries", "agent_clients.sql"),
		filepath.Join("..", "..", "db", "generated", "agent_clients.sql.go"),
	}
	for _, file := range sqlBoundaryFiles {
		findings, err := scanNULJoiner(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			t.Errorf("NUL joiner reachable from the SQL boundary: %s", finding)
		}
	}
	lockSrc, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"hashtext('agt:' || $1::text)", "hashtext($2::text)"} {
		if !strings.Contains(string(lockSrc), required) {
			t.Errorf("certification advisory lock must take tenant and publisher/product as separate parameters; missing %q", required)
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
		control, err := scanNULJoiner(planted)
		if err != nil {
			t.Fatal(err)
		}
		if len(control) == 0 {
			t.Fatal("the NUL-joiner scanner failed to detect a planted joiner")
		}
	})
}

// scanNULJoiner reports every line of file containing a literal NUL byte or
// the \x00 escape sequence (copied from the approvaltransport C1 guard).
func scanNULJoiner(file string) ([]string, error) {
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

// itoa avoids strconv in this guard file (copied from the approvaltransport
// C1 guard so the two guards stay textually parallel).
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
