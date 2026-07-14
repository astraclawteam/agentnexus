package approvaltransport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoApprovalPolicyOwnership is the permanent boundary guard of GA Task 0E:
// AgentNexus TRANSMITS approval plans and validates returned evidence — it
// never classifies domain risk, never walks an organization hierarchy and
// never chooses approvers or routes queues. The legacy resolution vocabulary
// below is therefore banned from every production source under the service
// (Go, SQL queries, generated code, OpenAPI and proto surfaces).
//
// Scope notes (deliberate, recorded):
//   - _test.go files are excluded: fixtures that assert REJECTION of the
//     legacy vocabulary are legitimate, and this guard's own literal list
//     lives in a _test.go file.
//   - db/migrations is excluded: applied migrations are immutable history
//     (000002/000005 created the legacy tables; migration 000009 retires
//     them). The queries and generated code that would keep the history
//     alive ARE scanned.
//   - api/CHANGELOG.yaml is excluded: it is the immutable protocol history
//     and legitimately NAMES the retired surface in past entries.
func TestNoApprovalPolicyOwnership(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "internal"),
		filepath.Join("..", "..", "api", "openapi"),
		filepath.Join("..", "..", "api", "proto"),
		filepath.Join("..", "..", "cmd"),
		filepath.Join("..", "..", "db", "queries"),
		filepath.Join("..", "..", "db", "generated"),
	}
	findings, err := scanLegacyApprovalResolutionIdentifiers(roots)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Errorf("legacy approval-resolution vocabulary in production source: %s", finding)
	}

	t.Run("positive control", func(t *testing.T) {
		dir := t.TempDir()
		planted := filepath.Join(dir, "planted.go")
		if err := os.WriteFile(planted, []byte("package planted\n\nconst planted = \"ModeUpwardReview\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		control, err := scanLegacyApprovalResolutionIdentifiers([]string{dir})
		if err != nil {
			t.Fatal(err)
		}
		if len(control) == 0 {
			t.Fatal("the guard scanner failed to detect a planted legacy identifier; the boundary scan is not trustworthy")
		}
	})
}

// legacyApprovalResolutionIdentifiers is the frozen list of banned
// approver-selection / risk-classification vocabulary. Every entry names the
// retired resolution machinery: route modes that chose HOW a change is
// approved, reviewer selection, the enterprise admin queue, AgentNexus-authored
// domain risk classification, and the retired public resolve surface.
var legacyApprovalResolutionIdentifiers = []string{
	"ModeUpwardReview",
	"ModeSingleConfirmation",
	"ModeEnterpriseKnowledgeAdminQueue",
	"EnterpriseKnowledgeAdminQueue",
	"ClassifyVerifiedRisk",
	"ReviewerUserID",
	"ReviewerDisplayName",
	"reviewer_user_id",
	"single_confirmation",
	"upward_review",
	"enterprise_knowledge_admin",
	"/v1/approvals/resolve",
	"resolveApprovalRoute",
	"X-Approval-Facts-Attestation",
}

func scanLegacyApprovalResolutionIdentifiers(roots []string) ([]string, error) {
	var findings []string
	for _, root := range roots {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			switch {
			case strings.HasSuffix(name, "_test.go"):
				return nil // rejection fixtures and this guard's own literal list
			case name == "CHANGELOG.yaml":
				return nil // immutable protocol history
			}
			switch filepath.Ext(name) {
			case ".go", ".sql", ".yaml", ".yml", ".proto":
			default:
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content := string(raw)
			for _, banned := range legacyApprovalResolutionIdentifiers {
				if index := strings.Index(content, banned); index >= 0 {
					line := 1 + strings.Count(content[:index], "\n")
					findings = append(findings, path+":"+itoa(line)+": contains "+banned)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return findings, nil
}

// itoa avoids strconv in this tiny guard helper.
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

// TestApprovalTransportSQLParametersCarryNoNULJoiner is the C1 regression
// guard: PostgreSQL rejects NUL bytes (0x00) in text parameters ("invalid
// byte sequence for encoding UTF8"), so no SQL parameter in this package may
// ever be built from a NUL-joined key. The in-process Go map-key joiner is
// allowed ONLY in model.go (MemoryStore.storeKey). The per-plan advisory
// lock takes tenant and plan as two SEPARATE parameters instead.
func TestApprovalTransportSQLParametersCarryNoNULJoiner(t *testing.T) {
	sqlBoundaryFiles := []string{
		"postgres.go",
		"service.go",
		"channel.go",
		filepath.Join("..", "..", "db", "queries", "approval_transport.sql"),
		filepath.Join("..", "..", "db", "generated", "approval_transport.sql.go"),
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
	lockSQL, err := os.ReadFile(filepath.Join("..", "..", "db", "queries", "approval_transport.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"hashtext('apt:' || sqlc.arg(tenant_ref)::text)", "hashtext(sqlc.arg(plan_ref))"} {
		if !strings.Contains(string(lockSQL), required) {
			t.Errorf("per-plan advisory lock must take tenant and plan as separate parameters; missing %q", required)
		}
	}
	if strings.Contains(string(lockSQL), "hashtextextended($1") {
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
// the \x00 escape sequence.
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
