package tickets

import (
	"os"
	"strings"
	"testing"
)

func TestStepGrantMigrationStoresOnlyHashAndImmutableExactScope(t *testing.T) {
	raw, err := os.ReadFile("../../db/migrations/000006_scoped_step_grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(strings.Join(strings.Fields(string(raw)), " "))
	for _, fragment := range []string{
		"create table sensitive_resource_ownerships",
		"create table step_grant_issuances",
		"alter table case_tickets add column token_hash text",
		"uq_case_ticket_token_hash",
		"agentnexus:invalidated-legacy-case-ticket:v1:",
		"status='revoked'",
		"expires_at=least(expires_at, clock_timestamp())",
		"agentnexus:case-ticket:v1:",
		"agentnexus:step-grant:v1:",
		"token_hash text not null",
		"unique (enterprise_id, token_hash)",
		"foreign key (enterprise_id, org_version, org_unit_id)",
		"dream:evidence:read",
		"step grant issuance evidence is immutable",
		"before update or delete on step_grant_issuances",
		"before truncate on step_grant_issuances",
		"step grant scope is immutable",
		"expected_audit_input_hash text not null",
		"expected_audit_output_hash text not null",
		"audit_row.input_hash is distinct from new.expected_audit_input_hash",
		"audit_row.output_hash is distinct from new.expected_audit_output_hash",
		"audit_row.case_ticket_id is distinct from grant_row.case_ticket_id",
		"idx_step_grants_enterprise_expiry",
	} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("migration missing %q", fragment)
		}
	}
	if strings.Contains(sql, "raw_token") {
		t.Fatal("migration must not persist raw tokens")
	}
	if strings.Contains(sql, "sha256(convert_to(id") {
		t.Fatal("legacy database-visible id must not remain an accepted bearer")
	}
	down := sql[strings.Index(sql, "-- +goose down"):]
	if !strings.Contains(down, "migration 000006 is irreversible") || !strings.Contains(down, "raise exception") {
		t.Fatal("credential migration Down must fail closed as explicitly irreversible")
	}
	for _, dangerous := range []string{"drop column if exists token_hash", "drop table if exists step_grant_issuances", "drop table if exists sensitive_resource_ownerships"} {
		if strings.Contains(down, dangerous) {
			t.Fatalf("irreversible migration Down contains destructive rollback: %q", dangerous)
		}
	}
}

func TestStepGrantQueriesAreTenantHashAndVersionScoped(t *testing.T) {
	raw, err := os.ReadFile("../../db/queries/grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, fragment := range []string{"getgrantresourceowner", "getgrantresourceownerforgrant", "insertstepgrantissuance", "getstepgrantbytokenhash", "enterprise_id = $1", "token_hash = $2", "getlatestgrantorgversion"} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("queries missing %q", fragment)
		}
	}
	if strings.Contains(sql, "getgrantresourceownerforgrant :one\nselect") && strings.Contains(sql[strings.Index(sql, "getgrantresourceownerforgrant"):], "for update") {
		t.Fatal("issuance ownership read must not reverse org-lock then row-lock ordering")
	}
}

func TestCaseTicketAuthenticationUsesTokenHash(t *testing.T) {
	raw, err := os.ReadFile("../../db/queries/tickets.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	if !strings.Contains(sql, "tickets.token_hash = sqlc.arg(token_hash)") {
		t.Fatal("case ticket lookup must use token hash")
	}
}
