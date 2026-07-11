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
		"token_hash text not null",
		"unique (enterprise_id, token_hash)",
		"foreign key (enterprise_id, org_version, org_unit_id)",
		"dream:evidence:read",
		"step grant issuance evidence is immutable",
		"before update or delete on step_grant_issuances",
		"before truncate on step_grant_issuances",
		"step grant scope is immutable",
	} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("migration missing %q", fragment)
		}
	}
	if strings.Contains(sql, "raw_token") {
		t.Fatal("migration must not persist raw tokens")
	}
}

func TestStepGrantQueriesAreTenantHashAndVersionScoped(t *testing.T) {
	raw, err := os.ReadFile("../../db/queries/grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, fragment := range []string{"getgrantresourceowner", "getgrantresourceownerforupdate", "insertstepgrantissuance", "getstepgrantbytokenhash", "enterprise_id = $1", "token_hash = $2", "getlatestgrantorgversion"} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("queries missing %q", fragment)
		}
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
