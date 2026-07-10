package approval

import (
	"os"
	"strings"
	"testing"
)

func TestApprovalMigrationBindsImmutableRouteEvidence(t *testing.T) {
	raw, err := os.ReadFile("../../db/migrations/000005_governed_approval_routes.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	required := []string{
		"approval_queue_items contains rows; governed route migration requires an empty pre-release table",
		"org_version bigint not null",
		"risk_reasons jsonb not null",
		"route_mode text not null",
		"org_path jsonb not null",
		"queue text",
		"route_input_hash text not null",
		"route_output_hash text not null",
		"foreign key (enterprise_id, org_version)",
		"foreign key (enterprise_id, org_version, org_unit_id)",
		"policy_snapshot_sealed",
		"reviewer_user_id is null or reviewer_user_id <> requester_user_id",
		"btrim(requester_user_id) = requester_user_id",
		"btrim(resource_type) = resource_type",
		"btrim(resource_id) = resource_id",
		"btrim(action) = action",
		"btrim(org_unit_id) = org_unit_id",
		"single_confirmation",
		"upward_review",
		"enterprise_knowledge_admin_queue",
		"enterprise_knowledge_admin",
		"drop column if exists org_version",
	}
	for _, value := range required {
		if !strings.Contains(sql, value) {
			t.Errorf("migration missing %q", value)
		}
	}
}

func TestApprovalQueriesAreVersionTenantAndLimitScoped(t *testing.T) {
	raw, err := os.ReadFile("../../db/queries/approval.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, value := range []string{"getlatestapprovalorgversion", "listapprovalorgunits", "listapprovalmemberships", "listapprovalusers", "insertapprovalqueueitem", "enterprise_id = $1", "version_number = $2", "limit 10001", "limit 100001"} {
		if !strings.Contains(sql, value) {
			t.Errorf("queries missing %q", value)
		}
	}
}
