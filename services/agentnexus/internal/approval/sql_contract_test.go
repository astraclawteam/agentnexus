package approval

import (
	"fmt"
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
		"create table enterprise_approval_policies",
		"policy_version bigint not null",
		"minimum_risk text not null",
		"max_low_impacted_users integer not null",
		"max_low_impacted_org_units integer not null",
		"new.policy_version <= old.policy_version",
		"create table approval_resolution_idempotency",
		"jsonb_array_elements(new.risk_reasons)",
		"count(distinct value)",
		"new.org_path->>0 <> new.org_unit_id",
		"non-adjacent organization path",
		"invalid reviewer evidence",
		"validate_approval_resolution_route_evidence",
		"enterprise approval policies cannot be deleted or truncated",
		"enterprise approval policy history is immutable and cannot be deleted or truncated",
		"before insert on approval_queue_items",
		"approval resolution evidence is immutable",
		"approval queue evidence is immutable",
		"pending' and new.status in ('approved', 'rejected', 'cancelled')",
		"foreign key (enterprise_id, audit_event_id)",
		"expected_audit_input_hash",
		"expected_audit_output_hash",
		"reviewer_permission",
		"approve_high_risk",
		"publish_low_risk",
		"organization admin path must reach root",
		"requester_permission",
		"validate_direct_requester_permission_evidence",
		"approval audit ledger is append-only",
		"linked_audit.evidence_pointer is distinct from new.queue_item_id",
		"before update or delete on audit_events",
		"before truncate on audit_events",
	}
	for _, value := range required {
		if !strings.Contains(sql, value) {
			t.Errorf("migration missing %q", value)
		}
	}
	queueModeStart := strings.Index(sql, "add column route_mode text not null check")
	queueModeEnd := strings.Index(sql[queueModeStart:], "add column org_path")
	if queueModeStart < 0 || queueModeEnd < 0 || strings.Contains(sql[queueModeStart:queueModeStart+queueModeEnd], "single_confirmation") {
		t.Fatal("queue route_mode must reject single_confirmation")
	}
}

func TestApprovalMigrationSeedsCanonicalDefaultPolicyForExistingEnterprises(t *testing.T) {
	raw, err := os.ReadFile("../../db/migrations/000005_governed_approval_routes.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(strings.Join(strings.Fields(string(raw)), " "))
	policy := DefaultPolicy()
	want := fmt.Sprintf("select id, '%s', %d, %d, 1 from enterprises", policy.MinimumRisk, policy.MaxLowImpactedUsers, policy.MaxLowImpactedOrgUnits)
	for _, fragment := range []string{"insert into enterprise_approval_policies", want, "after insert or update on enterprise_approval_policies"} {
		if !strings.Contains(sql, fragment) {
			t.Errorf("migration does not atomically seed canonical default policy/history: missing %q", fragment)
		}
	}
}

func TestApprovalQueriesAreVersionTenantAndLimitScoped(t *testing.T) {
	raw, err := os.ReadFile("../../db/queries/approval.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, value := range []string{"getlatestapprovalorgversion", "getenterpriseapprovalpolicy", "getcurrentapprovalpolicyversion", "acquireenterpriseapprovalpolicylock", "publishenterpriseapprovalpolicy", "hashtextextended($1, 2)", "policy_version = enterprise_approval_policies.policy_version + 1", "listapprovalorgunits", "listapprovalmemberships", "listapprovalusers", "insertapprovalqueueitem", "enterprise_id = $1", "version_number = $2", "limit 10001", "limit 100001"} {
		if !strings.Contains(sql, value) {
			t.Errorf("queries missing %q", value)
		}
	}
}
