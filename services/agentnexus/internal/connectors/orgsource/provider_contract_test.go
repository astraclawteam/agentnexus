package orgsource

import (
	"context"
	"testing"
)

func TestMockProvidersReturnNormalizedSnapshot(t *testing.T) {
	snapshot := Snapshot{
		Departments: []Department{{ID: "dept_legal", Name: "Legal"}},
		Employees:   []Employee{{ID: "user_1", DisplayName: "Ada", Email: "ada@example.com", DepartmentIDs: []string{"dept_legal"}}},
		Memberships: []Membership{{EmployeeID: "user_1", DepartmentID: "dept_legal", Role: RoleManager}},
	}

	providers := []Provider{
		NewMockWeComProvider(snapshot),
		NewMockFeishuProvider(snapshot),
		NewMockDingTalkProvider(snapshot),
	}

	for _, provider := range providers {
		t.Run(provider.Name(), func(t *testing.T) {
			got, err := provider.Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch returned error: %v", err)
			}
			if len(got.Departments) != 1 || got.Departments[0].ID != "dept_legal" {
				t.Fatalf("departments = %+v, want dept_legal", got.Departments)
			}
			if len(got.Employees) != 1 || got.Employees[0].DepartmentIDs[0] != "dept_legal" {
				t.Fatalf("employees = %+v, want normalized department membership", got.Employees)
			}
			if got.Memberships[0].Role != RoleManager {
				t.Fatalf("membership role = %q, want %q", got.Memberships[0].Role, RoleManager)
			}
		})
	}
}
