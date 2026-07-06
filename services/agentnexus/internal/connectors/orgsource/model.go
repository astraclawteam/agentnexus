package orgsource

import "context"

type Role string

const (
	RoleMember  Role = "member"
	RoleManager Role = "manager"
)

type Department struct {
	ID                string `json:"id"`
	ParentID          string `json:"parent_id"`
	Name              string `json:"name"`
	ManagerEmployeeID string `json:"manager_employee_id"`
}

type Employee struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"display_name"`
	Email             string   `json:"email"`
	Phone             string   `json:"phone"`
	ManagerEmployeeID string   `json:"manager_employee_id"`
	DepartmentIDs     []string `json:"department_ids"`
}

type Membership struct {
	EmployeeID   string `json:"employee_id"`
	DepartmentID string `json:"department_id"`
	Role         Role   `json:"role"`
}

type Snapshot struct {
	Departments []Department `json:"departments"`
	Employees   []Employee   `json:"employees"`
	Memberships []Membership `json:"memberships"`
}

type Provider interface {
	Name() string
	Fetch(context.Context) (Snapshot, error)
}

type mockProvider struct {
	name     string
	snapshot Snapshot
}

func (p mockProvider) Name() string {
	return p.name
}

func (p mockProvider) Fetch(context.Context) (Snapshot, error) {
	return NormalizeSnapshot(p.snapshot), nil
}

func NormalizeSnapshot(snapshot Snapshot) Snapshot {
	for employeeIndex := range snapshot.Employees {
		seen := map[string]struct{}{}
		unique := snapshot.Employees[employeeIndex].DepartmentIDs[:0]
		for _, departmentID := range snapshot.Employees[employeeIndex].DepartmentIDs {
			if departmentID == "" {
				continue
			}
			if _, ok := seen[departmentID]; ok {
				continue
			}
			seen[departmentID] = struct{}{}
			unique = append(unique, departmentID)
		}
		snapshot.Employees[employeeIndex].DepartmentIDs = unique
	}
	for membershipIndex := range snapshot.Memberships {
		if snapshot.Memberships[membershipIndex].Role == "" {
			snapshot.Memberships[membershipIndex].Role = RoleMember
		}
	}
	return snapshot
}
