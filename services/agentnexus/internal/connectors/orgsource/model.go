package orgsource

import "context"

type Role string

const (
	RoleMember  Role = "member"
	RoleManager Role = "manager"
)

type Department struct {
	ID                string
	ParentID          string
	Name              string
	ManagerEmployeeID string
}

type Employee struct {
	ID                string
	DisplayName       string
	Email             string
	Phone             string
	ManagerEmployeeID string
	DepartmentIDs     []string
}

type Membership struct {
	EmployeeID   string
	DepartmentID string
	Role         Role
}

type Snapshot struct {
	Departments []Department
	Employees   []Employee
	Memberships []Membership
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
