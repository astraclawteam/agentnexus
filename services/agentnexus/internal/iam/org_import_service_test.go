package iam

import (
	"context"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
)

func TestOrgImportServicePersistsConfirmedSnapshot(t *testing.T) {
	ctx := context.Background()
	service := NewService(
		NewMemoryStore(),
		WithIDGenerator(sequenceIDs("identity_wecom", "identity_email", "identity_phone", "identity_llmrouter", "event_1", "version_1")),
	)
	snapshot := orgsource.Snapshot{
		Departments: []orgsource.Department{
			{ID: "dept_root", Name: "Headquarters"},
			{ID: "dept_rd", ParentID: "dept_root", Name: "R&D", ManagerEmployeeID: "user_ada"},
		},
		Employees: []orgsource.Employee{
			{ID: "user_ada", DisplayName: "Ada", Email: "ada@example.test", Phone: "+8613800000000", DepartmentIDs: []string{"dept_rd", "dept_rd"}},
		},
		Memberships: []orgsource.Membership{
			{EmployeeID: "user_ada", DepartmentID: "dept_rd", Role: orgsource.RoleManager},
		},
	}

	result, err := service.ConfirmOrgImport(ctx, ConfirmOrgImportInput{
		EnterpriseID:   "ent_1",
		EnterpriseName: "Enterprise 1",
		Provider:       ProviderWeCom,
		SourceHash:     "sha256:source",
		Snapshot:       snapshot,
	})
	if err != nil {
		t.Fatalf("ConfirmOrgImport returned error: %v", err)
	}
	if result.OrgVersion.ID != "version_1" || result.OrgVersion.VersionNumber != 1 {
		t.Fatalf("org version = %+v, want version_1 number 1", result.OrgVersion)
	}
	if result.ImportedDepartments != 2 || result.ImportedEmployees != 1 || result.ImportedMemberships != 1 {
		t.Fatalf("result counts = %+v", result)
	}

	graph, err := service.GetOrgGraph(ctx, "ent_1")
	if err != nil {
		t.Fatalf("GetOrgGraph returned error: %v", err)
	}
	if len(graph.Departments) != 2 || len(graph.Users) != 1 || len(graph.Memberships) != 1 || len(graph.ExternalIdentities) != 4 {
		t.Fatalf("graph = %+v", graph)
	}
	if graph.ExternalIdentities[0].Provider == "" {
		t.Fatalf("expected external identities to include providers")
	}
}

func TestOrgImportServiceRequiresConfirmationForConflicts(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMemoryStore())
	snapshot := orgsource.Snapshot{
		Employees: []orgsource.Employee{
			{ID: "user_1", DisplayName: "One", Email: "same@example.test"},
			{ID: "user_2", DisplayName: "Two", Email: "same@example.test"},
		},
	}

	_, err := service.ConfirmOrgImport(ctx, ConfirmOrgImportInput{
		EnterpriseID:   "ent_1",
		EnterpriseName: "Enterprise 1",
		Provider:       ProviderOAHTTP,
		SourceHash:     "sha256:source",
		Snapshot:       snapshot,
	})
	if err != ErrOrgImportConfirmationRequired {
		t.Fatalf("error = %v, want ErrOrgImportConfirmationRequired", err)
	}

	if _, err := service.ConfirmOrgImport(ctx, ConfirmOrgImportInput{
		EnterpriseID:        "ent_1",
		EnterpriseName:      "Enterprise 1",
		Provider:            ProviderOAHTTP,
		SourceHash:          "sha256:source",
		HumanConfirmationID: "confirmation_1",
		Snapshot:            snapshot,
	}); err != nil {
		t.Fatalf("confirmed import returned error: %v", err)
	}
}
