package iam

import (
	"context"
	"testing"
)

func TestEnterpriseIAMAndOrgGraphLifecycle(t *testing.T) {
	ctx := context.Background()
	service := NewService(
		NewMemoryStore(),
		WithIDGenerator(sequenceIDs("event_1", "version_1")),
	)

	enterprise, err := service.CreateEnterprise(ctx, CreateEnterpriseInput{
		ID:   "ent_1",
		Name: "Astraclaw",
	})
	if err != nil {
		t.Fatalf("CreateEnterprise returned error: %v", err)
	}
	if enterprise.ID != "ent_1" || enterprise.Name != "Astraclaw" {
		t.Fatalf("enterprise = %+v, want ent_1 Astraclaw", enterprise)
	}

	user, err := service.UpsertEnterpriseUser(ctx, UpsertEnterpriseUserInput{
		ID:           "user_1",
		EnterpriseID: "ent_1",
		DisplayName:  "Original Name",
		Email:        "original@example.com",
	})
	if err != nil {
		t.Fatalf("UpsertEnterpriseUser insert returned error: %v", err)
	}
	user, err = service.UpsertEnterpriseUser(ctx, UpsertEnterpriseUserInput{
		ID:           user.ID,
		EnterpriseID: user.EnterpriseID,
		DisplayName:  "Updated Name",
		Email:        "updated@example.com",
		Phone:        "+8613800000000",
	})
	if err != nil {
		t.Fatalf("UpsertEnterpriseUser update returned error: %v", err)
	}
	if user.DisplayName != "Updated Name" || user.Email != "updated@example.com" {
		t.Fatalf("user = %+v, want updated fields", user)
	}

	identity, err := service.BindExternalIdentity(ctx, BindExternalIdentityInput{
		ID:               "identity_1",
		EnterpriseID:     "ent_1",
		EnterpriseUserID: "user_1",
		Provider:         "wecom",
		ExternalSubject:  "external_user_1",
	})
	if err != nil {
		t.Fatalf("BindExternalIdentity returned error: %v", err)
	}
	if identity.Provider != "wecom" || identity.ExternalSubject != "external_user_1" {
		t.Fatalf("identity = %+v, want wecom external subject", identity)
	}

	department, err := service.UpsertOrgUnit(ctx, UpsertOrgUnitInput{
		ID:           "dept_legal",
		EnterpriseID: "ent_1",
		Name:         "Legal",
		UnitType:     OrgUnitTypeDepartment,
	})
	if err != nil {
		t.Fatalf("UpsertOrgUnit department returned error: %v", err)
	}
	if department.UnitType != OrgUnitTypeDepartment {
		t.Fatalf("department type = %q, want %q", department.UnitType, OrgUnitTypeDepartment)
	}

	projectGroup, err := service.UpsertOrgUnit(ctx, UpsertOrgUnitInput{
		ID:           "pg_contracts",
		EnterpriseID: "ent_1",
		ParentID:     "dept_legal",
		Name:         "Contracts",
		UnitType:     OrgUnitTypeProjectGroup,
	})
	if err != nil {
		t.Fatalf("UpsertOrgUnit project group returned error: %v", err)
	}
	if projectGroup.ParentID != "dept_legal" {
		t.Fatalf("projectGroup parent = %q, want dept_legal", projectGroup.ParentID)
	}

	membership, err := service.AddOrgMembership(ctx, AddOrgMembershipInput{
		EnterpriseID:     "ent_1",
		EnterpriseUserID: "user_1",
		OrgUnitID:        "dept_legal",
		Role:             OrgRoleManager,
	})
	if err != nil {
		t.Fatalf("AddOrgMembership returned error: %v", err)
	}
	if membership.Role != OrgRoleManager {
		t.Fatalf("membership role = %q, want %q", membership.Role, OrgRoleManager)
	}

	version, err := service.CreateOrgVersion(ctx, CreateOrgVersionInput{
		EnterpriseID:  "ent_1",
		VersionNumber: 1,
		SourceHash:    "sha256:org-source",
	})
	if err != nil {
		t.Fatalf("CreateOrgVersion returned error: %v", err)
	}
	if version.VersionNumber != 1 || version.SourceEventID != "event_1" {
		t.Fatalf("version = %+v, want version 1 from event_1", version)
	}
}

func sequenceIDs(ids ...string) func() string {
	index := 0
	return func() string {
		if index >= len(ids) {
			return "extra_id"
		}
		id := ids[index]
		index++
		return id
	}
}
