package iam

import (
	"context"
	"errors"
	"strings"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
)

var ErrOrgImportConfirmationRequired = errors.New("org import confirmation required")

type ConfirmOrgImportInput struct {
	EnterpriseID        string
	EnterpriseName      string
	Provider            string
	SourceHash          string
	HumanConfirmationID string
	Snapshot            orgsource.Snapshot
}

type ConfirmOrgImportResult struct {
	OrgVersion          OrgVersion
	ImportedDepartments int
	ImportedEmployees   int
	ImportedMemberships int
}

func (s *Service) ConfirmOrgImport(ctx context.Context, input ConfirmOrgImportInput) (ConfirmOrgImportResult, error) {
	preview := orgsource.PreviewImport(input.Snapshot)
	if preview.RequiresConfirmation && input.HumanConfirmationID == "" {
		return ConfirmOrgImportResult{}, ErrOrgImportConfirmationRequired
	}

	snapshot := orgsource.NormalizeSnapshot(input.Snapshot)
	if _, err := s.CreateEnterprise(ctx, CreateEnterpriseInput{
		ID:   input.EnterpriseID,
		Name: input.EnterpriseName,
	}); err != nil {
		return ConfirmOrgImportResult{}, err
	}

	if err := s.importDepartments(ctx, input.EnterpriseID, snapshot.Departments); err != nil {
		return ConfirmOrgImportResult{}, err
	}
	explicitMemberships := map[string]struct{}{}
	for _, membership := range snapshot.Memberships {
		explicitMemberships[membership.EmployeeID+":"+membership.DepartmentID] = struct{}{}
	}
	importedMemberships := map[string]struct{}{}
	for _, employee := range snapshot.Employees {
		if _, err := s.UpsertEnterpriseUser(ctx, UpsertEnterpriseUserInput{
			ID:           employee.ID,
			EnterpriseID: input.EnterpriseID,
			DisplayName:  employee.DisplayName,
			Email:        employee.Email,
			Phone:        employee.Phone,
		}); err != nil {
			return ConfirmOrgImportResult{}, err
		}
		if err := s.bindImportIdentities(ctx, input.EnterpriseID, input.Provider, employee); err != nil {
			return ConfirmOrgImportResult{}, err
		}
		for _, departmentID := range employee.DepartmentIDs {
			if _, ok := explicitMemberships[employee.ID+":"+departmentID]; ok {
				continue
			}
			if _, err := s.AddOrgMembership(ctx, AddOrgMembershipInput{
				EnterpriseID:     input.EnterpriseID,
				EnterpriseUserID: employee.ID,
				OrgUnitID:        departmentID,
				Role:             OrgRoleMember,
			}); err != nil {
				return ConfirmOrgImportResult{}, err
			}
			importedMemberships[employee.ID+":"+departmentID] = struct{}{}
		}
	}
	for _, membership := range snapshot.Memberships {
		if _, err := s.AddOrgMembership(ctx, AddOrgMembershipInput{
			EnterpriseID:     input.EnterpriseID,
			EnterpriseUserID: membership.EmployeeID,
			OrgUnitID:        membership.DepartmentID,
			Role:             orgImportRole(membership.Role),
		}); err != nil {
			return ConfirmOrgImportResult{}, err
		}
		importedMemberships[membership.EmployeeID+":"+membership.DepartmentID] = struct{}{}
	}

	versionNumber, err := s.store.NextOrgVersionNumber(ctx, input.EnterpriseID)
	if err != nil {
		return ConfirmOrgImportResult{}, err
	}
	version, err := s.CreateOrgVersion(ctx, CreateOrgVersionInput{
		EnterpriseID:  input.EnterpriseID,
		VersionNumber: versionNumber,
		SourceHash:    input.SourceHash,
	})
	if err != nil {
		return ConfirmOrgImportResult{}, err
	}

	return ConfirmOrgImportResult{
		OrgVersion:          version,
		ImportedDepartments: len(snapshot.Departments),
		ImportedEmployees:   len(snapshot.Employees),
		ImportedMemberships: len(importedMemberships),
	}, nil
}

func (s *Service) importDepartments(ctx context.Context, enterpriseID string, departments []orgsource.Department) error {
	imported := map[string]struct{}{}
	for len(imported) < len(departments) {
		progress := false
		for _, department := range departments {
			if _, ok := imported[department.ID]; ok {
				continue
			}
			if department.ParentID != "" {
				if _, ok := imported[department.ParentID]; !ok {
					continue
				}
			}
			if _, err := s.UpsertOrgUnit(ctx, UpsertOrgUnitInput{
				ID:           department.ID,
				EnterpriseID: enterpriseID,
				ParentID:     department.ParentID,
				Name:         department.Name,
				UnitType:     OrgUnitTypeDepartment,
			}); err != nil {
				return err
			}
			imported[department.ID] = struct{}{}
			progress = true
		}
		if !progress {
			for _, department := range departments {
				if _, ok := imported[department.ID]; ok {
					continue
				}
				if _, err := s.UpsertOrgUnit(ctx, UpsertOrgUnitInput{
					ID:           department.ID,
					EnterpriseID: enterpriseID,
					ParentID:     "",
					Name:         department.Name,
					UnitType:     OrgUnitTypeDepartment,
				}); err != nil {
					return err
				}
				imported[department.ID] = struct{}{}
			}
		}
	}
	return nil
}

func (s *Service) bindImportIdentities(ctx context.Context, enterpriseID, provider string, employee orgsource.Employee) error {
	if provider == "" {
		provider = ProviderOAHTTP
	}
	candidates := []struct {
		provider string
		subject  string
	}{
		{provider: provider, subject: employee.ID},
		{provider: ProviderEmail, subject: strings.TrimSpace(employee.Email)},
		{provider: ProviderPhone, subject: strings.TrimSpace(employee.Phone)},
		{provider: ProviderLLMRouter, subject: employee.ID},
	}
	for _, candidate := range candidates {
		if candidate.subject == "" {
			continue
		}
		if _, err := s.BindExternalIdentity(ctx, BindExternalIdentityInput{
			ID:               s.newID(),
			EnterpriseID:     enterpriseID,
			EnterpriseUserID: employee.ID,
			Provider:         candidate.provider,
			ExternalSubject:  candidate.subject,
		}); err != nil {
			return err
		}
	}
	return nil
}

func orgImportRole(role orgsource.Role) OrgRole {
	if role == orgsource.RoleManager {
		return OrgRoleManager
	}
	return OrgRoleMember
}
