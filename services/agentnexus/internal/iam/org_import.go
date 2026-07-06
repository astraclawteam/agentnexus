package iam

import "context"

type Service struct {
	store Store
	newID func() string
}

type Option func(*Service)

func NewService(store Store, opts ...Option) *Service {
	service := &Service{
		store: store,
		newID: func() string {
			return "generated_id"
		},
	}
	for _, opt := range opts {
		opt(service)
	}
	return service
}

func WithIDGenerator(newID func() string) Option {
	return func(service *Service) {
		service.newID = newID
	}
}

func (s *Service) CreateEnterprise(ctx context.Context, input CreateEnterpriseInput) (Enterprise, error) {
	return s.store.CreateEnterprise(ctx, Enterprise{
		ID:   input.ID,
		Name: input.Name,
	})
}

func (s *Service) UpsertEnterpriseUser(ctx context.Context, input UpsertEnterpriseUserInput) (EnterpriseUser, error) {
	return s.store.UpsertEnterpriseUser(ctx, EnterpriseUser{
		ID:           input.ID,
		EnterpriseID: input.EnterpriseID,
		DisplayName:  input.DisplayName,
		Email:        input.Email,
		Phone:        input.Phone,
	})
}

func (s *Service) BindExternalIdentity(ctx context.Context, input BindExternalIdentityInput) (ExternalIdentity, error) {
	return s.store.BindExternalIdentity(ctx, ExternalIdentity{
		ID:               input.ID,
		EnterpriseID:     input.EnterpriseID,
		EnterpriseUserID: input.EnterpriseUserID,
		Provider:         input.Provider,
		ExternalSubject:  input.ExternalSubject,
	})
}

func (s *Service) UpsertOrgUnit(ctx context.Context, input UpsertOrgUnitInput) (OrgUnit, error) {
	return s.store.UpsertOrgUnit(ctx, OrgUnit{
		ID:           input.ID,
		EnterpriseID: input.EnterpriseID,
		ParentID:     input.ParentID,
		Name:         input.Name,
		UnitType:     input.UnitType,
	})
}

func (s *Service) AddOrgMembership(ctx context.Context, input AddOrgMembershipInput) (OrgMembership, error) {
	role := input.Role
	if role == "" {
		role = OrgRoleMember
	}
	return s.store.AddOrgMembership(ctx, OrgMembership{
		EnterpriseID:     input.EnterpriseID,
		EnterpriseUserID: input.EnterpriseUserID,
		OrgUnitID:        input.OrgUnitID,
		Role:             role,
	})
}

func (s *Service) CreateOrgVersion(ctx context.Context, input CreateOrgVersionInput) (OrgVersion, error) {
	event, err := s.store.CreateOrgEvent(ctx, OrgEvent{
		ID:           s.newID(),
		EnterpriseID: input.EnterpriseID,
		EventType:    "org_import",
		SourceHash:   input.SourceHash,
	})
	if err != nil {
		return OrgVersion{}, err
	}
	return s.store.CreateOrgVersion(ctx, OrgVersion{
		ID:            s.newID(),
		EnterpriseID:  input.EnterpriseID,
		VersionNumber: input.VersionNumber,
		SourceEventID: event.ID,
	})
}
