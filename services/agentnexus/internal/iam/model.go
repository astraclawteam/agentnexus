package iam

import "time"

type OrgUnitType string

const (
	OrgUnitTypeDepartment   OrgUnitType = "department"
	OrgUnitTypeProjectGroup OrgUnitType = "project_group"
)

type OrgRole string

const (
	OrgRoleMember  OrgRole = "member"
	OrgRoleManager OrgRole = "manager"
)

type Enterprise struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

type EnterpriseUser struct {
	ID           string
	EnterpriseID string
	DisplayName  string
	Email        string
	Phone        string
	CreatedAt    time.Time
}

type ExternalIdentity struct {
	ID               string
	EnterpriseID     string
	EnterpriseUserID string
	Provider         string
	ExternalSubject  string
	CreatedAt        time.Time
}

type OrgUnit struct {
	ID           string
	EnterpriseID string
	ParentID     string
	Name         string
	UnitType     OrgUnitType
	CreatedAt    time.Time
}

type OrgMembership struct {
	EnterpriseID     string
	EnterpriseUserID string
	OrgUnitID        string
	Role             OrgRole
	CreatedAt        time.Time
}

type OrgEvent struct {
	ID           string
	EnterpriseID string
	EventType    string
	SourceHash   string
	CreatedAt    time.Time
}

type OrgVersion struct {
	ID            string
	EnterpriseID  string
	VersionNumber int64
	SourceEventID string
	CreatedAt     time.Time
}

type CreateEnterpriseInput struct {
	ID   string
	Name string
}

type UpsertEnterpriseUserInput struct {
	ID           string
	EnterpriseID string
	DisplayName  string
	Email        string
	Phone        string
}

type BindExternalIdentityInput struct {
	ID               string
	EnterpriseID     string
	EnterpriseUserID string
	Provider         string
	ExternalSubject  string
}

type UpsertOrgUnitInput struct {
	ID           string
	EnterpriseID string
	ParentID     string
	Name         string
	UnitType     OrgUnitType
}

type AddOrgMembershipInput struct {
	EnterpriseID     string
	EnterpriseUserID string
	OrgUnitID        string
	Role             OrgRole
}

type CreateOrgVersionInput struct {
	EnterpriseID  string
	VersionNumber int64
	SourceHash    string
}
