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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type EnterpriseUser struct {
	ID           string    `json:"id"`
	EnterpriseID string    `json:"enterprise_id"`
	DisplayName  string    `json:"display_name"`
	Email        string    `json:"email"`
	Phone        string    `json:"phone"`
	CreatedAt    time.Time `json:"created_at"`
}

type ExternalIdentity struct {
	ID               string    `json:"id"`
	EnterpriseID     string    `json:"enterprise_id"`
	EnterpriseUserID string    `json:"enterprise_user_id"`
	Provider         string    `json:"provider"`
	ExternalSubject  string    `json:"external_subject"`
	CreatedAt        time.Time `json:"created_at"`
}

type OrgUnit struct {
	ID           string      `json:"id"`
	EnterpriseID string      `json:"enterprise_id"`
	ParentID     string      `json:"parent_id"`
	Name         string      `json:"name"`
	UnitType     OrgUnitType `json:"unit_type"`
	CreatedAt    time.Time   `json:"created_at"`
}

type OrgMembership struct {
	EnterpriseID     string    `json:"enterprise_id"`
	EnterpriseUserID string    `json:"enterprise_user_id"`
	OrgUnitID        string    `json:"org_unit_id"`
	Role             OrgRole   `json:"role"`
	CreatedAt        time.Time `json:"created_at"`
}

type OrgEvent struct {
	ID           string    `json:"id"`
	EnterpriseID string    `json:"enterprise_id"`
	EventType    string    `json:"event_type"`
	SourceHash   string    `json:"source_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type OrgVersion struct {
	ID            string    `json:"id"`
	EnterpriseID  string    `json:"enterprise_id"`
	VersionNumber int64     `json:"version_number"`
	SourceEventID string    `json:"source_event_id"`
	CreatedAt     time.Time `json:"created_at"`
}

const (
	ProviderOAHTTP    = "oa_http"
	ProviderWeCom     = "wecom"
	ProviderFeishu    = "feishu"
	ProviderDingTalk  = "dingtalk"
	ProviderEmail     = "email"
	ProviderPhone     = "phone"
	ProviderLLMRouter = "llmrouter"
)

type OrgGraph struct {
	Departments        []OrgUnit          `json:"departments"`
	Users              []EnterpriseUser   `json:"users"`
	Memberships        []OrgMembership    `json:"memberships"`
	ExternalIdentities []ExternalIdentity `json:"external_identities"`
	Versions           []OrgVersion       `json:"versions"`
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
