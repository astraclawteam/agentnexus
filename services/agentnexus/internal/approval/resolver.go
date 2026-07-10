package approval

import (
	"context"
	"errors"
	"sort"
	"strings"
)

const (
	MaxSnapshotOrgUnits           = 10_000
	MaxSnapshotPrincipals         = 100_000
	MaxSnapshotOrgDepth           = 256
	EnterpriseKnowledgeAdminQueue = "enterprise_knowledge_admin"
)

var ErrApprovalUnavailable = errors.New("approval unavailable")

type RouteMode string

const (
	ModeSingleConfirmation            RouteMode = "single_confirmation"
	ModeUpwardReview                  RouteMode = "upward_review"
	ModeEnterpriseKnowledgeAdminQueue RouteMode = "enterprise_knowledge_admin_queue"
)

type Permission string

const (
	PermissionPublishLowRisk  Permission = "publish_low_risk"
	PermissionApproveHighRisk Permission = "approve_high_risk"
	RoleManager                          = "manager"
)

type SnapshotUnit struct {
	ID       string
	ParentID string
}

type SnapshotMembership struct {
	UserID    string
	OrgUnitID string
	Role      string
}

type SnapshotUser struct {
	ID          string
	DisplayName string
}

type OrgSnapshot struct {
	enterpriseID string
	orgVersion   int64
	units        []SnapshotUnit
	memberships  []SnapshotMembership
	users        []SnapshotUser
}

func NewOrgSnapshot(enterpriseID string, orgVersion int64, units []SnapshotUnit, memberships []SnapshotMembership, users []SnapshotUser) (OrgSnapshot, error) {
	if !canonical(enterpriseID) || orgVersion < 1 || len(units) == 0 || len(units) > MaxSnapshotOrgUnits || len(memberships) > MaxSnapshotPrincipals || len(users) > MaxSnapshotPrincipals {
		return OrgSnapshot{}, ErrApprovalUnavailable
	}
	unitCopy := append([]SnapshotUnit(nil), units...)
	membershipCopy := append([]SnapshotMembership(nil), memberships...)
	userCopy := append([]SnapshotUser(nil), users...)
	parents := make(map[string]string, len(unitCopy))
	for _, unit := range unitCopy {
		if !canonical(unit.ID) || (unit.ParentID != "" && !canonical(unit.ParentID)) {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		if _, exists := parents[unit.ID]; exists {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		parents[unit.ID] = unit.ParentID
	}
	for _, parentID := range parents {
		if parentID != "" {
			if _, exists := parents[parentID]; !exists {
				return OrgSnapshot{}, ErrApprovalUnavailable
			}
		}
	}
	if !validParentGraph(parents) {
		return OrgSnapshot{}, ErrApprovalUnavailable
	}
	userIndex := make(map[string]string, len(userCopy))
	for _, user := range userCopy {
		if !canonical(user.ID) || !canonical(user.DisplayName) {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		if _, exists := userIndex[user.ID]; exists {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		userIndex[user.ID] = user.DisplayName
	}
	seenMemberships := make(map[string]struct{}, len(membershipCopy))
	for _, membership := range membershipCopy {
		if !canonical(membership.UserID) || !canonical(membership.OrgUnitID) || !knownSnapshotRole(membership.Role) {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		if _, exists := parents[membership.OrgUnitID]; !exists {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		if _, exists := userIndex[membership.UserID]; !exists {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		key := membership.UserID + "\x00" + membership.OrgUnitID + "\x00" + membership.Role
		if _, exists := seenMemberships[key]; exists {
			return OrgSnapshot{}, ErrApprovalUnavailable
		}
		seenMemberships[key] = struct{}{}
	}
	return OrgSnapshot{enterpriseID: enterpriseID, orgVersion: orgVersion, units: unitCopy, memberships: membershipCopy, users: userCopy}, nil
}

func validParentGraph(parents map[string]string) bool {
	colors := make(map[string]uint8, len(parents))
	for start := range parents {
		cursor := start
		path := make([]string, 0, MaxSnapshotOrgDepth)
		for cursor != "" && colors[cursor] != 2 {
			if colors[cursor] == 1 || len(path) >= MaxSnapshotOrgDepth {
				return false
			}
			colors[cursor] = 1
			path = append(path, cursor)
			cursor = parents[cursor]
		}
		for _, id := range path {
			colors[id] = 2
		}
	}
	return true
}

func knownSnapshotRole(role string) bool {
	if !canonical(role) {
		return false
	}
	switch role {
	case "member", RoleManager, "admin", "suggest", "edit", string(PermissionPublishLowRisk), string(PermissionApproveHighRisk), "workflow_edit", "workflow_advanced", "service_mode":
		return true
	default:
		return false
	}
}

type Request struct {
	EnterpriseID    string
	RequesterUserID string
	OrgVersion      int64
	OrgUnitID       string
	ResourceType    string
	ResourceID      string
	Action          string
	Facts           VerifiedChangeFacts
	RequestedRisk   RiskLevel
	PolicyVersion   int64
	IdempotencyHash string
	ReplayHash      string
}

type Route struct {
	Mode                        RouteMode    `json:"mode"`
	RiskLevel                   RiskLevel    `json:"risk_level"`
	RiskReasons                 []RiskReason `json:"risk_reasons"`
	RequesterUserID             string       `json:"requester_user_id"`
	ReviewerUserID              string       `json:"reviewer_user_id,omitempty"`
	ReviewerDisplayName         string       `json:"reviewer_display_name,omitempty"`
	OrgPath                     []string     `json:"org_path"`
	Queue                       string       `json:"queue,omitempty"`
	AutoPublish                 bool         `json:"auto_publish"`
	PolicyVersion               int64        `json:"policy_version"`
	AdminRootReached            bool         `json:"-"`
	ReviewerPermission          Permission   `json:"-"`
	ReviewerPermissionOrgUnitID string       `json:"-"`
}

type Resolver struct {
	policy  Policy
	observe func(string)
}

func NewIndexedResolver(policy Policy) *Resolver { return &Resolver{policy: policy} }

func (r *Resolver) Resolve(ctx context.Context, req Request, snapshot OrgSnapshot) (Route, error) {
	if err := ctx.Err(); err != nil {
		return Route{}, errors.Join(ErrApprovalUnavailable, err)
	}
	if r == nil || !canonicalRequest(req) || snapshot.enterpriseID != req.EnterpriseID || snapshot.orgVersion != req.OrgVersion {
		return Route{}, ErrApprovalUnavailable
	}
	parents := make(map[string]string, len(snapshot.units))
	for _, unit := range snapshot.units {
		parents[unit.ID] = unit.ParentID
	}
	if _, exists := parents[req.OrgUnitID]; !exists {
		return Route{}, ErrApprovalUnavailable
	}
	for _, impacted := range req.Facts.ImpactedOrgUnitIDs() {
		if _, exists := parents[impacted]; !exists {
			return Route{}, ErrApprovalUnavailable
		}
	}
	assessment, err := ClassifyVerifiedRisk(req.Facts, req.RequestedRisk, req.ResourceType, req.Action, r.policy)
	if err != nil {
		return Route{}, ErrApprovalUnavailable
	}
	base := Route{RiskLevel: assessment.Level, RiskReasons: append([]RiskReason{}, assessment.Reasons...), RequesterUserID: req.RequesterUserID, OrgPath: []string{}, AutoPublish: false, PolicyVersion: req.PolicyVersion}
	permissionIndex := newSnapshotPermissionIndex(snapshot, parents, req.OrgUnitID, r.observe)
	permission := PermissionApproveHighRisk
	if assessment.Level == RiskLow {
		permission = PermissionPublishLowRisk
		_, allowed := permissionIndex.allows(req.RequesterUserID, permission)
		if allowed {
			base.RiskReasons = append(base.RiskReasons, RiskReasonExplicitConfirmation)
			sort.Slice(base.RiskReasons, func(i, j int) bool { return base.RiskReasons[i] < base.RiskReasons[j] })
			base.Mode = ModeSingleConfirmation
			base.OrgPath = []string{req.OrgUnitID}
			return base, nil
		}
		base.RiskReasons = append(base.RiskReasons, RiskReasonExplicitReviewRequired)
		sort.Slice(base.RiskReasons, func(i, j int) bool { return base.RiskReasons[i] < base.RiskReasons[j] })
	}

	candidates := make(map[string][]string)
	displayNames := make(map[string]string, len(snapshot.users))
	for _, user := range snapshot.users {
		displayNames[user.ID] = user.DisplayName
	}
	for _, membership := range snapshot.memberships {
		if membership.Role == RoleManager {
			candidates[membership.OrgUnitID] = append(candidates[membership.OrgUnitID], membership.UserID)
		}
	}
	for unitID := range candidates {
		sort.Strings(candidates[unitID])
	}
	path := make([]string, 0, MaxSnapshotOrgDepth)
	for unitID := req.OrgUnitID; unitID != ""; unitID = parents[unitID] {
		if err := ctx.Err(); err != nil {
			return Route{}, errors.Join(ErrApprovalUnavailable, err)
		}
		path = append(path, unitID)
		for _, candidateID := range candidates[unitID] {
			if r.observe != nil {
				r.observe("candidate")
			}
			if candidateID == req.RequesterUserID {
				continue
			}
			permissionScope, allowed := permissionIndex.allows(candidateID, permission)
			if allowed {
				base.Mode = ModeUpwardReview
				base.ReviewerUserID = candidateID
				base.ReviewerDisplayName = displayNames[candidateID]
				base.ReviewerPermission = permission
				base.ReviewerPermissionOrgUnitID = permissionScope
				base.OrgPath = append([]string{}, path...)
				return base, nil
			}
		}
	}
	base.Mode = ModeEnterpriseKnowledgeAdminQueue
	base.Queue = EnterpriseKnowledgeAdminQueue
	base.OrgPath = append([]string{}, path...)
	base.AdminRootReached = true
	return base, nil
}

type snapshotPermissionGrant struct {
	scope string
	depth int
}
type snapshotPermissionIndex map[string]map[Permission]snapshotPermissionGrant

func newSnapshotPermissionIndex(snapshot OrgSnapshot, parents map[string]string, targetUnitID string, observe func(string)) snapshotPermissionIndex {
	ancestors := make(map[string]int, MaxSnapshotOrgDepth)
	depth := 0
	for cursor := targetUnitID; cursor != ""; cursor = parents[cursor] {
		ancestors[cursor] = depth
		depth++
	}
	index := make(snapshotPermissionIndex)
	for _, membership := range snapshot.memberships {
		if observe != nil {
			observe("membership")
		}
		permission := Permission(membership.Role)
		if permission != PermissionPublishLowRisk && permission != PermissionApproveHighRisk {
			continue
		}
		grantDepth, covers := ancestors[membership.OrgUnitID]
		if !covers {
			continue
		}
		if index[membership.UserID] == nil {
			index[membership.UserID] = make(map[Permission]snapshotPermissionGrant)
		}
		existing, exists := index[membership.UserID][permission]
		if !exists || grantDepth < existing.depth {
			index[membership.UserID][permission] = snapshotPermissionGrant{scope: membership.OrgUnitID, depth: grantDepth}
		}
	}
	return index
}

func (i snapshotPermissionIndex) allows(userID string, permission Permission) (string, bool) {
	grant, ok := i[userID][permission]
	return grant.scope, ok
}

func canonicalRequest(req Request) bool {
	return req.OrgVersion > 0 && canonical(req.EnterpriseID) && canonical(req.RequesterUserID) && canonical(req.OrgUnitID) && canonical(req.ResourceType) && canonical(req.ResourceID) && canonical(req.Action)
}

func canonical(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}
