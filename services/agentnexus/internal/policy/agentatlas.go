package policy

import (
	"context"
	"errors"
	"sort"
	"sync"
)

type AtlasPermission string

const (
	PermissionSuggest          AtlasPermission = "suggest"
	PermissionEdit             AtlasPermission = "edit"
	PermissionPublishLowRisk   AtlasPermission = "publish_low_risk"
	PermissionApproveHighRisk  AtlasPermission = "approve_high_risk"
	PermissionWorkflowEdit     AtlasPermission = "workflow_edit"
	PermissionWorkflowAdvanced AtlasPermission = "workflow_advanced"
	PermissionServiceMode      AtlasPermission = "service_mode"
)

type ResourceType string

const (
	ResourceKnowledge ResourceType = "knowledge"
	ResourceWorkflow  ResourceType = "workflow"
	ResourceService   ResourceType = "service"
)

type AtlasAction string

const (
	ActionKnowledgeSuggest         AtlasAction = "knowledge.suggest"
	ActionKnowledgeCreate          AtlasAction = "knowledge.create"
	ActionKnowledgeUpdate          AtlasAction = "knowledge.update"
	ActionKnowledgePublishLowRisk  AtlasAction = "knowledge.publish_low_risk"
	ActionKnowledgeApproveHighRisk AtlasAction = "knowledge.approve_high_risk"
	ActionWorkflowEdit             AtlasAction = "workflow.edit"
	ActionWorkflowEditAdvanced     AtlasAction = "workflow.edit_advanced"
	ActionServiceMode              AtlasAction = "service.mode"
)

type AtlasRiskLevel string

const (
	AtlasRiskLow    AtlasRiskLevel = "low"
	AtlasRiskMedium AtlasRiskLevel = "medium"
	AtlasRiskHigh   AtlasRiskLevel = "high"
)

type actionRequirement struct {
	resourceType ResourceType
	permission   AtlasPermission
	baselineRisk AtlasRiskLevel
}

var actionRequirements = map[AtlasAction]actionRequirement{
	ActionKnowledgeSuggest:         {resourceType: ResourceKnowledge, permission: PermissionSuggest, baselineRisk: AtlasRiskLow},
	ActionKnowledgeCreate:          {resourceType: ResourceKnowledge, permission: PermissionEdit, baselineRisk: AtlasRiskMedium},
	ActionKnowledgeUpdate:          {resourceType: ResourceKnowledge, permission: PermissionEdit, baselineRisk: AtlasRiskMedium},
	ActionKnowledgePublishLowRisk:  {resourceType: ResourceKnowledge, permission: PermissionPublishLowRisk, baselineRisk: AtlasRiskLow},
	ActionKnowledgeApproveHighRisk: {resourceType: ResourceKnowledge, permission: PermissionApproveHighRisk, baselineRisk: AtlasRiskHigh},
	ActionWorkflowEdit:             {resourceType: ResourceWorkflow, permission: PermissionWorkflowEdit, baselineRisk: AtlasRiskMedium},
	ActionWorkflowEditAdvanced:     {resourceType: ResourceWorkflow, permission: PermissionWorkflowAdvanced, baselineRisk: AtlasRiskHigh},
	ActionServiceMode:              {resourceType: ResourceService, permission: PermissionServiceMode, baselineRisk: AtlasRiskHigh},
}

func RequiredPermission(resourceType ResourceType, action AtlasAction) (AtlasPermission, AtlasRiskLevel, bool) {
	requirement, ok := actionRequirements[action]
	if !ok || requirement.resourceType != resourceType {
		return "", AtlasRiskHigh, false
	}
	return requirement.permission, requirement.baselineRisk, true
}

type AtlasMembership struct {
	OrgUnitID string
	Role      string
}

type AtlasOrgUnit struct {
	ID       string
	ParentID string
}

type AtlasAccessSnapshot struct {
	EnterpriseID string
	OrgVersion   int64
	Memberships  []AtlasMembership
	OrgUnits     []AtlasOrgUnit
}

type AtlasPolicySource interface {
	LoadAccessSnapshot(context.Context, string, string) (AtlasAccessSnapshot, error)
}

type ScopedRequest struct {
	EnterpriseID string
	ActorUserID  string
	OrgUnitID    string
	OrgVersion   int64
	ResourceType ResourceType
	ResourceID   string
	Action       AtlasAction
}

type PermissionDecision struct {
	Decision       Decision          `json:"decision"`
	Permissions    []AtlasPermission `json:"permissions"`
	OrgUnitIDs     []string          `json:"org_unit_ids"`
	MaskFields     []string          `json:"mask_fields"`
	RiskLevel      AtlasRiskLevel    `json:"risk_level"`
	FallbackAction AtlasAction       `json:"fallback_action,omitempty"`
	OrgVersion     int64             `json:"org_version"`
}

var ErrAtlasPolicyUnavailable = errors.New("agentatlas policy unavailable")

type AgentAtlasEvaluator struct {
	source AtlasPolicySource
}

func NewAgentAtlasEvaluator(source AtlasPolicySource) *AgentAtlasEvaluator {
	return &AgentAtlasEvaluator{source: source}
}

func (e *AgentAtlasEvaluator) Evaluate(ctx context.Context, req ScopedRequest) (PermissionDecision, error) {
	requiredPermission, baselineRisk, known := RequiredPermission(req.ResourceType, req.Action)
	if !known {
		baselineRisk = AtlasRiskHigh
	}
	if e == nil || e.source == nil || req.EnterpriseID == "" || req.ActorUserID == "" {
		return PermissionDecision{}, ErrAtlasPolicyUnavailable
	}

	snapshot, err := e.source.LoadAccessSnapshot(ctx, req.EnterpriseID, req.ActorUserID)
	if err != nil {
		return PermissionDecision{}, errors.Join(ErrAtlasPolicyUnavailable, err)
	}
	if snapshot.EnterpriseID != req.EnterpriseID || snapshot.OrgVersion < 1 {
		return PermissionDecision{}, ErrAtlasPolicyUnavailable
	}

	decision := deniedAtlasDecision(snapshot.OrgVersion, baselineRisk)
	if req.OrgVersion != snapshot.OrgVersion || req.OrgUnitID == "" || req.ResourceID == "" || !known {
		return decision, nil
	}

	parents, valid := validatedAtlasGraph(snapshot)
	if !valid {
		return decision, nil
	}
	if _, ok := parents[req.OrgUnitID]; !ok {
		return decision, nil
	}

	grantedScopes := atlasGrantedScopes(snapshot.Memberships, parents, req.OrgUnitID, requiredPermission)
	if len(grantedScopes) > 0 {
		decision.Decision = DecisionAllow
		decision.Permissions = []AtlasPermission{requiredPermission}
		decision.OrgUnitIDs = grantedScopes
		return decision, nil
	}

	if req.Action == ActionKnowledgeUpdate {
		fallbackScopes := atlasGrantedScopes(snapshot.Memberships, parents, req.OrgUnitID, PermissionSuggest)
		if len(fallbackScopes) > 0 {
			decision.Permissions = []AtlasPermission{PermissionSuggest}
			decision.OrgUnitIDs = fallbackScopes
			decision.FallbackAction = ActionKnowledgeSuggest
		}
	}
	return decision, nil
}

func deniedAtlasDecision(orgVersion int64, risk AtlasRiskLevel) PermissionDecision {
	return PermissionDecision{
		Decision:    DecisionDeny,
		Permissions: []AtlasPermission{},
		OrgUnitIDs:  []string{},
		MaskFields:  []string{},
		RiskLevel:   risk,
		OrgVersion:  orgVersion,
	}
}

func validatedAtlasGraph(snapshot AtlasAccessSnapshot) (map[string]string, bool) {
	parents := make(map[string]string, len(snapshot.OrgUnits))
	for _, unit := range snapshot.OrgUnits {
		if unit.ID == "" {
			return nil, false
		}
		if _, exists := parents[unit.ID]; exists {
			return nil, false
		}
		parents[unit.ID] = unit.ParentID
	}
	for id, parentID := range parents {
		if parentID != "" {
			if _, exists := parents[parentID]; !exists {
				return nil, false
			}
		}
		seen := map[string]struct{}{id: {}}
		for cursor := parentID; cursor != ""; cursor = parents[cursor] {
			if _, exists := seen[cursor]; exists {
				return nil, false
			}
			seen[cursor] = struct{}{}
		}
	}
	for _, membership := range snapshot.Memberships {
		if _, exists := parents[membership.OrgUnitID]; !exists {
			return nil, false
		}
	}
	return parents, true
}

func atlasGrantedScopes(memberships []AtlasMembership, parents map[string]string, targetOrgUnitID string, permission AtlasPermission) []string {
	covered := map[string]struct{}{}
	for _, membership := range memberships {
		if atlasPermissionForRole(membership.Role) != permission || !atlasScopeCovers(parents, membership.OrgUnitID, targetOrgUnitID) {
			continue
		}
		covered[membership.OrgUnitID] = struct{}{}
	}
	result := make([]string, 0, len(covered))
	for orgUnitID := range covered {
		result = append(result, orgUnitID)
	}
	sort.Strings(result)
	return result
}

func atlasScopeCovers(parents map[string]string, grantedOrgUnitID, targetOrgUnitID string) bool {
	for cursor := targetOrgUnitID; cursor != ""; cursor = parents[cursor] {
		if cursor == grantedOrgUnitID {
			return true
		}
	}
	return false
}

func atlasPermissionForRole(role string) AtlasPermission {
	if role == "member" {
		return PermissionSuggest
	}
	permission := AtlasPermission(role)
	switch permission {
	case PermissionSuggest, PermissionEdit, PermissionPublishLowRisk, PermissionApproveHighRisk, PermissionWorkflowEdit, PermissionWorkflowAdvanced, PermissionServiceMode:
		return permission
	default:
		return ""
	}
}

type MemoryAtlasPolicySource struct {
	mu        sync.RWMutex
	snapshots map[string]AtlasAccessSnapshot
}

func NewMemoryAtlasPolicySource() *MemoryAtlasPolicySource {
	return &MemoryAtlasPolicySource{snapshots: map[string]AtlasAccessSnapshot{}}
}

func (s *MemoryAtlasPolicySource) StoreSnapshot(enterpriseID, actorUserID string, snapshot AtlasAccessSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[atlasSnapshotKey(enterpriseID, actorUserID)] = cloneAccessSnapshot(snapshot)
}

func (s *MemoryAtlasPolicySource) LoadAccessSnapshot(ctx context.Context, enterpriseID, actorUserID string) (AtlasAccessSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return AtlasAccessSnapshot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot, ok := s.snapshots[atlasSnapshotKey(enterpriseID, actorUserID)]
	if !ok {
		return AtlasAccessSnapshot{}, ErrAtlasPolicyUnavailable
	}
	return cloneAccessSnapshot(snapshot), nil
}

func cloneAccessSnapshot(snapshot AtlasAccessSnapshot) AtlasAccessSnapshot {
	snapshot.OrgUnits = append([]AtlasOrgUnit(nil), snapshot.OrgUnits...)
	snapshot.Memberships = append([]AtlasMembership(nil), snapshot.Memberships...)
	return snapshot
}

func atlasSnapshotKey(enterpriseID, actorUserID string) string {
	return enterpriseID + "\x00" + actorUserID
}
