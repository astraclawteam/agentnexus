package policy

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
)

const (
	MaxAtlasOrgUnits    = 10_000
	MaxAtlasMemberships = 100_000
	MaxAtlasOrgDepth    = 256
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
	if e == nil || e.source == nil || !atlasCanonicalNonEmpty(req.EnterpriseID) || !atlasCanonicalNonEmpty(req.ActorUserID) {
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
	if req.OrgVersion != snapshot.OrgVersion || !atlasCanonicalNonEmpty(req.OrgUnitID) || !atlasCanonicalNonEmpty(string(req.ResourceType)) || !atlasCanonicalNonEmpty(req.ResourceID) || !atlasCanonicalNonEmpty(string(req.Action)) || !known {
		return decision, nil
	}

	analysis, valid, err := analyzeAtlasSnapshot(ctx, snapshot, req.OrgUnitID, requiredPermission, nil)
	if err != nil {
		return PermissionDecision{}, errors.Join(ErrAtlasPolicyUnavailable, err)
	}
	if !valid {
		return decision, nil
	}

	if len(analysis.requiredScopes) > 0 {
		decision.Decision = DecisionAllow
		decision.Permissions = []AtlasPermission{requiredPermission}
		decision.OrgUnitIDs = analysis.requiredScopes
		return decision, nil
	}

	if req.Action == ActionKnowledgeUpdate && len(analysis.suggestScopes) > 0 {
		decision.Permissions = []AtlasPermission{PermissionSuggest}
		decision.OrgUnitIDs = analysis.suggestScopes
		decision.FallbackAction = ActionKnowledgeSuggest
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

type atlasGraphWork string

const (
	atlasGraphWorkUnit       atlasGraphWork = "unit"
	atlasGraphWorkParent     atlasGraphWork = "parent"
	atlasGraphWorkMembership atlasGraphWork = "membership"
	atlasGraphWorkAncestor   atlasGraphWork = "ancestor"
)

type atlasScopeAnalysis struct {
	requiredScopes []string
	suggestScopes  []string
}

func analyzeAtlasSnapshot(ctx context.Context, snapshot AtlasAccessSnapshot, targetOrgUnitID string, requiredPermission AtlasPermission, observe func(atlasGraphWork)) (atlasScopeAnalysis, bool, error) {
	empty := atlasScopeAnalysis{requiredScopes: []string{}, suggestScopes: []string{}}
	if len(snapshot.OrgUnits) > MaxAtlasOrgUnits || len(snapshot.Memberships) > MaxAtlasMemberships {
		return empty, false, nil
	}
	if err := ctx.Err(); err != nil {
		return empty, false, err
	}

	parents := make(map[string]string, len(snapshot.OrgUnits))
	for _, unit := range snapshot.OrgUnits {
		if err := ctx.Err(); err != nil {
			return empty, false, err
		}
		if !atlasCanonicalNonEmpty(unit.ID) || (unit.ParentID != "" && !atlasCanonicalNonEmpty(unit.ParentID)) {
			return empty, false, nil
		}
		if _, exists := parents[unit.ID]; exists {
			return empty, false, nil
		}
		parents[unit.ID] = unit.ParentID
		if observe != nil {
			observe(atlasGraphWorkUnit)
		}
	}

	colors := make(map[string]uint8, len(parents))
	depths := make(map[string]int, len(parents))
	for id := range parents {
		if colors[id] == 2 {
			continue
		}
		path := make([]string, 0)
		cursor := id
		baseDepth := 0
		for cursor != "" {
			if err := ctx.Err(); err != nil {
				return empty, false, err
			}
			if observe != nil {
				observe(atlasGraphWorkParent)
			}
			parentID, exists := parents[cursor]
			if !exists {
				return empty, false, nil
			}
			switch colors[cursor] {
			case 1:
				return empty, false, nil
			case 2:
				baseDepth = depths[cursor]
				cursor = ""
				continue
			}
			colors[cursor] = 1
			path = append(path, cursor)
			if len(path) > MaxAtlasOrgDepth {
				return empty, false, nil
			}
			cursor = parentID
		}
		for i := len(path) - 1; i >= 0; i-- {
			baseDepth++
			if baseDepth > MaxAtlasOrgDepth {
				return empty, false, nil
			}
			depths[path[i]] = baseDepth
			colors[path[i]] = 2
		}
	}

	if _, exists := parents[targetOrgUnitID]; !exists {
		return empty, false, nil
	}
	ancestors := make(map[string]struct{}, depths[targetOrgUnitID])
	for cursor := targetOrgUnitID; cursor != ""; cursor = parents[cursor] {
		if err := ctx.Err(); err != nil {
			return empty, false, err
		}
		ancestors[cursor] = struct{}{}
		if observe != nil {
			observe(atlasGraphWorkAncestor)
		}
	}

	requiredScopes := map[string]struct{}{}
	suggestScopes := map[string]struct{}{}
	seenMemberships := make(map[string]struct{}, len(snapshot.Memberships))
	for _, membership := range snapshot.Memberships {
		if err := ctx.Err(); err != nil {
			return empty, false, err
		}
		if !atlasCanonicalNonEmpty(membership.OrgUnitID) || !atlasKnownRole(membership.Role) {
			return empty, false, nil
		}
		if _, exists := parents[membership.OrgUnitID]; !exists {
			return empty, false, nil
		}
		membershipKey := membership.OrgUnitID + "\x00" + membership.Role
		if _, exists := seenMemberships[membershipKey]; exists {
			return empty, false, nil
		}
		seenMemberships[membershipKey] = struct{}{}
		if observe != nil {
			observe(atlasGraphWorkMembership)
		}
		if _, coversTarget := ancestors[membership.OrgUnitID]; !coversTarget {
			continue
		}
		permission := atlasPermissionForRole(membership.Role)
		if permission == requiredPermission {
			requiredScopes[membership.OrgUnitID] = struct{}{}
		}
		if permission == PermissionSuggest {
			suggestScopes[membership.OrgUnitID] = struct{}{}
		}
	}
	return atlasScopeAnalysis{requiredScopes: atlasSortedScopes(requiredScopes), suggestScopes: atlasSortedScopes(suggestScopes)}, true, nil
}

func atlasSortedScopes(scopes map[string]struct{}) []string {
	result := make([]string, 0, len(scopes))
	for orgUnitID := range scopes {
		result = append(result, orgUnitID)
	}
	sort.Strings(result)
	return result
}

func atlasCanonicalNonEmpty(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func atlasKnownRole(role string) bool {
	if !atlasCanonicalNonEmpty(role) {
		return false
	}
	if role == "member" || role == "manager" || role == "admin" {
		return true
	}
	return atlasPermissionForRole(role) != ""
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
