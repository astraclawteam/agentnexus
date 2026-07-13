// Neutral capability policy (GA Task 0B).
//
// This file replaces the retired vendor-specific AgentAtlas permission
// vocabulary. Authorization is expressed as capability/permission
// relationships over the sealed organization snapshot and evaluated through
// the OpenFGA relationship checker (openfga.go): memberships become member
// tuples on permission-qualified department objects, the resource's
// organization placement becomes materialized parent tuples, and the scope
// decision is the checker's viewer relationship.
package policy

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
)

const (
	MaxSealedOrgUnits    = 10_000
	MaxSealedMemberships = 100_000
	MaxSealedOrgDepth    = 256
)

// PrincipalPermission is the neutral permission vocabulary of the frozen
// public contract (PrincipalPermission schema); wire values are frozen.
type PrincipalPermission string

const (
	PermissionSuggest          PrincipalPermission = "suggest"
	PermissionEdit             PrincipalPermission = "edit"
	PermissionPublishLowRisk   PrincipalPermission = "publish_low_risk"
	PermissionApproveHighRisk  PrincipalPermission = "approve_high_risk"
	PermissionWorkflowEdit     PrincipalPermission = "workflow_edit"
	PermissionWorkflowAdvanced PrincipalPermission = "workflow_advanced"
	PermissionServiceMode      PrincipalPermission = "service_mode"
)

type ResourceType string

const (
	ResourceKnowledge     ResourceType = "knowledge"
	ResourceWorkflow      ResourceType = "workflow"
	ResourceService       ResourceType = "service"
	ResourceDreamEvidence ResourceType = "dream_evidence"
)

// Capability is a namespaced business-semantic capability requested on a
// resource. Connector operations never appear here.
type Capability string

const (
	CapabilityKnowledgeSuggest         Capability = "knowledge.suggest"
	CapabilityKnowledgeCreate          Capability = "knowledge.create"
	CapabilityKnowledgeUpdate          Capability = "knowledge.update"
	CapabilityKnowledgePublishLowRisk  Capability = "knowledge.publish_low_risk"
	CapabilityKnowledgeApproveHighRisk Capability = "knowledge.approve_high_risk"
	CapabilityWorkflowEdit             Capability = "workflow.edit"
	CapabilityWorkflowEditAdvanced     Capability = "workflow.edit_advanced"
	CapabilityWorkflowPublishLowRisk   Capability = "workflow.publish_low_risk"
	CapabilityWorkflowApproveHighRisk  Capability = "workflow.approve_high_risk"
	CapabilityServiceMode              Capability = "service.mode"
	CapabilityEvidenceRead             Capability = "dream_evidence.read"
)

// ConnectorCapabilityPrefix namespaces enterprise connector capabilities.
// No capability under it is grantable through this evaluator; AstraClaw
// origins are additionally denied at ingress classification.
const ConnectorCapabilityPrefix = "connector."

// IsConnectorCapability reports whether a capability addresses the
// enterprise connector plane.
func IsConnectorCapability(capability Capability) bool {
	return strings.HasPrefix(string(capability), ConnectorCapabilityPrefix)
}

// CapabilityRisk is the frozen low/medium/high risk vocabulary.
type CapabilityRisk string

const (
	CapabilityRiskLow    CapabilityRisk = "low"
	CapabilityRiskMedium CapabilityRisk = "medium"
	CapabilityRiskHigh   CapabilityRisk = "high"
)

type capabilityRequirement struct {
	resourceType ResourceType
	permission   PrincipalPermission
	baselineRisk CapabilityRisk
}

var capabilityRequirements = map[Capability]capabilityRequirement{
	CapabilityKnowledgeSuggest:         {resourceType: ResourceKnowledge, permission: PermissionSuggest, baselineRisk: CapabilityRiskLow},
	CapabilityKnowledgeCreate:          {resourceType: ResourceKnowledge, permission: PermissionEdit, baselineRisk: CapabilityRiskMedium},
	CapabilityKnowledgeUpdate:          {resourceType: ResourceKnowledge, permission: PermissionEdit, baselineRisk: CapabilityRiskMedium},
	CapabilityKnowledgePublishLowRisk:  {resourceType: ResourceKnowledge, permission: PermissionPublishLowRisk, baselineRisk: CapabilityRiskLow},
	CapabilityKnowledgeApproveHighRisk: {resourceType: ResourceKnowledge, permission: PermissionApproveHighRisk, baselineRisk: CapabilityRiskHigh},
	CapabilityWorkflowEdit:             {resourceType: ResourceWorkflow, permission: PermissionWorkflowEdit, baselineRisk: CapabilityRiskMedium},
	CapabilityWorkflowEditAdvanced:     {resourceType: ResourceWorkflow, permission: PermissionWorkflowAdvanced, baselineRisk: CapabilityRiskHigh},
	CapabilityWorkflowPublishLowRisk:   {resourceType: ResourceWorkflow, permission: PermissionPublishLowRisk, baselineRisk: CapabilityRiskLow},
	CapabilityWorkflowApproveHighRisk:  {resourceType: ResourceWorkflow, permission: PermissionApproveHighRisk, baselineRisk: CapabilityRiskHigh},
	CapabilityServiceMode:              {resourceType: ResourceService, permission: PermissionServiceMode, baselineRisk: CapabilityRiskHigh},
	CapabilityEvidenceRead:             {resourceType: ResourceDreamEvidence, permission: PermissionApproveHighRisk, baselineRisk: CapabilityRiskHigh},
}

// RequiredCapabilityPermission resolves the permission relation and baseline
// risk a capability requires on a resource type.
func RequiredCapabilityPermission(resourceType ResourceType, capability Capability) (PrincipalPermission, CapabilityRisk, bool) {
	requirement, ok := capabilityRequirements[capability]
	if !ok || requirement.resourceType != resourceType {
		return "", CapabilityRiskHigh, false
	}
	return requirement.permission, requirement.baselineRisk, true
}

// SealedMembership is one membership row of a sealed organization snapshot.
type SealedMembership struct {
	OrgUnitID string
	Role      string
}

// SealedOrgUnit is one organization unit row of a sealed snapshot.
type SealedOrgUnit struct {
	ID       string
	ParentID string
}

// SealedAccessSnapshot is the sealed, versioned organization snapshot the
// evaluator answers against. It is server-authored; callers never supply it.
type SealedAccessSnapshot struct {
	TenantRef   string
	OrgVersion  int64
	Memberships []SealedMembership
	OrgUnits    []SealedOrgUnit
}

// SnapshotSource loads the sealed snapshot of a verified principal.
type SnapshotSource interface {
	LoadAccessSnapshot(context.Context, string, string) (SealedAccessSnapshot, error)
}

// CapabilityRequest is the evaluator input. Every identity and organization
// field is credential- or server-derived: TenantRef/PrincipalRef come from
// the verified principal context, SealedOrgVersion is the version pinned at
// ingress, and TargetOrgUnitID (optional) is the server-resolved placement
// of the resource — request bodies never carry any of them.
type CapabilityRequest struct {
	TenantRef        string
	PrincipalRef     string
	SealedOrgVersion int64
	ResourceType     ResourceType
	ResourceID       string
	Capability       Capability
	TargetOrgUnitID  string
}

// PermissionDecision is the wire-frozen decision payload.
type PermissionDecision struct {
	Decision           Decision              `json:"decision"`
	Permissions        []PrincipalPermission `json:"permissions"`
	OrgUnitIDs         []string              `json:"org_unit_ids"`
	MaskFields         []string              `json:"mask_fields"`
	RiskLevel          CapabilityRisk        `json:"risk_level"`
	FallbackCapability Capability            `json:"fallback_action,omitempty"`
	OrgVersion         int64                 `json:"org_version"`
}

// ErrPolicyUnavailable reports that no sealed policy answer is possible; the
// caller fails closed.
var ErrPolicyUnavailable = errors.New("capability policy unavailable")

// SnapshotIntegrityObserver is notified when a SEALED organization snapshot
// fails structural integrity (a cycle, a dangling reference, a duplicate, an
// unknown role, or an over-limit graph). That is a data-pipeline fault in
// server-authored data, NOT a permission denial — surfacing it distinctly
// (rather than emitting a silent baseline-risk deny) upholds the
// no-silent-degradation governance rule.
type SnapshotIntegrityObserver interface {
	SealedSnapshotIntegrityFailure(ctx context.Context, tenantRef, principalRef string, orgVersion int64)
}

// CapabilityEvaluator evaluates capability requests against sealed
// snapshots through the OpenFGA relationship checker.
type CapabilityEvaluator struct {
	source   SnapshotSource
	observer SnapshotIntegrityObserver
}

// CapabilityEvaluatorOption configures an evaluator.
type CapabilityEvaluatorOption func(*CapabilityEvaluator)

// WithSnapshotIntegrityObserver registers an observer notified on sealed
// snapshot integrity failures.
func WithSnapshotIntegrityObserver(observer SnapshotIntegrityObserver) CapabilityEvaluatorOption {
	return func(e *CapabilityEvaluator) { e.observer = observer }
}

func NewCapabilityEvaluator(source SnapshotSource, opts ...CapabilityEvaluatorOption) *CapabilityEvaluator {
	evaluator := &CapabilityEvaluator{source: source}
	for _, opt := range opts {
		opt(evaluator)
	}
	return evaluator
}

func (e *CapabilityEvaluator) Evaluate(ctx context.Context, req CapabilityRequest) (PermissionDecision, error) {
	requiredPermission, baselineRisk, known := RequiredCapabilityPermission(req.ResourceType, req.Capability)
	if !known {
		baselineRisk = CapabilityRiskHigh
	}
	if e == nil || e.source == nil || !sealedCanonical(req.TenantRef) || !sealedCanonical(req.PrincipalRef) {
		return PermissionDecision{}, ErrPolicyUnavailable
	}

	snapshot, err := e.source.LoadAccessSnapshot(ctx, req.TenantRef, req.PrincipalRef)
	if err != nil {
		return PermissionDecision{}, errors.Join(ErrPolicyUnavailable, err)
	}
	if snapshot.TenantRef != req.TenantRef || snapshot.OrgVersion < 1 {
		return PermissionDecision{}, ErrPolicyUnavailable
	}

	decision := DeniedCapabilityDecision(snapshot.OrgVersion, baselineRisk)
	if req.SealedOrgVersion != snapshot.OrgVersion || !sealedCanonical(string(req.ResourceType)) || !sealedCanonical(req.ResourceID) || !sealedCanonical(string(req.Capability)) || !known || (req.TargetOrgUnitID != "" && !sealedCanonical(req.TargetOrgUnitID)) {
		return DeniedCapabilityDecision(snapshot.OrgVersion, CapabilityRiskHigh), nil
	}

	analysis, valid, err := sealCapabilityRelations(ctx, snapshot, req, requiredPermission, nil)
	if err != nil {
		return PermissionDecision{}, errors.Join(ErrPolicyUnavailable, err)
	}
	if !valid {
		// A structurally invalid sealed snapshot is a data-integrity fault, not
		// an ordinary permission denial: deny at high risk (matching the
		// malformed-request treatment above, distinguishable from a low/medium
		// permission deny) AND signal the pipeline fault so it is never silent.
		if e.observer != nil {
			e.observer.SealedSnapshotIntegrityFailure(ctx, req.TenantRef, req.PrincipalRef, snapshot.OrgVersion)
		}
		return DeniedCapabilityDecision(snapshot.OrgVersion, CapabilityRiskHigh), nil
	}

	if len(analysis.requiredScopes) > 0 && analysis.covered {
		decision.Decision = DecisionAllow
		decision.Permissions = []PrincipalPermission{requiredPermission}
		decision.OrgUnitIDs = analysis.requiredScopes
		return decision, nil
	}

	if req.Capability == CapabilityKnowledgeUpdate && len(analysis.suggestScopes) > 0 && analysis.suggestCovered {
		decision.Permissions = []PrincipalPermission{PermissionSuggest}
		decision.OrgUnitIDs = analysis.suggestScopes
		decision.FallbackCapability = CapabilityKnowledgeSuggest
	}
	return decision, nil
}

// DeniedCapabilityDecision is the complete deny payload at a sealed version.
func DeniedCapabilityDecision(orgVersion int64, risk CapabilityRisk) PermissionDecision {
	return PermissionDecision{
		Decision:    DecisionDeny,
		Permissions: []PrincipalPermission{},
		OrgUnitIDs:  []string{},
		MaskFields:  []string{},
		RiskLevel:   risk,
		OrgVersion:  orgVersion,
	}
}

type sealedGraphWork string

const (
	sealedGraphWorkUnit       sealedGraphWork = "unit"
	sealedGraphWorkParent     sealedGraphWork = "parent"
	sealedGraphWorkMembership sealedGraphWork = "membership"
	sealedGraphWorkAncestor   sealedGraphWork = "ancestor"
)

type capabilityScopeAnalysis struct {
	requiredScopes []string
	suggestScopes  []string
	covered        bool
	suggestCovered bool
}

// sealCapabilityRelations validates the sealed snapshot graph, seals it into
// an ephemeral OpenFGA relationship store and answers the scope questions
// through checker relationships:
//
//   - membership with the required permission at unit M:
//     (user:<principal>, member, department:<M>|<permission>)
//   - the target unit's ancestor chain, materialized for the resource:
//     (department:<ancestor>|<permission>, parent, knowledge_space:<resource>|<permission>)
//   - scope coverage = Check(user, viewer, knowledge_space:<resource>|<permission>)
//
// Without a target unit (pure capability query), coverage degenerates to
// membership existence, still answered through Check on the member relation.
func sealCapabilityRelations(ctx context.Context, snapshot SealedAccessSnapshot, req CapabilityRequest, requiredPermission PrincipalPermission, observe func(sealedGraphWork)) (capabilityScopeAnalysis, bool, error) {
	empty := capabilityScopeAnalysis{requiredScopes: []string{}, suggestScopes: []string{}}
	if len(snapshot.OrgUnits) > MaxSealedOrgUnits || len(snapshot.Memberships) > MaxSealedMemberships {
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
		if !sealedCanonical(unit.ID) || (unit.ParentID != "" && !sealedCanonical(unit.ParentID)) {
			return empty, false, nil
		}
		if _, exists := parents[unit.ID]; exists {
			return empty, false, nil
		}
		parents[unit.ID] = unit.ParentID
		if observe != nil {
			observe(sealedGraphWorkUnit)
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
				observe(sealedGraphWorkParent)
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
			if len(path) > MaxSealedOrgDepth {
				return empty, false, nil
			}
			cursor = parentID
		}
		for i := len(path) - 1; i >= 0; i-- {
			baseDepth++
			if baseDepth > MaxSealedOrgDepth {
				return empty, false, nil
			}
			depths[path[i]] = baseDepth
			colors[path[i]] = 2
		}
	}

	targeted := req.TargetOrgUnitID != ""
	ancestors := map[string]struct{}{}
	if targeted {
		if _, exists := parents[req.TargetOrgUnitID]; !exists {
			return empty, false, nil
		}
		for cursor := req.TargetOrgUnitID; cursor != ""; cursor = parents[cursor] {
			if err := ctx.Err(); err != nil {
				return empty, false, err
			}
			ancestors[cursor] = struct{}{}
			if observe != nil {
				observe(sealedGraphWorkAncestor)
			}
		}
	}

	principal := TypeUser + ":" + req.PrincipalRef
	relations := NewInMemoryOpenFGA()
	requiredScopes := map[string]struct{}{}
	suggestScopes := map[string]struct{}{}
	seenMemberships := make(map[string]struct{}, len(snapshot.Memberships))
	for _, membership := range snapshot.Memberships {
		if err := ctx.Err(); err != nil {
			return empty, false, err
		}
		if !sealedCanonical(membership.OrgUnitID) || !sealedKnownRole(membership.Role) {
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
			observe(sealedGraphWorkMembership)
		}
		permission, _ := MembershipRolePermission(membership.Role)
		if permission != requiredPermission && permission != PermissionSuggest {
			continue
		}
		if targeted {
			if _, coversTarget := ancestors[membership.OrgUnitID]; !coversTarget {
				continue
			}
		}
		if err := relations.WriteRelation(ctx, TupleKey{User: principal, Relation: RelationMember, Object: permissionScopedDepartment(membership.OrgUnitID, permission)}); err != nil {
			return empty, false, err
		}
		if permission == requiredPermission {
			requiredScopes[membership.OrgUnitID] = struct{}{}
		}
		if permission == PermissionSuggest {
			suggestScopes[membership.OrgUnitID] = struct{}{}
		}
	}

	analysis := capabilityScopeAnalysis{
		requiredScopes: sealedSortedScopes(requiredScopes),
		suggestScopes:  sealedSortedScopes(suggestScopes),
	}
	confirm := func(scopes []string, permission PrincipalPermission) (bool, error) {
		if targeted {
			resource := permissionScopedResource(req.ResourceID, permission)
			for ancestor := range ancestors {
				if err := relations.WriteRelation(ctx, TupleKey{User: permissionScopedDepartment(ancestor, permission), Relation: RelationParent, Object: resource}); err != nil {
					return false, err
				}
			}
			return relations.Check(ctx, TupleKey{User: principal, Relation: RelationViewer, Object: resource})
		}
		for _, scope := range scopes {
			allowed, err := relations.Check(ctx, TupleKey{User: principal, Relation: RelationMember, Object: permissionScopedDepartment(scope, permission)})
			if err != nil {
				return false, err
			}
			if allowed {
				return true, nil
			}
		}
		return false, nil
	}
	covered, err := confirm(analysis.requiredScopes, requiredPermission)
	if err != nil {
		return empty, false, err
	}
	analysis.covered = covered
	suggestCovered, err := confirm(analysis.suggestScopes, PermissionSuggest)
	if err != nil {
		return empty, false, err
	}
	analysis.suggestCovered = suggestCovered
	return analysis, true, nil
}

func permissionScopedDepartment(orgUnitID string, permission PrincipalPermission) string {
	return TypeDepartment + ":" + orgUnitID + "|" + string(permission)
}

func permissionScopedResource(resourceID string, permission PrincipalPermission) string {
	return TypeKnowledgeSpace + ":" + resourceID + "|" + string(permission)
}

func sealedSortedScopes(scopes map[string]struct{}) []string {
	result := make([]string, 0, len(scopes))
	for orgUnitID := range scopes {
		result = append(result, orgUnitID)
	}
	sort.Strings(result)
	return result
}

func sealedCanonical(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func sealedKnownRole(role string) bool {
	_, known := MembershipRolePermission(role)
	return known
}

// MembershipRolePermission is the single canonical mapping from a sealed
// organization membership role to its effective neutral permission.
func MembershipRolePermission(role string) (PrincipalPermission, bool) {
	if !sealedCanonical(role) {
		return "", false
	}
	if role == "member" {
		return PermissionSuggest, true
	}
	if role == "manager" || role == "admin" {
		return "", true
	}
	permission := PrincipalPermission(role)
	switch permission {
	case PermissionSuggest, PermissionEdit, PermissionPublishLowRisk, PermissionApproveHighRisk, PermissionWorkflowEdit, PermissionWorkflowAdvanced, PermissionServiceMode:
		return permission, true
	default:
		return "", false
	}
}

// MemorySnapshotSource is the in-memory SnapshotSource used by tests and the
// browser harness.
type MemorySnapshotSource struct {
	mu        sync.RWMutex
	snapshots map[string]SealedAccessSnapshot
}

func NewMemorySnapshotSource() *MemorySnapshotSource {
	return &MemorySnapshotSource{snapshots: map[string]SealedAccessSnapshot{}}
}

func (s *MemorySnapshotSource) StoreSnapshot(tenantRef, principalRef string, snapshot SealedAccessSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[sealedSnapshotKey(tenantRef, principalRef)] = cloneSealedSnapshot(snapshot)
}

func (s *MemorySnapshotSource) LoadAccessSnapshot(ctx context.Context, tenantRef, principalRef string) (SealedAccessSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return SealedAccessSnapshot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot, ok := s.snapshots[sealedSnapshotKey(tenantRef, principalRef)]
	if !ok {
		return SealedAccessSnapshot{}, ErrPolicyUnavailable
	}
	return cloneSealedSnapshot(snapshot), nil
}

func cloneSealedSnapshot(snapshot SealedAccessSnapshot) SealedAccessSnapshot {
	snapshot.OrgUnits = append([]SealedOrgUnit(nil), snapshot.OrgUnits...)
	snapshot.Memberships = append([]SealedMembership(nil), snapshot.Memberships...)
	return snapshot
}

func sealedSnapshotKey(tenantRef, principalRef string) string {
	return tenantRef + "\x00" + principalRef
}
