package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
)

type ApprovalRecordStage string

const (
	ApprovalStageQueue ApprovalRecordStage = "queue"
	ApprovalStageAudit ApprovalRecordStage = "audit"
)

type ApprovalQueueEvidence struct {
	ID              string
	EnterpriseID    string
	RequesterID     string
	OrgVersion      int64
	OrgUnitID       string
	ResourceType    string
	ResourceID      string
	Action          string
	RiskLevel       approval.RiskLevel
	RiskReasons     []approval.RiskReason
	RouteMode       approval.RouteMode
	ReviewerUserID  string
	OrgPath         []string
	Queue           string
	InputHash       string
	OutputHash      string
	PolicyVersion   int64
	IdempotencyHash string
}

type ApprovalRouteStore interface {
	LookupResolution(context.Context, string, string, string) (approval.Route, bool, error)
	RecordResolution(context.Context, approval.Request, approval.Route) (approval.Route, error)
}

var (
	ErrApprovalIdempotencyConflict = errors.New("approval idempotency conflict")
	ErrApprovalStale               = errors.New("approval resolution stale")
)

type memoryApprovalVersion struct{ orgVersion, policyVersion int64 }
type memoryApprovalResolution struct {
	requestHash string
	route       approval.Route
}

type MemoryApprovalStore struct {
	mu          sync.Mutex
	random      io.Reader
	fail        func(ApprovalRecordStage) error
	queues      []ApprovalQueueEvidence
	events      []audit.Event
	versions    map[string]memoryApprovalVersion
	resolutions map[string]memoryApprovalResolution
}

func NewMemoryApprovalStore(randomSource io.Reader, fail func(ApprovalRecordStage) error) *MemoryApprovalStore {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &MemoryApprovalStore{random: randomSource, fail: fail, queues: []ApprovalQueueEvidence{}, events: []audit.Event{}, versions: map[string]memoryApprovalVersion{}, resolutions: map[string]memoryApprovalResolution{}}
}

func (s *MemoryApprovalStore) SetCurrentVersions(enterpriseID string, orgVersion, policyVersion int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[enterpriseID] = memoryApprovalVersion{orgVersion: orgVersion, policyVersion: policyVersion}
}

func (s *MemoryApprovalStore) LookupResolution(_ context.Context, enterpriseID, idempotencyHash, requestHash string) (approval.Route, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.resolutions[enterpriseID+"\x00"+idempotencyHash]
	if !ok {
		return approval.Route{}, false, nil
	}
	if existing.requestHash != requestHash {
		return approval.Route{}, false, ErrApprovalIdempotencyConflict
	}
	return existing.route, true, nil
}

func (s *MemoryApprovalStore) Record(ctx context.Context, req approval.Request, route approval.Route) error {
	_, err := s.RecordResolution(ctx, req, route)
	return err
}

func (s *MemoryApprovalStore) RecordResolution(ctx context.Context, req approval.Request, route approval.Route) (approval.Route, error) {
	if s == nil || s.random == nil || ctx.Err() != nil || !validRecordedRoute(req, route) {
		return approval.Route{}, errors.New("approval record unavailable")
	}
	inputHash, outputHash, err := approvalEvidenceHashes(req, route)
	if err != nil {
		return approval.Route{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return approval.Route{}, err
	}
	key := req.EnterpriseID + "\x00" + req.IdempotencyHash
	if existing, ok := s.resolutions[key]; ok {
		if existing.requestHash != req.ReplayHash {
			return approval.Route{}, ErrApprovalIdempotencyConflict
		}
		return existing.route, nil
	}
	current, ok := s.versions[req.EnterpriseID]
	if !ok || current.orgVersion != req.OrgVersion || current.policyVersion != req.PolicyVersion {
		return approval.Route{}, ErrApprovalStale
	}

	var queued *ApprovalQueueEvidence
	if route.Mode != approval.ModeSingleConfirmation {
		if s.fail != nil {
			if err := s.fail(ApprovalStageQueue); err != nil {
				return approval.Route{}, err
			}
		}
		id, err := randomApprovalID(s.random, "approval_")
		if err != nil {
			return approval.Route{}, err
		}
		queued = &ApprovalQueueEvidence{ID: id, EnterpriseID: req.EnterpriseID, RequesterID: req.RequesterUserID, OrgVersion: req.OrgVersion, OrgUnitID: req.OrgUnitID, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: req.Action, RiskLevel: route.RiskLevel, RiskReasons: append([]approval.RiskReason{}, route.RiskReasons...), RouteMode: route.Mode, ReviewerUserID: route.ReviewerUserID, OrgPath: append([]string{}, route.OrgPath...), Queue: route.Queue, InputHash: inputHash, OutputHash: outputHash, PolicyVersion: req.PolicyVersion, IdempotencyHash: req.IdempotencyHash}
	}
	if s.fail != nil {
		if err := s.fail(ApprovalStageAudit); err != nil {
			return approval.Route{}, err
		}
	}
	auditID, err := randomApprovalID(s.random, "approvalaudit_")
	if err != nil {
		return approval.Route{}, err
	}
	previous := ""
	if len(s.events) > 0 {
		previous = s.events[len(s.events)-1].EventHash
	}
	evidencePointer := ""
	if queued != nil {
		evidencePointer = queued.ID
	}
	event := audit.NewEvent(audit.EventInput{ID: auditID, EnterpriseID: req.EnterpriseID, ActorUserID: req.RequesterUserID, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: "approval.route.resolve", Decision: string(route.Mode), InputHash: inputHash, OutputHash: outputHash, EvidencePointer: evidencePointer}, previous)
	if queued != nil {
		s.queues = append(s.queues, *queued)
	}
	s.events = append(s.events, event)
	s.resolutions[key] = memoryApprovalResolution{requestHash: req.ReplayHash, route: route}
	return route, nil
}

func (s *MemoryApprovalStore) Snapshot() ([]ApprovalQueueEvidence, []audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	queues := append([]ApprovalQueueEvidence{}, s.queues...)
	for i := range queues {
		queues[i].RiskReasons = append([]approval.RiskReason{}, queues[i].RiskReasons...)
		queues[i].OrgPath = append([]string{}, queues[i].OrgPath...)
	}
	return queues, append([]audit.Event{}, s.events...)
}

func approvalEvidenceHashes(req approval.Request, route approval.Route) (string, string, error) {
	input := struct {
		EnterpriseID       string             `json:"enterprise_id"`
		RequesterUserID    string             `json:"requester_user_id"`
		OrgVersion         int64              `json:"org_version"`
		OrgUnitID          string             `json:"org_unit_id"`
		ResourceType       string             `json:"resource_type"`
		ResourceID         string             `json:"resource_id"`
		Action             string             `json:"action"`
		FactsDigest        string             `json:"facts_digest"`
		RequestedRisk      approval.RiskLevel `json:"requested_risk,omitempty"`
		PolicyVersion      int64              `json:"policy_version"`
		IdempotencyKeyHash string             `json:"idempotency_key_hash"`
	}{req.EnterpriseID, req.RequesterUserID, req.OrgVersion, req.OrgUnitID, req.ResourceType, req.ResourceID, req.Action, req.Facts.Digest(), req.RequestedRisk, req.PolicyVersion, req.IdempotencyHash}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return "", "", err
	}
	outputBytes, err := json.Marshal(route)
	if err != nil {
		return "", "", err
	}
	return sha256Hex(inputBytes), sha256Hex(outputBytes), nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func randomApprovalID(source io.Reader, prefix string) (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func validRecordedRoute(req approval.Request, route approval.Route) bool {
	if req.EnterpriseID == "" || req.RequesterUserID == "" || req.OrgVersion < 1 || req.PolicyVersion < 1 || len(req.IdempotencyHash) != 64 || len(req.ReplayHash) != 64 || route.PolicyVersion != req.PolicyVersion || route.RequesterUserID != req.RequesterUserID || route.AutoPublish || len(route.RiskReasons) == 0 || route.OrgPath == nil || len(route.OrgPath) == 0 || route.ReviewerUserID == req.RequesterUserID {
		return false
	}
	allowedReasons := map[approval.RiskReason]bool{
		approval.RiskReasonPublishedBehaviorChange: true, approval.RiskReasonPermissionApprovalChange: true,
		approval.RiskReasonEvidenceRequirementChange: true, approval.RiskReasonExecutionDeadlineChange: true,
		approval.RiskReasonExternalSideEffect: true, approval.RiskReasonEnterpriseMinimumRisk: true,
		approval.RiskReasonImpactedOrgScope: true, approval.RiskReasonImpactedUserScope: true,
		approval.RiskReasonRequestedRiskOverride: true, approval.RiskReasonUnverifiedChangeFacts: true,
		approval.RiskReasonUnknownChangedField: true, approval.RiskReasonUnknownAction: true,
		approval.RiskReasonActionBaseline: true, approval.RiskReasonExplicitReviewRequired: true,
		approval.RiskReasonExplicitConfirmation: true,
	}
	for i, reason := range route.RiskReasons {
		if !allowedReasons[reason] || (i > 0 && route.RiskReasons[i-1] >= reason) {
			return false
		}
	}
	seenUnits := map[string]bool{}
	for i, unitID := range route.OrgPath {
		if !canonicalAuthorizationValue(unitID) || seenUnits[unitID] || (i == 0 && unitID != req.OrgUnitID) {
			return false
		}
		seenUnits[unitID] = true
	}
	switch route.Mode {
	case approval.ModeSingleConfirmation:
		return route.RiskLevel == approval.RiskLow && route.ReviewerUserID == "" && route.ReviewerDisplayName == "" && route.ReviewerPermission == "" && route.ReviewerPermissionOrgUnitID == "" && !route.AdminRootReached && route.Queue == ""
	case approval.ModeUpwardReview:
		expected := approval.PermissionApproveHighRisk
		if route.RiskLevel == approval.RiskLow {
			expected = approval.PermissionPublishLowRisk
		}
		return canonicalAuthorizationValue(route.ReviewerUserID) && canonicalAuthorizationValue(route.ReviewerDisplayName) && route.ReviewerPermission == expected && canonicalAuthorizationValue(route.ReviewerPermissionOrgUnitID) && seenUnits[route.ReviewerPermissionOrgUnitID] && !route.AdminRootReached && route.Queue == ""
	case approval.ModeEnterpriseKnowledgeAdminQueue:
		return route.ReviewerUserID == "" && route.ReviewerDisplayName == "" && route.ReviewerPermission == "" && route.ReviewerPermissionOrgUnitID == "" && route.AdminRootReached && route.Queue == approval.EnterpriseKnowledgeAdminQueue
	default:
		return false
	}
}

func validApprovalQueueStatusTransition(current, next string) bool {
	if current == next {
		return current == "pending" || current == "approved" || current == "rejected" || current == "cancelled"
	}
	return current == "pending" && (next == "approved" || next == "rejected" || next == "cancelled")
}
