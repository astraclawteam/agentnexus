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
	"sort"
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
	ID             string
	EnterpriseID   string
	RequesterID    string
	OrgVersion     int64
	OrgUnitID      string
	ResourceType   string
	ResourceID     string
	Action         string
	RiskLevel      approval.RiskLevel
	RiskReasons    []approval.RiskReason
	RouteMode      approval.RouteMode
	ReviewerUserID string
	OrgPath        []string
	Queue          string
	InputHash      string
	OutputHash     string
}

type ApprovalRouteStore interface {
	Record(context.Context, approval.Request, approval.Route) error
}

type MemoryApprovalStore struct {
	mu     sync.Mutex
	random io.Reader
	fail   func(ApprovalRecordStage) error
	queues []ApprovalQueueEvidence
	events []audit.Event
}

func NewMemoryApprovalStore(randomSource io.Reader, fail func(ApprovalRecordStage) error) *MemoryApprovalStore {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &MemoryApprovalStore{random: randomSource, fail: fail, queues: []ApprovalQueueEvidence{}, events: []audit.Event{}}
}

func (s *MemoryApprovalStore) Record(ctx context.Context, req approval.Request, route approval.Route) error {
	if s == nil || s.random == nil || ctx.Err() != nil || !validRecordedRoute(req, route) {
		return errors.New("approval record unavailable")
	}
	inputHash, outputHash, err := approvalEvidenceHashes(req, route)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	var queued *ApprovalQueueEvidence
	if route.Mode != approval.ModeSingleConfirmation {
		if s.fail != nil {
			if err := s.fail(ApprovalStageQueue); err != nil {
				return err
			}
		}
		id, err := randomApprovalID(s.random, "approval_")
		if err != nil {
			return err
		}
		queued = &ApprovalQueueEvidence{ID: id, EnterpriseID: req.EnterpriseID, RequesterID: req.RequesterUserID, OrgVersion: req.OrgVersion, OrgUnitID: req.OrgUnitID, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Action: req.Action, RiskLevel: route.RiskLevel, RiskReasons: append([]approval.RiskReason{}, route.RiskReasons...), RouteMode: route.Mode, ReviewerUserID: route.ReviewerUserID, OrgPath: append([]string{}, route.OrgPath...), Queue: route.Queue, InputHash: inputHash, OutputHash: outputHash}
	}
	if s.fail != nil {
		if err := s.fail(ApprovalStageAudit); err != nil {
			return err
		}
	}
	auditID, err := randomApprovalID(s.random, "approvalaudit_")
	if err != nil {
		return err
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
	return nil
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
	changed := append([]string{}, req.Risk.ChangedFields...)
	impacted := append([]string{}, req.Risk.ImpactedOrgUnitIDs...)
	sort.Strings(changed)
	sort.Strings(impacted)
	input := struct {
		EnterpriseID            string             `json:"enterprise_id"`
		RequesterUserID         string             `json:"requester_user_id"`
		OrgVersion              int64              `json:"org_version"`
		OrgUnitID               string             `json:"org_unit_id"`
		ResourceType            string             `json:"resource_type"`
		ResourceID              string             `json:"resource_id"`
		Action                  string             `json:"action"`
		ChangedFields           []string           `json:"changed_fields"`
		ImpactedOrgUnitIDs      []string           `json:"impacted_org_unit_ids"`
		ImpactedUserCount       int                `json:"impacted_user_count"`
		PublishedBehaviorChange bool               `json:"published_behavior_change"`
		ExternalSideEffect      bool               `json:"external_side_effect"`
		RequestedRisk           approval.RiskLevel `json:"requested_risk,omitempty"`
	}{req.EnterpriseID, req.RequesterUserID, req.OrgVersion, req.OrgUnitID, req.ResourceType, req.ResourceID, req.Action, changed, impacted, req.Risk.ImpactedUserCount, req.Risk.PublishedBehaviorChange, req.Risk.ExternalSideEffect, req.Risk.RequestedRisk}
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
	if req.EnterpriseID == "" || req.RequesterUserID == "" || req.OrgVersion < 1 || route.RequesterUserID != req.RequesterUserID || route.AutoPublish || route.RiskReasons == nil || route.OrgPath == nil || len(route.OrgPath) == 0 || route.ReviewerUserID == req.RequesterUserID {
		return false
	}
	switch route.Mode {
	case approval.ModeSingleConfirmation:
		return route.RiskLevel == approval.RiskLow && route.ReviewerUserID == "" && route.Queue == ""
	case approval.ModeUpwardReview:
		return route.ReviewerUserID != "" && route.Queue == ""
	case approval.ModeEnterpriseKnowledgeAdminQueue:
		return route.ReviewerUserID == "" && route.Queue == approval.EnterpriseKnowledgeAdminQueue
	default:
		return false
	}
}
