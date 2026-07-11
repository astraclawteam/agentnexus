package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
)

type AuditEvidenceAction = audit.Action

const (
	AuditActionWorkflowDraftCreated       = audit.ActionWorkflowDraftCreated
	AuditActionWorkflowVersionPublished   = audit.ActionWorkflowVersionPublished
	AuditActionDreamPolicyCreated         = audit.ActionDreamPolicyCreated
	AuditActionDreamPolicyCreateRequested = audit.ActionDreamPolicyCreateRequested
	AuditActionDreamJobRun                = audit.ActionDreamJobRun
	AuditActionRetrievalPlanCreated       = audit.ActionRetrievalPlanCreated
	AuditActionEvidenceLocated            = audit.ActionEvidenceLocated
	AuditActionEvidenceRead               = audit.ActionEvidenceRead
	AuditActionAnswerTraceCreated         = audit.ActionAnswerTraceCreated
	AuditActionSensitiveArtifactParsed    = audit.ActionSensitiveArtifactParsed
	AuditActionVisibilityRuleChanged      = audit.ActionVisibilityRuleChanged
)

func ValidAuditEvidenceAction(action AuditEvidenceAction) bool { return audit.ValidAction(action) }

type AuditEvidenceInput struct {
	EnterpriseID  string
	ActorUserID   string
	CaseTicketID  string
	Action        AuditEvidenceAction
	ResourceType  string
	ResourceID    string
	TraceID       string
	WorkflowRunID string
	Details       map[string]any
}

type ServiceAuthenticator interface {
	AuthenticateService(clientID, secret string) bool
}

type AuditEvidenceSink interface {
	AppendAuditEvidence(context.Context, AuditEvidenceInput) (string, error)
}

type auditEvidenceHandler struct {
	enterpriseID string
	tickets      TicketActorAuthenticator
	sink         AuditEvidenceSink
	service      ServiceAuthenticator
}

func newAuditEvidenceHandler(enterpriseID string, tickets TicketActorAuthenticator, sink AuditEvidenceSink, service ServiceAuthenticator) (*auditEvidenceHandler, error) {
	if enterpriseID == "" || tickets == nil || sink == nil || service == nil {
		return nil, errors.New("audit evidence dependencies incomplete")
	}
	return &auditEvidenceHandler{enterpriseID: enterpriseID, tickets: tickets, sink: sink, service: service}, nil
}

func (h *auditEvidenceHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/audit/evidence", h.append)
}

func (h *auditEvidenceHandler) append(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	clientID, secret, ok := r.BasicAuth()
	if !ok || !h.service.AuthenticateService(clientID, secret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_service"})
		return
	}
	var request struct {
		TicketID      string              `json:"ticket_id"`
		EnterpriseID  string              `json:"enterprise_id"`
		Action        AuditEvidenceAction `json:"action"`
		ResourceType  string              `json:"resource_type"`
		ResourceID    string              `json:"resource_id"`
		TraceID       string              `json:"trace_id"`
		WorkflowRunID string              `json:"workflow_run_id"`
		Details       map[string]any      `json:"details"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !validAuditEvidenceRequest(request.TicketID, request.EnterpriseID, request.ResourceType, request.ResourceID, request.TraceID, request.WorkflowRunID, request.Action, request.Details, h.enterpriseID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	actor, err := h.tickets.AuthenticateTicketActor(r.Context(), request.TicketID)
	if errors.Is(err, ErrTicketActorUnavailable) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ticket_unavailable"})
		return
	}
	if err != nil || actor.EnterpriseID != request.EnterpriseID || actor.UserID == "" || actor.CaseTicketID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_ticket"})
		return
	}
	id, err := h.sink.AppendAuditEvidence(r.Context(), AuditEvidenceInput{EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, CaseTicketID: actor.CaseTicketID, Action: request.Action, ResourceType: request.ResourceType, ResourceID: request.ResourceID, TraceID: request.TraceID, WorkflowRunID: request.WorkflowRunID, Details: request.Details})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit_unavailable"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"audit_ref_id": id})
}

func validAuditEvidenceRequest(ticketID, enterpriseID, resourceType, resourceID, traceID, workflowRunID string, action AuditEvidenceAction, details map[string]any, expectedEnterprise string) bool {
	if !boundedText(ticketID, 4096, false) || enterpriseID != expectedEnterprise || !boundedText(resourceType, 64, false) || !boundedText(resourceID, 128, false) || !boundedText(traceID, 128, true) || !boundedText(workflowRunID, 128, true) || !ValidAuditEvidenceAction(action) || len(details) > 100 {
		return false
	}
	if action == AuditActionDreamPolicyCreateRequested && resourceType != "dream_policy" {
		return false
	}
	return validAuditDetailValue(details, 0)
}

func validAuditDetailValue(value any, depth int) bool {
	if depth > 4 {
		return false
	}
	switch item := value.(type) {
	case nil, bool, float64:
		return true
	case string:
		return boundedText(item, 1024, true)
	case []any:
		if len(item) > 100 {
			return false
		}
		for _, child := range item {
			if !validAuditDetailValue(child, depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		if len(item) > 100 {
			return false
		}
		for key, child := range item {
			if !boundedText(key, 128, false) || !validAuditDetailValue(child, depth+1) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func boundedText(value string, maxRunes int, allowEmpty bool) bool {
	return utf8.ValidString(value) && (allowEmpty || value != "") && utf8.RuneCountInString(value) <= maxRunes && !strings.ContainsRune(value, '\x00')
}
