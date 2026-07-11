package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
)

type AuditEvidenceAction = audit.Action

const (
	AuditActionWorkflowDraftCreated        = audit.ActionWorkflowDraftCreated
	AuditActionWorkflowVersionPublished    = audit.ActionWorkflowVersionPublished
	AuditActionDreamPolicyCreated          = audit.ActionDreamPolicyCreated
	AuditActionDreamPolicyCreateAuthorized = audit.ActionDreamPolicyCreateAuthorized
	AuditActionDreamJobRun                 = audit.ActionDreamJobRun
	AuditActionRetrievalPlanCreated        = audit.ActionRetrievalPlanCreated
	AuditActionEvidenceLocated             = audit.ActionEvidenceLocated
	AuditActionEvidenceRead                = audit.ActionEvidenceRead
	AuditActionAnswerTraceCreated          = audit.ActionAnswerTraceCreated
	AuditActionSensitiveArtifactParsed     = audit.ActionSensitiveArtifactParsed
	AuditActionVisibilityRuleChanged       = audit.ActionVisibilityRuleChanged
)

func ValidAuditEvidenceAction(action AuditEvidenceAction) bool { return audit.ValidAction(action) }

type AuditEvidenceInput struct {
	EnterpriseID  string
	ActorUserID   string
	Action        AuditEvidenceAction
	TraceID       string
	WorkflowRunID string
	Details       map[string]any
}

type AuditEvidenceSink interface {
	AppendAuditEvidence(context.Context, AuditEvidenceInput) (string, error)
}

type auditEvidenceHandler struct {
	enterpriseID string
	tickets      TicketActorAuthenticator
	sink         AuditEvidenceSink
}

func newAuditEvidenceHandler(enterpriseID string, tickets TicketActorAuthenticator, sink AuditEvidenceSink) (*auditEvidenceHandler, error) {
	if enterpriseID == "" || tickets == nil || sink == nil {
		return nil, errors.New("audit evidence dependencies incomplete")
	}
	return &auditEvidenceHandler{enterpriseID: enterpriseID, tickets: tickets, sink: sink}, nil
}

func (h *auditEvidenceHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/audit/evidence", h.append)
}

func (h *auditEvidenceHandler) append(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	var request struct {
		TicketID      string              `json:"ticket_id"`
		EnterpriseID  string              `json:"enterprise_id"`
		Action        AuditEvidenceAction `json:"action"`
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
	if err := decoder.Decode(&struct{}{}); err != io.EOF || request.TicketID == "" || request.EnterpriseID != h.enterpriseID || !ValidAuditEvidenceAction(request.Action) || len(request.Details) > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	actor, err := h.tickets.AuthenticateTicketActor(r.Context(), request.TicketID)
	if err != nil || actor.EnterpriseID != request.EnterpriseID || actor.UserID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_ticket"})
		return
	}
	id, err := h.sink.AppendAuditEvidence(r.Context(), AuditEvidenceInput{EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, Action: request.Action, TraceID: request.TraceID, WorkflowRunID: request.WorkflowRunID, Details: request.Details})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit_unavailable"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"audit_ref_id": id})
}
