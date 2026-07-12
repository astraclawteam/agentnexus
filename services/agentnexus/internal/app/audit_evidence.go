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
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
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
	IdempotencyKey string
	EnterpriseID   string
	ActorUserID    string
	CaseTicketID   string
	Action         AuditEvidenceAction
	ResourceType   string
	ResourceID     string
	TraceID        string
	Details        map[string]any
}

type AuditEvidenceSink interface {
	AppendAuditEvidence(context.Context, AuditEvidenceInput) (string, error)
}

// auditEvidenceHandler appends trusted first-party service audit evidence.
// The service identity comes from the verified trusted context (service
// credential source); the request body binds the Case Ticket lineage through
// business_context_ref and carries NO tenant or actor identity.
type auditEvidenceHandler struct {
	enterpriseID string
	tickets      trust.AccessTicketVerifier
	sink         AuditEvidenceSink
	audit        BrowserAuditSink
}

func newAuditEvidenceHandler(enterpriseID string, tickets trust.AccessTicketVerifier, sink AuditEvidenceSink, auditSink BrowserAuditSink) (*auditEvidenceHandler, error) {
	if enterpriseID == "" || tickets == nil || sink == nil {
		return nil, errors.New("audit evidence dependencies incomplete")
	}
	return &auditEvidenceHandler{enterpriseID: enterpriseID, tickets: tickets, sink: sink, audit: auditSink}, nil
}

func (h *auditEvidenceHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/audit/evidence", h.append)
}

func (h *auditEvidenceHandler) append(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	trustedCtx, err := trust.FromRequest(r)
	if err != nil {
		if trust.HTTPStatus(err) == http.StatusServiceUnavailable {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ticket_unavailable"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_service"})
		return
	}
	if trustedCtx.Source != trust.SourceServiceCredential || trustedCtx.Principal.TenantRef != h.enterpriseID {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_service"})
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) > 1 || (len(keys) == 1 && !boundedText(keys[0], 128, false)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_idempotency_key"})
		return
	}
	idempotencyKey := ""
	if len(keys) == 1 {
		idempotencyKey = strings.TrimSpace(keys[0])
		if utf8.RuneCountInString(idempotencyKey) < 16 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_idempotency_key"})
			return
		}
	}
	var request struct {
		RequestID          string              `json:"request_id"`
		BusinessContextRef string              `json:"business_context_ref"`
		Action             AuditEvidenceAction `json:"action"`
		ResourceType       string              `json:"resource_type"`
		ResourceID         string              `json:"resource_id"`
		TraceID            string              `json:"trace_id"`
		Details            map[string]any      `json:"details"`
	}
	if !h.decodeAuditEvidenceRequest(w, r, trustedCtx, map[string]any{
		"request_id":           &request.RequestID,
		"business_context_ref": &request.BusinessContextRef,
		"action":               &request.Action,
		"resource_type":        &request.ResourceType,
		"resource_id":          &request.ResourceID,
		"trace_id":             &request.TraceID,
		"details":              &request.Details,
	}, map[string]struct{}{"business_context_ref": {}, "action": {}, "resource_type": {}, "resource_id": {}}) {
		return
	}
	if !validAuditEvidenceRequest(request.BusinessContextRef, request.RequestID, request.ResourceType, request.ResourceID, request.TraceID, request.Action, request.Details) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	identity, err := h.tickets.VerifyAccessTicket(r.Context(), request.BusinessContextRef)
	if err != nil {
		if errors.Is(err, trust.ErrSourceUnavailable) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ticket_unavailable"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_ticket"})
		return
	}
	if identity.TenantRef != h.enterpriseID || identity.PrincipalRef == "" || identity.TicketRef == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_ticket"})
		return
	}
	id, err := h.sink.AppendAuditEvidence(r.Context(), AuditEvidenceInput{IdempotencyKey: idempotencyKey, EnterpriseID: identity.TenantRef, ActorUserID: identity.PrincipalRef, CaseTicketID: identity.TicketRef, Action: request.Action, ResourceType: request.ResourceType, ResourceID: request.ResourceID, TraceID: request.TraceID, Details: request.Details})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit_unavailable"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"audit_ref_id": id})
}

// decodeAuditEvidenceRequest decodes the frozen AuditEvidenceRequest member
// set strictly: unknown members are rejected, and members that would carry
// trusted identity (enterprise_id, actor_user_id, ...) are rejected AND
// audited — body values never win.
func (h *auditEvidenceHandler) decodeAuditEvidenceRequest(w http.ResponseWriter, r *http.Request, trustedCtx trust.Context, targets map[string]any, required map[string]struct{}) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	invalid := func() bool {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return false
	}
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return invalid()
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return invalid()
		}
		if _, duplicate := seen[key]; duplicate {
			return invalid()
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || string(raw) == "null" {
			return invalid()
		}
		target, expected := targets[key]
		if !expected {
			if trust.ForgedIdentityField(key) {
				auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.forged_body_field")
			}
			return invalid()
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return invalid()
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return invalid()
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return invalid()
	}
	for name := range required {
		if _, exists := seen[name]; !exists {
			return invalid()
		}
	}
	return true
}

func validAuditEvidenceRequest(businessContextRef, requestID, resourceType, resourceID, traceID string, action AuditEvidenceAction, details map[string]any) bool {
	if !boundedText(businessContextRef, 4096, false) || !boundedText(requestID, 128, true) || !boundedText(resourceType, 64, false) || !boundedText(resourceID, 128, false) || !boundedText(traceID, 128, true) || !ValidAuditEvidenceAction(action) || len(details) > 100 {
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
