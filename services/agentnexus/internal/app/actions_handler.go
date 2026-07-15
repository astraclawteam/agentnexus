package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const maxActionsRequestBytes = 64 << 10

// ActionsService is the GA Task 0F durable controlled-execution plane consumed
// by the gateway (implemented by *actions.Service). Identity derives from the
// ingress-resolved trusted context only; the request JSON never carries it.
type ActionsService interface {
	RequestAction(ctx context.Context, principal runtime.PrincipalContext, req runtime.ActionRequest) (actions.Action, error)
	IngestReceipt(ctx context.Context, principal runtime.PrincipalContext, resultID string, receipt runtime.ActionReceipt) (actions.Action, error)
	Compensate(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error)
	GetReceipt(ctx context.Context, principal runtime.PrincipalContext, receiptRef string) (runtime.ActionReceipt, error)
}

// actionsHandler serves the durable action surface:
//
//	POST /v1/runtime/act                                 (requestRuntimeAction)
//	POST /v1/runtime/actions/{action_ref}/receipts       (ingestRuntimeActionReceipt)
//	POST /v1/runtime/actions/{action_ref}/compensations  (triggerRuntimeActionCompensation)
//	GET  /v1/runtime/receipts/{receipt_ref}              (getRuntimeActionReceipt)
//
// Request bodies are strictly decoded (unknown members and trusted-identity
// fields are rejected); every failure envelope is fixed and opaque.
type actionsHandler struct {
	enterpriseID string
	service      ActionsService
	audit        BrowserAuditSink
	logger       *slog.Logger
}

func newActionsHandler(enterpriseID string, service ActionsService, audit BrowserAuditSink, logger *slog.Logger) (*actionsHandler, error) {
	if enterpriseID == "" || service == nil {
		return nil, errors.New("actions dependencies incomplete")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &actionsHandler{enterpriseID: enterpriseID, service: service, audit: audit, logger: logger}, nil
}

func (h *actionsHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/runtime/act", h.request)
	mux.HandleFunc("POST /v1/runtime/actions/{action_ref}/receipts", h.ingestReceipt)
	mux.HandleFunc("POST /v1/runtime/actions/{action_ref}/compensations", h.compensate)
	mux.HandleFunc("GET /v1/runtime/receipts/{receipt_ref}", h.getReceipt)
}

func (h *actionsHandler) request(w http.ResponseWriter, r *http.Request) {
	trustedCtx, ok := h.begin(w, r)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	request, err := runtime.DecodeActionRequest(body)
	if err != nil {
		if errors.Is(err, runtime.ErrTrustedIdentityInRequest) {
			auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.forged_body_field")
		}
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, err := NewRequestContext(trustedCtx, request.RequestID, request.TraceID); err != nil {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	action, err := h.service.RequestAction(r.Context(), trustedCtx.Principal, request)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, action.Runtime())
}

func (h *actionsHandler) ingestReceipt(w http.ResponseWriter, r *http.Request) {
	trustedCtx, ok := h.begin(w, r)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var envelope struct {
		RequestID string                `json:"request_id"`
		TraceID   string                `json:"trace_id"`
		ResultID  string                `json:"result_id"`
		Receipt   runtime.ActionReceipt `json:"receipt"`
	}
	if !h.decodeStrict(w, r, trustedCtx, body, &envelope, "receipt") {
		return
	}
	if _, err := NewRequestContext(trustedCtx, envelope.RequestID, envelope.TraceID); err != nil {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if envelope.Receipt.ActionRef != r.PathValue("action_ref") {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	action, err := h.service.IngestReceipt(r.Context(), trustedCtx.Principal, envelope.ResultID, envelope.Receipt)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, action.Runtime())
}

func (h *actionsHandler) compensate(w http.ResponseWriter, r *http.Request) {
	trustedCtx, ok := h.begin(w, r)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var envelope struct {
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
	}
	if !h.decodeStrict(w, r, trustedCtx, body, &envelope, "request_id") {
		return
	}
	if _, err := NewRequestContext(trustedCtx, envelope.RequestID, envelope.TraceID); err != nil {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	action, err := h.service.Compensate(r.Context(), trustedCtx.Principal, r.PathValue("action_ref"))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, action.Runtime())
}

func (h *actionsHandler) getReceipt(w http.ResponseWriter, r *http.Request) {
	trustedCtx, ok := h.begin(w, r)
	if !ok {
		return
	}
	receipt, err := h.service.GetReceipt(r.Context(), trustedCtx.Principal, r.PathValue("receipt_ref"))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (h *actionsHandler) begin(w http.ResponseWriter, r *http.Request) (trust.Context, bool) {
	setNoStore(w)
	trustedCtx, status := trustedRequestContext(r)
	if status != 0 {
		writeActionsError(w, status, "request_failed")
		return trust.Context{}, false
	}
	if trustedCtx.Principal.TenantRef != h.enterpriseID {
		writeActionsError(w, http.StatusUnauthorized, "request_failed")
		return trust.Context{}, false
	}
	return trustedCtx, true
}

func (h *actionsHandler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeActionsError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeActionsError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxActionsRequestBytes))
	if err != nil {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

// decodeStrict decodes a correlation envelope strictly: the body must be a JSON
// object, trusted-identity keys are rejected (and audited distinctly), the
// required member must be present and unknown members fail.
func (h *actionsHandler) decodeStrict(w http.ResponseWriter, r *http.Request, trustedCtx trust.Context, body []byte, out any, requiredMember string) bool {
	var probe any
	if err := json.Unmarshal(body, &probe); err != nil {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	root, isObject := probe.(map[string]any)
	if !isObject {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if _, forged := findForbiddenIdentityKey(root); forged {
		auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.forged_body_field")
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if _, present := root[requiredMember]; !present {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeActionsError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

// writeServiceError maps action-service sentinels onto fixed opaque envelopes.
func (h *actionsHandler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	status, reason := http.StatusServiceUnavailable, "action_unavailable"
	switch {
	case errors.Is(err, actions.ErrInvalidInput):
		status, reason = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, actions.ErrNotFound):
		status, reason = http.StatusNotFound, "action_not_found"
	case errors.Is(err, actions.ErrCompensationUndeclared):
		status, reason = http.StatusUnprocessableEntity, "compensation_undeclared"
	case errors.Is(err, actions.ErrIdempotencyConflict), errors.Is(err, actions.ErrForbiddenTransition),
		errors.Is(err, actions.ErrBlindRetryForbidden), errors.Is(err, actions.ErrApprovalRequired),
		errors.Is(err, actions.ErrEvidenceConsumed):
		status, reason = http.StatusConflict, "action_conflict"
	case errors.Is(err, actions.ErrCallerUntrusted), errors.Is(err, actions.ErrEvidenceRejected),
		errors.Is(err, actions.ErrReceiptRejected):
		status, reason = http.StatusForbidden, "action_rejected"
	}
	h.logger.WarnContext(r.Context(), "action.request_failed",
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.String("reason", reason),
		slog.String("error", err.Error()),
	)
	writeActionsError(w, status, reason)
}

func writeActionsError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"error": reason})
}
