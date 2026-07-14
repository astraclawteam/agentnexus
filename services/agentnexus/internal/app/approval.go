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
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const maxApprovalTransportRequestBytes = 16 << 10

// ApprovalTransmissionService is the approval TRANSMISSION plane consumed by
// the gateway (implemented by *approvaltransport.Service). AgentNexus
// transmits the caller's signed plan unchanged, validates returned evidence
// and exposes status — it never classifies risk, walks hierarchy or chooses
// approvers (GA Task 0E locked boundary). Identity derives from the
// ingress-resolved trusted context only.
type ApprovalTransmissionService interface {
	Transmit(ctx context.Context, principal runtime.PrincipalContext, req runtime.ApprovalRequest) (approvaltransport.Transmission, error)
	RecordEvidence(ctx context.Context, principal runtime.PrincipalContext, evidence runtime.ApprovalEvidence) (approvaltransport.EvidenceRecord, error)
	GetStatus(ctx context.Context, principal runtime.PrincipalContext, planRef string) (approvaltransport.Transmission, error)
	Revoke(ctx context.Context, principal runtime.PrincipalContext, planRef, reason string) (approvaltransport.Transmission, error)
}

// approvalTransportHandler serves the transmission surface:
//
//	POST /v1/approvals/transmissions
//	GET  /v1/approvals/transmissions/{plan_ref}
//	POST /v1/approvals/transmissions/{plan_ref}/revocations
//	POST /v1/approvals/evidence
//
// Request bodies are strictly decoded (unknown members and trusted-identity
// fields are rejected); every failure envelope is fixed and opaque.
type approvalTransportHandler struct {
	enterpriseID string
	service      ApprovalTransmissionService
	audit        BrowserAuditSink
	logger       *slog.Logger
}

// newApprovalTransportHandler builds the handler. The logger is the single
// handler-side observability seam (0D evidence-handler precedent); nil falls
// back to slog.Default() explicitly.
func newApprovalTransportHandler(enterpriseID string, service ApprovalTransmissionService, audit BrowserAuditSink, logger *slog.Logger) (*approvalTransportHandler, error) {
	if enterpriseID == "" || service == nil {
		return nil, errors.New("approval transmission dependencies incomplete")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &approvalTransportHandler{enterpriseID: enterpriseID, service: service, audit: audit, logger: logger}, nil
}

func (h *approvalTransportHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/approvals/transmissions", h.transmit)
	mux.HandleFunc("GET /v1/approvals/transmissions/{plan_ref}", h.status)
	mux.HandleFunc("POST /v1/approvals/transmissions/{plan_ref}/revocations", h.revoke)
	mux.HandleFunc("POST /v1/approvals/evidence", h.recordEvidence)
}

// approvalTransmissionResponse is the diagnostics status view. It carries the
// exact operation binding and the transport lifecycle — and, by boundary,
// not a single approver identity, queue or risk field.
type approvalTransmissionResponse struct {
	PlanRef             string     `json:"plan_ref"`
	PlanHash            string     `json:"plan_hash"`
	Authority           string     `json:"authority"`
	BusinessContextRef  string     `json:"business_context_ref"`
	Capability          string     `json:"capability"`
	ParameterHash       string     `json:"parameter_hash"`
	Status              string     `json:"status"`
	ExpiresAt           time.Time  `json:"expires_at"`
	DeliveryAttempts    int        `json:"delivery_attempts"`
	LastDeliveryOutcome string     `json:"last_delivery_state,omitempty"`
	Decision            string     `json:"decision,omitempty"`
	DecidedAt           *time.Time `json:"decided_at,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func transmissionResponse(transmission approvaltransport.Transmission) approvalTransmissionResponse {
	response := approvalTransmissionResponse{
		PlanRef:             transmission.PlanRef,
		PlanHash:            transmission.PlanHash,
		Authority:           transmission.Authority,
		BusinessContextRef:  transmission.BusinessContextRef,
		Capability:          transmission.Capability,
		ParameterHash:       transmission.ParameterHash,
		Status:              string(transmission.Status),
		ExpiresAt:           transmission.ExpiresAt.UTC(),
		DeliveryAttempts:    transmission.DeliveryAttempts,
		LastDeliveryOutcome: string(transmission.LastDeliveryOutcome),
		Decision:            string(transmission.Decision),
		UpdatedAt:           transmission.UpdatedAt.UTC(),
	}
	if !transmission.DecidedAt.IsZero() {
		decidedAt := transmission.DecidedAt.UTC()
		response.DecidedAt = &decidedAt
	}
	if !transmission.RevokedAt.IsZero() {
		revokedAt := transmission.RevokedAt.UTC()
		response.RevokedAt = &revokedAt
	}
	return response
}

func (h *approvalTransportHandler) transmit(w http.ResponseWriter, r *http.Request) {
	trustedCtx, ok := h.begin(w, r)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	request, err := runtime.DecodeApprovalRequest(body)
	if err != nil {
		h.rejectDecode(w, r, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, err)
		return
	}
	if _, err := NewRequestContext(trustedCtx, request.RequestID, request.TraceID); err != nil {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	transmission, err := h.service.Transmit(r.Context(), trustedCtx.Principal, request)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, transmissionResponse(transmission))
}

func (h *approvalTransportHandler) status(w http.ResponseWriter, r *http.Request) {
	trustedCtx, ok := h.begin(w, r)
	if !ok {
		return
	}
	transmission, err := h.service.GetStatus(r.Context(), trustedCtx.Principal, r.PathValue("plan_ref"))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, transmissionResponse(transmission))
}

func (h *approvalTransportHandler) recordEvidence(w http.ResponseWriter, r *http.Request) {
	trustedCtx, ok := h.begin(w, r)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	var envelope struct {
		RequestID string                   `json:"request_id"`
		TraceID   string                   `json:"trace_id"`
		Evidence  runtime.ApprovalEvidence `json:"evidence"`
	}
	if !h.decodeStrictEnvelope(w, r, trustedCtx, body, &envelope, "evidence") {
		return
	}
	if _, err := NewRequestContext(trustedCtx, envelope.RequestID, envelope.TraceID); err != nil {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, err := h.service.RecordEvidence(r.Context(), trustedCtx.Principal, envelope.Evidence); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	transmission, err := h.service.GetStatus(r.Context(), trustedCtx.Principal, envelope.Evidence.PlanRef)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, transmissionResponse(transmission))
}

func (h *approvalTransportHandler) revoke(w http.ResponseWriter, r *http.Request) {
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
		Reason    string `json:"reason"`
	}
	if !h.decodeStrictEnvelope(w, r, trustedCtx, body, &envelope, "reason") {
		return
	}
	if _, err := NewRequestContext(trustedCtx, envelope.RequestID, envelope.TraceID); err != nil {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	transmission, err := h.service.Revoke(r.Context(), trustedCtx.Principal, r.PathValue("plan_ref"), envelope.Reason)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, transmissionResponse(transmission))
}

// begin resolves the ingress trusted context. Handlers never authenticate on
// their own.
func (h *approvalTransportHandler) begin(w http.ResponseWriter, r *http.Request) (trust.Context, bool) {
	setNoStore(w)
	trustedCtx, status := trustedRequestContext(r)
	if status != 0 {
		writeApprovalTransportError(w, status, "request_failed")
		return trust.Context{}, false
	}
	if trustedCtx.Principal.TenantRef != h.enterpriseID {
		writeApprovalTransportError(w, http.StatusUnauthorized, "request_failed")
		return trust.Context{}, false
	}
	return trustedCtx, true
}

// readBody enforces the single JSON media type and the request size bound.
func (h *approvalTransportHandler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeApprovalTransportError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeApprovalTransportError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxApprovalTransportRequestBytes))
	if err != nil {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

// decodeStrictEnvelope decodes a correlation envelope strictly: the body must
// be a JSON object, trusted-identity keys are rejected (and audited
// distinctly), the required member must be present and unknown members fail.
func (h *approvalTransportHandler) decodeStrictEnvelope(w http.ResponseWriter, r *http.Request, trustedCtx trust.Context, body []byte, out any, requiredMember string) bool {
	var probe any
	if err := json.Unmarshal(body, &probe); err != nil {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	root, isObject := probe.(map[string]any)
	if !isObject {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if key, forged := findForbiddenIdentityKey(root); forged {
		_ = key
		auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.forged_body_field")
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if _, present := root[requiredMember]; !present {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

// findForbiddenIdentityKey mirrors the SDK strict-decoder identity ban for
// the handler-local envelopes: request JSON never carries trusted identity
// or connector topology.
func findForbiddenIdentityKey(value any) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			switch key {
			case "enterprise_id", "actor_user_id", "connector_instance_id":
				return key, true
			}
			if strings.Contains(key, "enterprise") || strings.HasPrefix(key, "connector_") {
				return key, true
			}
			if found, forged := findForbiddenIdentityKey(child); forged {
				return found, true
			}
		}
	case []any:
		for _, child := range typed {
			if found, forged := findForbiddenIdentityKey(child); forged {
				return found, true
			}
		}
	}
	return "", false
}

// rejectDecode maps SDK strict-decoder failures; forged identity is audited
// distinctly and every rejection uses the same fixed envelope.
func (h *approvalTransportHandler) rejectDecode(w http.ResponseWriter, r *http.Request, tenantRef, principalRef string, err error) {
	if errors.Is(err, runtime.ErrTrustedIdentityInRequest) {
		auditTrustViolation(r.Context(), h.audit, tenantRef, principalRef, "trusted_context.forged_body_field")
	}
	writeApprovalTransportError(w, http.StatusBadRequest, "invalid_request")
}

// writeServiceError maps transmission service errors onto fixed opaque
// envelopes. A transport failure is NOT an error here: Transmit returns the
// pending transmission and this mapper never sees it. The joined internal
// cause is LOGGED (0D evidence-handler precedent) before it is discarded -
// it carries only sentinels, refs and coded reasons, never plan content or
// attestation values.
func (h *approvalTransportHandler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	status, reason := http.StatusServiceUnavailable, "approval_unavailable"
	switch {
	case errors.Is(err, approvaltransport.ErrInvalidInput):
		status, reason = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, approvaltransport.ErrNotFound):
		status, reason = http.StatusNotFound, "approval_not_found"
	case errors.Is(err, approvaltransport.ErrPlanConflict), errors.Is(err, approvaltransport.ErrEvidenceReplay):
		status, reason = http.StatusConflict, "approval_conflict"
	case errors.Is(err, approvaltransport.ErrTransmissionRevoked):
		status, reason = http.StatusConflict, "approval_conflict"
	case errors.Is(err, approvaltransport.ErrCallerUntrusted), errors.Is(err, approvaltransport.ErrEvidenceRejected), errors.Is(err, approvaltransport.ErrEvidenceExpired):
		status, reason = http.StatusForbidden, "approval_rejected"
	}
	h.logger.WarnContext(r.Context(), "approval.request_failed",
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.String("reason", reason),
		slog.String("error", err.Error()),
	)
	writeApprovalTransportError(w, status, reason)
}

func writeApprovalTransportError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"error": reason})
}
