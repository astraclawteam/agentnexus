package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const maxEvidenceRequestBytes = 64 << 10

// EvidenceService is the semantic evidence runtime consumed by the gateway
// (implemented by *evidence.Service). Identity and authorization derive from
// the ingress-resolved trusted context only.
type EvidenceService interface {
	Locate(ctx context.Context, principal runtime.PrincipalContext, authz evidence.Authorization, req runtime.EvidenceRequest) (evidence.LocateResult, error)
	Read(ctx context.Context, principal runtime.PrincipalContext, authz evidence.Authorization, req runtime.EvidenceReadRequest) (evidence.ReadResult, error)
}

// evidenceHandler serves POST /v1/runtime/locate and POST /v1/runtime/read.
// Request bodies are decoded through the frozen SDK strict decoders (unknown
// fields, trusted-identity fields and connector selectors are rejected);
// every failure envelope is fixed and opaque.
type evidenceHandler struct {
	enterpriseID string
	service      EvidenceService
	audit        BrowserAuditSink
}

func newEvidenceHandler(enterpriseID string, service EvidenceService, audit BrowserAuditSink) (*evidenceHandler, error) {
	if enterpriseID == "" || service == nil {
		return nil, errors.New("evidence dependencies incomplete")
	}
	return &evidenceHandler{enterpriseID: enterpriseID, service: service, audit: audit}, nil
}

func (h *evidenceHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/runtime/locate", h.locate)
	mux.HandleFunc("POST /v1/runtime/read", h.read)
}

func (h *evidenceHandler) locate(w http.ResponseWriter, r *http.Request) {
	trustedCtx, authz, ok := h.begin(w, r)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	request, err := runtime.DecodeEvidenceRequest(body)
	if err != nil {
		h.rejectDecode(w, r, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, err)
		return
	}
	if _, err := NewRequestContext(trustedCtx, request.RequestID, request.TraceID); err != nil {
		writeEvidenceError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.service.Locate(r.Context(), trustedCtx.Principal, authz, request)
	if err != nil {
		writeEvidenceServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *evidenceHandler) read(w http.ResponseWriter, r *http.Request) {
	trustedCtx, authz, ok := h.begin(w, r)
	if !ok {
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	request, err := runtime.DecodeEvidenceReadRequest(body)
	if err != nil {
		h.rejectDecode(w, r, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, err)
		return
	}
	if _, err := NewRequestContext(trustedCtx, request.RequestID, request.TraceID); err != nil {
		writeEvidenceError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.service.Read(r.Context(), trustedCtx.Principal, authz, request)
	if err != nil {
		writeEvidenceServiceError(w, r, err)
		return
	}
	// The read envelope: a deny carries the decision only; an allow always
	// states its cache provenance (source version, as-of time, explicit
	// served-from-cache marker) — never masquerading as real-time data.
	payload := map[string]any{"decision": result.Decision}
	if result.Decision == evidence.DecisionAllow {
		payload["data"] = result.Data
		payload["source_version"] = result.SourceVersion
		payload["as_of"] = result.AsOf.UTC()
		payload["served_from_cache"] = result.ServedFromCache
		if result.ContinuationRef != "" {
			payload["continuation_ref"] = result.ContinuationRef
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

// begin resolves the ingress trusted context and derives the caller's
// evidence authorization envelope. Handlers never authenticate on their own.
func (h *evidenceHandler) begin(w http.ResponseWriter, r *http.Request) (trust.Context, evidence.Authorization, bool) {
	setNoStore(w)
	trustedCtx, status := trustedRequestContext(r)
	if status != 0 {
		writeEvidenceError(w, status, "request_failed")
		return trust.Context{}, evidence.Authorization{}, false
	}
	if trustedCtx.Principal.TenantRef != h.enterpriseID {
		writeEvidenceError(w, http.StatusUnauthorized, "request_failed")
		return trust.Context{}, evidence.Authorization{}, false
	}
	return trustedCtx, evidence.Authorization{
		OrgVersion:                 trustedCtx.OrgVersion,
		ConnectorCapabilityAllowed: trustedCtx.ConnectorCapabilityAllowed,
	}, true
}

// readBody enforces the single JSON media type and the request size bound.
func (h *evidenceHandler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeEvidenceError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeEvidenceError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEvidenceRequestBytes))
	if err != nil {
		writeEvidenceError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

// rejectDecode maps strict-decoder failures. Attempts to smuggle trusted
// identity or connector topology are audited distinctly; every rejection uses
// the same fixed envelope (no echo of caller content).
func (h *evidenceHandler) rejectDecode(w http.ResponseWriter, r *http.Request, tenantRef, principalRef string, err error) {
	if errors.Is(err, runtime.ErrTrustedIdentityInRequest) {
		auditTrustViolation(r.Context(), h.audit, tenantRef, principalRef, "trusted_context.forged_body_field")
	}
	writeEvidenceError(w, http.StatusBadRequest, "invalid_request")
}

// writeEvidenceServiceError maps service errors onto fixed opaque envelopes.
// The joined internal cause is LOGGED before it is discarded (it carries only
// sentinels, refs and coded reasons — never content or source topology, which
// the service-level canary tests assert on the same error texts).
func writeEvidenceServiceError(w http.ResponseWriter, r *http.Request, err error) {
	status, reason := http.StatusServiceUnavailable, "evidence_unavailable"
	switch {
	case errors.Is(err, evidence.ErrInvalidRequest):
		status, reason = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, evidence.ErrContentTooLarge):
		// Explicit bound failure: never silent truncation, never a partial
		// result.
		status, reason = http.StatusUnprocessableEntity, "content_bound_exceeded"
	case errors.Is(err, evidence.ErrDenied):
		status, reason = http.StatusForbidden, "evidence_denied"
	}
	slog.WarnContext(r.Context(), "evidence.request_failed",
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.String("reason", reason),
		slog.String("error", err.Error()),
	)
	writeEvidenceError(w, status, reason)
}

func writeEvidenceError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"error": reason})
}
