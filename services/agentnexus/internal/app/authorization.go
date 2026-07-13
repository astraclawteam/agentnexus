package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const maxAuthorizationRequestBytes = 16 << 10

type capabilityDecisionEvaluator interface {
	Evaluate(context.Context, policy.CapabilityRequest) (policy.PermissionDecision, error)
}

type authorizationDependencies struct {
	EnterpriseID string
	Evaluator    capabilityDecisionEvaluator
	Audit        BrowserAuditSink
}

type authorizationHandler struct {
	enterpriseID string
	evaluator    capabilityDecisionEvaluator
	audit        BrowserAuditSink
}

// authorizationDecisionRequest is the frozen AuthorizationDecisionRequest
// shape: correlation, resource binding and capability only. Identity and
// organization facts derive from the verified trusted context.
type authorizationDecisionRequest struct {
	RequestID    string              `json:"request_id"`
	TraceID      string              `json:"trace_id"`
	ResourceType policy.ResourceType `json:"resource_type"`
	ResourceID   string              `json:"resource_id"`
	Capability   policy.Capability   `json:"capability"`
	Purpose      string              `json:"purpose"`
}

func newAuthorizationHandler(deps authorizationDependencies) (*authorizationHandler, error) {
	if deps.EnterpriseID == "" || deps.Evaluator == nil {
		return nil, errors.New("authorization dependencies incomplete")
	}
	return &authorizationHandler{enterpriseID: deps.EnterpriseID, evaluator: deps.Evaluator, audit: deps.Audit}, nil
}

func (h *authorizationHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/authorization/decisions", h.decide)
}

// trustedRequestContext returns the immutable credential-derived context the
// ingress middleware resolved, mapped onto a transport status on failure.
func trustedRequestContext(r *http.Request) (trust.Context, int) {
	resolved, err := trust.FromRequest(r)
	if err != nil {
		return trust.Context{}, trust.HTTPStatus(err)
	}
	return resolved, 0
}

// auditTrustViolation records a rejected trust input. Best-effort: an audit
// outage never turns a rejection into an acceptance.
func auditTrustViolation(ctx context.Context, sink BrowserAuditSink, enterpriseID, actorUserID, action string) {
	if sink == nil {
		return
	}
	auditCtx, cancel := boundedCleanupContext(ctx)
	defer cancel()
	_ = sink.AppendBrowserAudit(auditCtx, BrowserAuditEvent{EnterpriseID: enterpriseID, ActorUserID: actorUserID, Action: action, Decision: "deny"})
}

func (h *authorizationHandler) decide(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	trustedCtx, status := trustedRequestContext(r)
	if status != 0 {
		writeAuthorizationError(w, status)
		return
	}
	if trustedCtx.Principal.TenantRef != h.enterpriseID {
		writeAuthorizationError(w, http.StatusUnauthorized)
		return
	}

	var input authorizationDecisionRequest
	if !h.decodeAuthorizationRequest(w, r, trustedCtx, &input) {
		return
	}
	requestContext, err := NewRequestContext(trustedCtx, input.RequestID, input.TraceID)
	if err != nil {
		writeAuthorizationError(w, http.StatusBadRequest)
		return
	}

	if policy.IsConnectorCapability(input.Capability) && !trustedCtx.ConnectorCapabilityAllowed {
		auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.connector_capability_denied")
		writeJSON(w, http.StatusOK, policy.DeniedCapabilityDecision(trustedCtx.OrgVersion, policy.CapabilityRiskHigh))
		return
	}

	decision, err := h.evaluator.Evaluate(r.Context(), policy.CapabilityRequest{
		TenantRef:        requestContext.Principal.TenantRef,
		PrincipalRef:     requestContext.Principal.PrincipalRef,
		SealedOrgVersion: requestContext.OrgVersion,
		ResourceType:     input.ResourceType,
		ResourceID:       input.ResourceID,
		Capability:       input.Capability,
	})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, policy.DeniedCapabilityDecision(requestContext.OrgVersion, policy.CapabilityRiskHigh))
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func validAuthorizationResourceType(value policy.ResourceType) bool {
	switch value {
	case policy.ResourceKnowledge, policy.ResourceWorkflow, policy.ResourceService, policy.ResourceDreamEvidence:
		return true
	}
	return false
}

func (h *authorizationHandler) decodeAuthorizationRequest(w http.ResponseWriter, r *http.Request, trustedCtx trust.Context, target *authorizationDecisionRequest) bool {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeAuthorizationError(w, http.StatusUnsupportedMediaType)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeAuthorizationError(w, http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizationRequestBytes)
	decoder := json.NewDecoder(r.Body)
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		writeAuthorizationError(w, http.StatusBadRequest)
		return false
	}
	seen := make(map[string]struct{}, 6)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			writeAuthorizationError(w, http.StatusBadRequest)
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			writeAuthorizationError(w, http.StatusBadRequest)
			return false
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || string(raw) == "null" {
			writeAuthorizationError(w, http.StatusBadRequest)
			return false
		}
		switch key {
		case "request_id":
			err = json.Unmarshal(raw, &target.RequestID)
		case "trace_id":
			err = json.Unmarshal(raw, &target.TraceID)
		case "resource_type":
			err = json.Unmarshal(raw, &target.ResourceType)
		case "resource_id":
			err = json.Unmarshal(raw, &target.ResourceID)
		case "capability":
			err = json.Unmarshal(raw, &target.Capability)
		case "purpose":
			err = json.Unmarshal(raw, &target.Purpose)
		default:
			// Trusted identity and organization facts can never arrive in
			// request JSON: rejected AND audited; other unknown members are
			// plain schema violations.
			if trust.ForgedIdentityField(key) {
				auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.forged_body_field")
			}
			writeAuthorizationError(w, http.StatusBadRequest)
			return false
		}
		if err != nil {
			writeAuthorizationError(w, http.StatusBadRequest)
			return false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		writeAuthorizationError(w, http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeAuthorizationError(w, http.StatusBadRequest)
		return false
	}
	for _, required := range []string{"request_id", "resource_type", "resource_id", "capability"} {
		if _, exists := seen[required]; !exists {
			writeAuthorizationError(w, http.StatusBadRequest)
			return false
		}
	}
	if !canonicalAuthorizationValue(target.RequestID) || len(target.RequestID) > 128 ||
		(target.TraceID != "" && (!canonicalAuthorizationValue(target.TraceID) || len(target.TraceID) > 128)) ||
		!validAuthorizationResourceType(target.ResourceType) ||
		!canonicalAuthorizationValue(target.ResourceID) || len(target.ResourceID) > 256 ||
		!canonicalAuthorizationValue(string(target.Capability)) || len(target.Capability) > 256 ||
		len(target.Purpose) > 1024 {
		writeAuthorizationError(w, http.StatusBadRequest)
		return false
	}
	return true
}

func canonicalAuthorizationValue(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func writeAuthorizationError(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": "request_failed"})
}
