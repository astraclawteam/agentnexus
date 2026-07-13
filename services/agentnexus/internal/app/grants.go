package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

type GrantResourceOwner struct {
	EnterpriseID string
	ResourceType string
	ResourceID   string
	OrgUnitID    string
	OrgVersion   int64
}

type GrantResourceOwnerResolver interface {
	ResolveGrantResourceOwner(context.Context, string, string, string) (GrantResourceOwner, error)
}

// ScopedGrantAuthorizer authorizes step grants against the server-resolved
// resource owner and the sealed capability policy. The organization
// placement and version never come from the caller: placement is the owner
// registry's, the version is the actor's sealed ingress version.
type ScopedGrantAuthorizer struct {
	owners    GrantResourceOwnerResolver
	evaluator capabilityDecisionEvaluator
}

func NewScopedGrantAuthorizer(owners GrantResourceOwnerResolver, evaluator capabilityDecisionEvaluator) *ScopedGrantAuthorizer {
	return &ScopedGrantAuthorizer{owners: owners, evaluator: evaluator}
}

func (a *ScopedGrantAuthorizer) AuthorizeGrant(ctx context.Context, actor tickets.Actor, input tickets.CreateStepGrantInput) (tickets.GrantAuthorization, error) {
	if a == nil || a.owners == nil || a.evaluator == nil || input.ResourceType != string(policy.ResourceDreamEvidence) || input.Action != "read" || actor.OrgVersion < 1 {
		return tickets.GrantAuthorization{}, tickets.ErrGrantDenied
	}
	owner, err := a.owners.ResolveGrantResourceOwner(ctx, actor.EnterpriseID, input.ResourceType, input.ResourceID)
	if err != nil {
		return tickets.GrantAuthorization{}, tickets.ErrGrantUnavailable
	}
	if owner.EnterpriseID != actor.EnterpriseID || owner.ResourceType != input.ResourceType || owner.ResourceID != input.ResourceID || !canonicalAuthorizationValue(owner.OrgUnitID) || owner.OrgVersion != actor.OrgVersion {
		return tickets.GrantAuthorization{}, tickets.ErrGrantDenied
	}
	decision, err := a.evaluator.Evaluate(ctx, policy.CapabilityRequest{
		TenantRef:        actor.EnterpriseID,
		PrincipalRef:     actor.UserID,
		SealedOrgVersion: actor.OrgVersion,
		ResourceType:     policy.ResourceDreamEvidence,
		ResourceID:       input.ResourceID,
		Capability:       policy.CapabilityEvidenceRead,
		TargetOrgUnitID:  owner.OrgUnitID,
	})
	if err != nil {
		return tickets.GrantAuthorization{}, tickets.ErrGrantUnavailable
	}
	allowed := decision.Decision == policy.DecisionAllow &&
		decision.OrgVersion == actor.OrgVersion &&
		decision.RiskLevel == policy.CapabilityRiskHigh &&
		decision.FallbackCapability == "" &&
		len(decision.MaskFields) == 0 &&
		len(decision.Permissions) == 1 && decision.Permissions[0] == policy.PermissionApproveHighRisk &&
		validGrantEvidenceScopes(decision.OrgUnitIDs)
	return tickets.GrantAuthorization{Allowed: allowed, EnterpriseID: actor.EnterpriseID, OrgVersion: decision.OrgVersion, OrgUnitID: owner.OrgUnitID}, nil
}

func validGrantEvidenceScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > policy.MaxSealedMemberships {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope == "" || strings.TrimSpace(scope) != scope {
			return false
		}
		if _, exists := seen[scope]; exists {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}

const maxGrantRequestBytes = 16 << 10

type grantService interface {
	AuthorizeAndCreateGrant(context.Context, tickets.Actor, tickets.CreateStepGrantInput) (tickets.StepGrant, error)
	VerifyGrant(context.Context, tickets.Actor, tickets.VerifyStepGrantInput) (tickets.StepGrant, error)
}

type grantHandler struct {
	enterpriseID string
	service      grantService
	audit        BrowserAuditSink
}

func newGrantHandler(enterpriseID string, service grantService, audit BrowserAuditSink) (*grantHandler, error) {
	if enterpriseID == "" || service == nil {
		return nil, errors.New("grant dependencies incomplete")
	}
	return &grantHandler{enterpriseID: enterpriseID, service: service, audit: audit}, nil
}

func (h *grantHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/step-grants", h.create)
	mux.HandleFunc("POST /v1/tickets/verify", h.verify)
}

// grantActor derives the tickets actor from the immutable trusted context.
func (h *grantHandler) grantActor(r *http.Request) (tickets.Actor, trust.Context, int) {
	trustedCtx, status := trustedRequestContext(r)
	if status != 0 {
		return tickets.Actor{}, trust.Context{}, status
	}
	if trustedCtx.Principal.TenantRef != h.enterpriseID {
		return tickets.Actor{}, trust.Context{}, http.StatusUnauthorized
	}
	return tickets.Actor{
		EnterpriseID: trustedCtx.Principal.TenantRef,
		UserID:       trustedCtx.Principal.PrincipalRef,
		CaseTicketID: trustedCtx.CaseTicketRef,
		OrgVersion:   trustedCtx.OrgVersion,
	}, trustedCtx, 0
}

func (h *grantHandler) create(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	actor, trustedCtx, status := h.grantActor(r)
	if status != 0 {
		writeGrantError(w, status)
		return
	}
	fields, ok := decodeUniqueGrantObject(w, r)
	if !ok {
		return
	}
	var input struct {
		CaseTicketID string `json:"case_ticket_id"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		Action       string `json:"action"`
		TTLSeconds   int64  `json:"ttl_seconds"`
	}
	// ttl_seconds is bounded here only to the frozen contract's 1..86400 range.
	// The requested TTL is then clamped DOWN to tickets.MaxStepGrantTTL by
	// AuthorizeAndCreateGrant; this cap is not silent — the response's
	// expires_at reflects the actually granted (capped) lifetime, so the caller
	// always sees the true expiry rather than the value it asked for.
	if !h.decodeExactGrantFields(r, trustedCtx, fields, map[string]any{"case_ticket_id": &input.CaseTicketID, "resource_type": &input.ResourceType, "resource_id": &input.ResourceID, "action": &input.Action, "ttl_seconds": &input.TTLSeconds}) || input.TTLSeconds <= 0 || input.TTLSeconds > int64((24*time.Hour)/time.Second) {
		writeGrantError(w, http.StatusBadRequest)
		return
	}
	// The business-context lineage in the body may never contradict the
	// credential's own Case Ticket: body values never win.
	if actor.CaseTicketID != "" && input.CaseTicketID != actor.CaseTicketID {
		auditTrustViolation(r.Context(), h.audit, actor.EnterpriseID, actor.UserID, "trusted_context.lineage_conflict")
		writeGrantError(w, http.StatusForbidden)
		return
	}
	grant, err := h.service.AuthorizeAndCreateGrant(r.Context(), actor, tickets.CreateStepGrantInput{CaseTicketID: input.CaseTicketID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, TTL: time.Duration(input.TTLSeconds) * time.Second})
	if err != nil {
		writeGrantServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": grant.Token, "expires_at": grant.ExpiresAt, "resource_type": grant.ResourceType, "resource_id": grant.ResourceID, "action": grant.Action, "scopes": grant.Scopes})
}

func (h *grantHandler) verify(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	actor, trustedCtx, status := h.grantActor(r)
	if status != 0 {
		writeGrantError(w, status)
		return
	}
	fields, ok := decodeUniqueGrantObject(w, r)
	if !ok {
		return
	}
	var input struct{ Token, ResourceType, ResourceID, Action, Scope string }
	if !h.decodeExactGrantFields(r, trustedCtx, fields, map[string]any{"token": &input.Token, "resource_type": &input.ResourceType, "resource_id": &input.ResourceID, "action": &input.Action, "scope": &input.Scope}) {
		writeGrantError(w, http.StatusBadRequest)
		return
	}
	grant, err := h.service.VerifyGrant(r.Context(), actor, tickets.VerifyStepGrantInput{Token: input.Token, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scope: input.Scope})
	if err != nil {
		writeGrantServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "step_grant_id": grant.ID, "expires_at": grant.ExpiresAt, "scopes": grant.Scopes})
}

func decodeUniqueGrantObject(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool) {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		writeGrantError(w, http.StatusUnsupportedMediaType)
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != "application/json" {
		writeGrantError(w, http.StatusUnsupportedMediaType)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxGrantRequestBytes+1))
	if err != nil {
		writeGrantError(w, http.StatusBadRequest)
		return nil, false
	}
	if len(body) > maxGrantRequestBytes {
		writeGrantError(w, http.StatusRequestEntityTooLarge)
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		writeGrantError(w, http.StatusBadRequest)
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, valid := keyToken.(string)
		if err != nil || !valid {
			writeGrantError(w, http.StatusBadRequest)
			return nil, false
		}
		if _, duplicate := fields[key]; duplicate {
			writeGrantError(w, http.StatusBadRequest)
			return nil, false
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || string(raw) == "null" {
			writeGrantError(w, http.StatusBadRequest)
			return nil, false
		}
		fields[key] = raw
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		writeGrantError(w, http.StatusBadRequest)
		return nil, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeGrantError(w, http.StatusBadRequest)
		return nil, false
	}
	return fields, true
}

// decodeExactGrantFields decodes the exact expected member set. A member
// carrying trusted identity or organization facts is rejected AND audited;
// body values never win.
func (h *grantHandler) decodeExactGrantFields(r *http.Request, trustedCtx trust.Context, fields map[string]json.RawMessage, targets map[string]any) bool {
	for key := range fields {
		if _, expected := targets[key]; !expected && trust.ForgedIdentityField(key) {
			auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.forged_body_field")
			return false
		}
	}
	if len(fields) != len(targets) {
		return false
	}
	for key, target := range targets {
		raw, ok := fields[key]
		if !ok || json.Unmarshal(raw, target) != nil {
			return false
		}
	}
	return true
}

func writeGrantServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tickets.ErrGrantDenied):
		writeGrantError(w, http.StatusForbidden)
	case errors.Is(err, tickets.ErrInvalidGrant):
		writeGrantError(w, http.StatusBadRequest)
	default:
		writeGrantError(w, http.StatusServiceUnavailable)
	}
}

func writeGrantError(w http.ResponseWriter, status int) {
	writeJSON(w, status, map[string]string{"error": "request_failed"})
}
