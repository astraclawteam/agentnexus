package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
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

type ScopedGrantAuthorizer struct {
	owners    GrantResourceOwnerResolver
	evaluator atlasDecisionEvaluator
}

func NewScopedGrantAuthorizer(owners GrantResourceOwnerResolver, evaluator atlasDecisionEvaluator) *ScopedGrantAuthorizer {
	return &ScopedGrantAuthorizer{owners: owners, evaluator: evaluator}
}

func (a *ScopedGrantAuthorizer) AuthorizeGrant(ctx context.Context, actor tickets.Actor, input tickets.CreateStepGrantInput) (tickets.GrantAuthorization, error) {
	if a == nil || a.owners == nil || a.evaluator == nil || input.ResourceType != string(policy.ResourceDreamEvidence) || input.Action != string(policy.ActionDreamEvidenceRead) {
		return tickets.GrantAuthorization{}, tickets.ErrGrantDenied
	}
	owner, err := a.owners.ResolveGrantResourceOwner(ctx, actor.EnterpriseID, input.ResourceType, input.ResourceID)
	if err != nil {
		return tickets.GrantAuthorization{}, tickets.ErrGrantUnavailable
	}
	if owner.EnterpriseID != actor.EnterpriseID || owner.ResourceType != input.ResourceType || owner.ResourceID != input.ResourceID || owner.OrgUnitID != input.OrgUnitID || owner.OrgVersion != input.OrgVersion {
		return tickets.GrantAuthorization{}, tickets.ErrGrantDenied
	}
	decision, err := a.evaluator.Evaluate(ctx, policy.ScopedRequest{EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, OrgUnitID: input.OrgUnitID, OrgVersion: input.OrgVersion, ResourceType: policy.ResourceDreamEvidence, ResourceID: input.ResourceID, Action: policy.ActionDreamEvidenceRead})
	if err != nil {
		return tickets.GrantAuthorization{}, tickets.ErrGrantUnavailable
	}
	allowed := decision.Decision == policy.DecisionAllow && decision.OrgVersion == input.OrgVersion
	return tickets.GrantAuthorization{Allowed: allowed, EnterpriseID: actor.EnterpriseID, OrgVersion: decision.OrgVersion, OrgUnitIDs: append([]string(nil), decision.OrgUnitIDs...)}, nil
}

const maxGrantRequestBytes = 16 << 10

type grantService interface {
	AuthorizeAndCreateGrant(context.Context, tickets.Actor, tickets.CreateStepGrantInput) (tickets.StepGrant, error)
	VerifyGrant(context.Context, tickets.VerifyStepGrantInput) (tickets.StepGrant, error)
}

type grantHandler struct {
	auth    *authorizationHandler
	service grantService
}

func newGrantHandler(auth *authorizationHandler, service grantService) (*grantHandler, error) {
	if auth == nil || service == nil {
		return nil, errors.New("grant dependencies incomplete")
	}
	return &grantHandler{auth: auth, service: service}, nil
}

func (h *grantHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/step-grants", h.create)
	mux.HandleFunc("POST /v1/tickets/verify", h.verify)
}

func (h *grantHandler) create(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	actor, status := h.auth.authenticateActor(r)
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
		OrgUnitID    string `json:"org_unit_id"`
		OrgVersion   int64  `json:"org_version"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		Action       string `json:"action"`
		TTLSeconds   int64  `json:"ttl_seconds"`
	}
	if !decodeExactGrantFields(fields, map[string]any{"case_ticket_id": &input.CaseTicketID, "org_unit_id": &input.OrgUnitID, "org_version": &input.OrgVersion, "resource_type": &input.ResourceType, "resource_id": &input.ResourceID, "action": &input.Action, "ttl_seconds": &input.TTLSeconds}) || input.TTLSeconds <= 0 || input.TTLSeconds > int64((24*time.Hour)/time.Second) {
		writeGrantError(w, http.StatusBadRequest)
		return
	}
	grant, err := h.service.AuthorizeAndCreateGrant(r.Context(), tickets.Actor{EnterpriseID: actor.EnterpriseID, UserID: actor.UserID, CaseTicketID: actor.CaseTicketID}, tickets.CreateStepGrantInput{CaseTicketID: input.CaseTicketID, OrgUnitID: input.OrgUnitID, OrgVersion: input.OrgVersion, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, TTL: time.Duration(input.TTLSeconds) * time.Second})
	if err != nil {
		writeGrantServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": grant.Token, "expires_at": grant.ExpiresAt, "resource_type": grant.ResourceType, "resource_id": grant.ResourceID, "action": grant.Action, "scopes": grant.Scopes})
}

func (h *grantHandler) verify(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	actor, status := h.auth.authenticateActor(r)
	if status != 0 {
		writeGrantError(w, status)
		return
	}
	fields, ok := decodeUniqueGrantObject(w, r)
	if !ok {
		return
	}
	var input struct{ Token, ResourceType, ResourceID, Action, Scope string }
	if !decodeExactGrantFields(fields, map[string]any{"token": &input.Token, "resource_type": &input.ResourceType, "resource_id": &input.ResourceID, "action": &input.Action, "scope": &input.Scope}) {
		writeGrantError(w, http.StatusBadRequest)
		return
	}
	grant, err := h.service.VerifyGrant(r.Context(), tickets.VerifyStepGrantInput{Token: input.Token, EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Scope: input.Scope})
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

func decodeExactGrantFields(fields map[string]json.RawMessage, targets map[string]any) bool {
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
