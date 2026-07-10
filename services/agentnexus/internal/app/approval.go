package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
)

const maxApprovalRequestBytes = 16 << 10

type approvalDependencies struct {
	EnterpriseID string
	Sessions     authorizationSessionResolver
	TicketActors TicketActorAuthenticator
	Source       ApprovalSnapshotSource
	Store        ApprovalRouteStore
	Policy       approval.Policy
}

type approvalHandler struct {
	actor  *authorizationHandler
	source ApprovalSnapshotSource
	store  ApprovalRouteStore
	policy approval.Policy
}

type approvalResolveRequest struct {
	OrgVersion              int64
	OrgUnitID               string
	ResourceType            string
	ResourceID              string
	Action                  string
	ChangedFields           []string
	ImpactedOrgUnitIDs      []string
	ImpactedUserCount       int
	PublishedBehaviorChange bool
	ExternalSideEffect      bool
	RequestedRisk           approval.RiskLevel
}

func newApprovalHandler(deps approvalDependencies) (*approvalHandler, error) {
	if !canonicalAuthorizationValue(deps.EnterpriseID) || deps.Sessions == nil || deps.Source == nil || deps.Store == nil {
		return nil, errors.New("approval dependencies incomplete")
	}
	return &approvalHandler{actor: &authorizationHandler{enterpriseID: deps.EnterpriseID, sessions: deps.Sessions, ticketActors: deps.TicketActors}, source: deps.Source, store: deps.Store, policy: deps.Policy}, nil
}

func (h *approvalHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/approvals/resolve", h.resolve)
}

func (h *approvalHandler) resolve(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	actor, status := h.actor.authenticateActor(r)
	if status != 0 {
		writeAuthorizationError(w, status)
		return
	}
	input, ok := decodeApprovalRequest(w, r)
	if !ok {
		return
	}
	request := approval.Request{EnterpriseID: actor.EnterpriseID, RequesterUserID: actor.UserID, OrgVersion: input.OrgVersion, OrgUnitID: input.OrgUnitID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Risk: approval.RiskInput{ChangedFields: input.ChangedFields, ImpactedOrgUnitIDs: input.ImpactedOrgUnitIDs, ImpactedUserCount: input.ImpactedUserCount, PublishedBehaviorChange: input.PublishedBehaviorChange, ExternalSideEffect: input.ExternalSideEffect, RequestedRisk: input.RequestedRisk}}
	loaded, err := h.source.LoadApprovalSnapshot(r.Context(), actor.EnterpriseID, input.OrgVersion, actor.UserID)
	if err != nil {
		writeAuthorizationError(w, http.StatusServiceUnavailable)
		return
	}
	route, err := approval.NewResolver(loaded.Permissions, h.policy).Resolve(r.Context(), request, loaded.Snapshot)
	if err != nil {
		writeAuthorizationError(w, http.StatusServiceUnavailable)
		return
	}
	if err := h.store.Record(r.Context(), request, route); err != nil {
		writeAuthorizationError(w, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, route)
}

func decodeApprovalRequest(w http.ResponseWriter, r *http.Request) (approvalResolveRequest, bool) {
	var target approvalResolveRequest
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeAuthorizationError(w, http.StatusUnsupportedMediaType)
		return target, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeAuthorizationError(w, http.StatusUnsupportedMediaType)
		return target, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxApprovalRequestBytes+1))
	if err != nil {
		writeAuthorizationError(w, http.StatusBadRequest)
		return target, false
	}
	if len(body) > maxApprovalRequestBytes {
		writeAuthorizationError(w, http.StatusRequestEntityTooLarge)
		return target, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		writeAuthorizationError(w, http.StatusBadRequest)
		return target, false
	}
	seen := make(map[string]struct{}, 11)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, valid := keyToken.(string)
		if err != nil || !valid {
			writeAuthorizationError(w, http.StatusBadRequest)
			return target, false
		}
		if _, duplicate := seen[key]; duplicate {
			writeAuthorizationError(w, http.StatusBadRequest)
			return target, false
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || string(raw) == "null" {
			writeAuthorizationError(w, http.StatusBadRequest)
			return target, false
		}
		switch key {
		case "org_version":
			err = json.Unmarshal(raw, &target.OrgVersion)
		case "org_unit_id":
			err = json.Unmarshal(raw, &target.OrgUnitID)
		case "resource_type":
			err = json.Unmarshal(raw, &target.ResourceType)
		case "resource_id":
			err = json.Unmarshal(raw, &target.ResourceID)
		case "action":
			err = json.Unmarshal(raw, &target.Action)
		case "changed_fields":
			err = json.Unmarshal(raw, &target.ChangedFields)
		case "impacted_org_unit_ids":
			err = json.Unmarshal(raw, &target.ImpactedOrgUnitIDs)
		case "impacted_user_count":
			err = json.Unmarshal(raw, &target.ImpactedUserCount)
		case "published_behavior_change":
			err = json.Unmarshal(raw, &target.PublishedBehaviorChange)
		case "external_side_effect":
			err = json.Unmarshal(raw, &target.ExternalSideEffect)
		case "requested_risk":
			err = json.Unmarshal(raw, &target.RequestedRisk)
		default:
			writeAuthorizationError(w, http.StatusBadRequest)
			return target, false
		}
		if err != nil {
			writeAuthorizationError(w, http.StatusBadRequest)
			return target, false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		writeAuthorizationError(w, http.StatusBadRequest)
		return target, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeAuthorizationError(w, http.StatusBadRequest)
		return target, false
	}
	for _, required := range []string{"org_version", "org_unit_id", "resource_type", "resource_id", "action"} {
		if _, exists := seen[required]; !exists {
			writeAuthorizationError(w, http.StatusBadRequest)
			return target, false
		}
	}
	if target.ChangedFields == nil {
		target.ChangedFields = []string{}
	}
	if target.ImpactedOrgUnitIDs == nil {
		target.ImpactedOrgUnitIDs = []string{}
	}
	if !validApprovalInput(target) {
		writeAuthorizationError(w, http.StatusBadRequest)
		return target, false
	}
	return target, true
}

func validApprovalInput(input approvalResolveRequest) bool {
	if input.OrgVersion < 1 || input.ImpactedUserCount < 0 || !canonicalAuthorizationValue(input.OrgUnitID) || !canonicalAuthorizationValue(input.ResourceType) || !canonicalAuthorizationValue(input.ResourceID) || !canonicalAuthorizationValue(input.Action) {
		return false
	}
	if input.RequestedRisk != "" && input.RequestedRisk != approval.RiskLow && input.RequestedRisk != approval.RiskMedium && input.RequestedRisk != approval.RiskHigh {
		return false
	}
	return canonicalUniqueStrings(input.ChangedFields) && canonicalUniqueStrings(input.ImpactedOrgUnitIDs)
}

func canonicalUniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
