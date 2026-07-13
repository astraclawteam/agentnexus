package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
)

const maxApprovalRequestBytes = 16 << 10

type approvalDependencies struct {
	EnterpriseID  string
	Source        ApprovalSnapshotSource
	Store         ApprovalRouteStore
	FactsVerifier ChangeFactsVerifier
	Audit         BrowserAuditSink
}

type approvalHandler struct {
	enterpriseID string
	source       ApprovalSnapshotSource
	store        ApprovalRouteStore
	verifier     ChangeFactsVerifier
	audit        BrowserAuditSink
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
	FactsIssuedAt           time.Time
	FactsExpiresAt          time.Time
	FactsNonce              string
}

func newApprovalHandler(deps approvalDependencies) (*approvalHandler, error) {
	if !canonicalAuthorizationValue(deps.EnterpriseID) || deps.Source == nil || deps.Store == nil || deps.FactsVerifier == nil {
		return nil, errors.New("approval dependencies incomplete")
	}
	return &approvalHandler{enterpriseID: deps.EnterpriseID, source: deps.Source, store: deps.Store, verifier: deps.FactsVerifier, audit: deps.Audit}, nil
}

func (h *approvalHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/approvals/resolve", h.resolve)
}

func (h *approvalHandler) resolve(w http.ResponseWriter, r *http.Request) {
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
	// Identity comes ONLY from the ingress-resolved trusted context. The
	// governed-change facts (including their org_version / org_unit_id) are
	// the console BFF's attested payload; Task 0E replaces this resolver
	// with approval transmission and retires those body facts.
	actor := struct{ EnterpriseID, UserID string }{EnterpriseID: trustedCtx.Principal.TenantRef, UserID: trustedCtx.Principal.PrincipalRef}
	idempotencyHash, signature, ok := decodeApprovalHeaders(w, r)
	if !ok {
		return
	}
	input, ok := decodeApprovalRequest(w, r)
	if !ok {
		return
	}
	verificationInput := ChangeFactsVerificationInput{EnterpriseID: actor.EnterpriseID, ActorUserID: actor.UserID, OrgVersion: input.OrgVersion, OrgUnitID: input.OrgUnitID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, ChangedFields: input.ChangedFields, ImpactedOrgUnitIDs: input.ImpactedOrgUnitIDs, ImpactedUserCount: input.ImpactedUserCount, PublishedBehaviorChange: input.PublishedBehaviorChange, ExternalSideEffect: input.ExternalSideEffect, FactsIssuedAt: input.FactsIssuedAt, FactsExpiresAt: input.FactsExpiresAt, FactsNonce: input.FactsNonce, IdempotencyKeyHash: idempotencyHash, Signature: signature}
	replayHash, err := computeApprovalReplayHash(verificationInput, input.RequestedRisk)
	if err != nil {
		writeAuthorizationError(w, http.StatusBadRequest)
		return
	}
	replayed, found, err := h.store.LookupResolution(r.Context(), actor.EnterpriseID, idempotencyHash, replayHash)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrApprovalIdempotencyConflict) {
			status = http.StatusConflict
		}
		writeAuthorizationError(w, status)
		return
	}
	if found {
		writeJSON(w, http.StatusOK, replayed)
		return
	}
	facts, err := h.verifier.VerifyChangeFacts(r.Context(), verificationInput)
	if err != nil {
		writeAuthorizationError(w, http.StatusServiceUnavailable)
		return
	}
	request := approval.Request{EnterpriseID: actor.EnterpriseID, RequesterUserID: actor.UserID, OrgVersion: input.OrgVersion, OrgUnitID: input.OrgUnitID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, Action: input.Action, Facts: facts, RequestedRisk: input.RequestedRisk, IdempotencyHash: idempotencyHash, ReplayHash: replayHash}
	loaded, err := h.source.LoadApprovalSnapshot(r.Context(), actor.EnterpriseID, input.OrgVersion, actor.UserID)
	if err != nil {
		writeAuthorizationError(w, http.StatusServiceUnavailable)
		return
	}
	request.PolicyVersion = loaded.PolicyVersion
	route, err := approval.NewIndexedResolver(loaded.Policy).Resolve(r.Context(), request, loaded.Snapshot)
	if err != nil {
		writeAuthorizationError(w, http.StatusServiceUnavailable)
		return
	}
	storedRoute, err := h.store.RecordResolution(r.Context(), request, route)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrApprovalIdempotencyConflict) {
			status = http.StatusConflict
		}
		writeAuthorizationError(w, status)
		return
	}
	writeJSON(w, http.StatusOK, storedRoute)
}

func decodeApprovalHeaders(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	keys := r.Header.Values("Idempotency-Key")
	signatures := r.Header.Values("X-Approval-Facts-Attestation")
	if len(keys) != 1 || len(signatures) != 1 || len(keys[0]) < 16 || len(keys[0]) > 128 || strings.TrimSpace(keys[0]) != keys[0] || strings.ContainsAny(keys[0], "\r\n\t") || signatures[0] == "" || len(signatures[0]) > 256 || strings.TrimSpace(signatures[0]) != signatures[0] {
		writeAuthorizationError(w, http.StatusBadRequest)
		return "", "", false
	}
	sum := sha256.Sum256([]byte(keys[0]))
	return hex.EncodeToString(sum[:]), signatures[0], true
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
		case "facts_issued_at":
			err = json.Unmarshal(raw, &target.FactsIssuedAt)
		case "facts_expires_at":
			err = json.Unmarshal(raw, &target.FactsExpiresAt)
		case "facts_nonce":
			err = json.Unmarshal(raw, &target.FactsNonce)
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
	for _, required := range []string{"org_version", "org_unit_id", "resource_type", "resource_id", "action", "changed_fields", "impacted_org_unit_ids", "impacted_user_count", "published_behavior_change", "external_side_effect", "requested_risk", "facts_issued_at", "facts_expires_at", "facts_nonce"} {
		if _, exists := seen[required]; !exists {
			writeAuthorizationError(w, http.StatusBadRequest)
			return target, false
		}
	}
	if !validApprovalInput(target) {
		writeAuthorizationError(w, http.StatusBadRequest)
		return target, false
	}
	return target, true
}

func validApprovalInput(input approvalResolveRequest) bool {
	if input.OrgVersion < 1 || input.ImpactedUserCount < 0 || input.ChangedFields == nil || input.ImpactedOrgUnitIDs == nil || input.FactsIssuedAt.IsZero() || input.FactsExpiresAt.IsZero() || len(input.FactsNonce) < 16 || !canonicalAuthorizationValue(input.FactsNonce) || !canonicalAuthorizationValue(input.OrgUnitID) || !canonicalAuthorizationValue(input.ResourceType) || !canonicalAuthorizationValue(input.ResourceID) || !canonicalAuthorizationValue(input.Action) {
		return false
	}
	if input.RequestedRisk != approval.RiskLow && input.RequestedRisk != approval.RiskMedium && input.RequestedRisk != approval.RiskHigh {
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
