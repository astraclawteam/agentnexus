package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

const maxAuthorizationRequestBytes = 16 << 10

var (
	ErrInvalidTicketActor     = errors.New("invalid ticket actor")
	ErrTicketActorUnavailable = errors.New("ticket actor unavailable")
)

type AuthorizationActor struct {
	EnterpriseID string
	UserID       string
}

type TicketActorAuthenticator interface {
	AuthenticateTicketActor(context.Context, string) (AuthorizationActor, error)
}

type RejectTicketActorAuthenticator struct{}

func (RejectTicketActorAuthenticator) AuthenticateTicketActor(context.Context, string) (AuthorizationActor, error) {
	return AuthorizationActor{}, ErrInvalidTicketActor
}

type authorizationSessionResolver interface {
	GetSession(context.Context, string) (browserauth.BrowserSession, error)
}

type atlasDecisionEvaluator interface {
	Evaluate(context.Context, policy.ScopedRequest) (policy.PermissionDecision, error)
}

type authorizationDependencies struct {
	EnterpriseID string
	Sessions     authorizationSessionResolver
	TicketActors TicketActorAuthenticator
	Evaluator    atlasDecisionEvaluator
}

type authorizationHandler struct {
	enterpriseID string
	sessions     authorizationSessionResolver
	ticketActors TicketActorAuthenticator
	evaluator    atlasDecisionEvaluator
}

type authorizationDecisionRequest struct {
	OrgUnitID    string              `json:"org_unit_id"`
	OrgVersion   int64               `json:"org_version"`
	ResourceType policy.ResourceType `json:"resource_type"`
	ResourceID   string              `json:"resource_id"`
	Action       policy.AtlasAction  `json:"action"`
}

func newAuthorizationHandler(deps authorizationDependencies) (*authorizationHandler, error) {
	if deps.EnterpriseID == "" || deps.Sessions == nil || deps.Evaluator == nil {
		return nil, errors.New("authorization dependencies incomplete")
	}
	return &authorizationHandler{enterpriseID: deps.EnterpriseID, sessions: deps.Sessions, ticketActors: deps.TicketActors, evaluator: deps.Evaluator}, nil
}

func (h *authorizationHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/authorization/decisions", h.decide)
}

func (h *authorizationHandler) decide(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	actor, status := h.authenticateActor(r)
	if status != 0 {
		writeAuthorizationError(w, status)
		return
	}

	var input authorizationDecisionRequest
	if !decodeAuthorizationRequest(w, r, &input) {
		return
	}
	decision, err := h.evaluator.Evaluate(r.Context(), policy.ScopedRequest{
		EnterpriseID: actor.EnterpriseID,
		ActorUserID:  actor.UserID,
		OrgUnitID:    input.OrgUnitID,
		OrgVersion:   input.OrgVersion,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		Action:       input.Action,
	})
	if err != nil {
		writeAuthorizationError(w, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (h *authorizationHandler) authenticateActor(r *http.Request) (AuthorizationActor, int) {
	var sessionCookies []*http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name == browserSessionCookie {
			sessionCookies = append(sessionCookies, cookie)
		}
	}
	authorizationValues := r.Header.Values("Authorization")
	if len(sessionCookies) > 1 {
		return AuthorizationActor{}, http.StatusUnauthorized
	}
	if len(sessionCookies) == 1 && len(authorizationValues) > 0 {
		return AuthorizationActor{}, http.StatusUnauthorized
	}
	if len(sessionCookies) == 1 {
		session, sessionErr := h.sessions.GetSession(r.Context(), sessionCookies[0].Value)
		if errors.Is(sessionErr, browserauth.ErrSessionUnavailable) {
			return AuthorizationActor{}, http.StatusServiceUnavailable
		}
		if sessionErr != nil || session.EnterpriseID != h.enterpriseID || session.UserID == "" {
			return AuthorizationActor{}, http.StatusUnauthorized
		}
		return AuthorizationActor{EnterpriseID: session.EnterpriseID, UserID: session.UserID}, 0
	}

	if len(authorizationValues) != 1 || h.ticketActors == nil {
		return AuthorizationActor{}, http.StatusUnauthorized
	}
	parts := strings.Fields(authorizationValues[0])
	if len(parts) != 2 || parts[0] != "CaseTicket" || parts[1] == "" || len(parts[1]) > 4096 {
		return AuthorizationActor{}, http.StatusUnauthorized
	}
	actor, err := h.ticketActors.AuthenticateTicketActor(r.Context(), parts[1])
	if errors.Is(err, ErrTicketActorUnavailable) {
		return AuthorizationActor{}, http.StatusServiceUnavailable
	}
	if err != nil || actor.EnterpriseID != h.enterpriseID || actor.UserID == "" {
		return AuthorizationActor{}, http.StatusUnauthorized
	}
	return actor, 0
}

func decodeAuthorizationRequest(w http.ResponseWriter, r *http.Request, target *authorizationDecisionRequest) bool {
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
	seen := make(map[string]struct{}, 5)
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
		case "org_unit_id":
			err = json.Unmarshal(raw, &target.OrgUnitID)
		case "org_version":
			err = json.Unmarshal(raw, &target.OrgVersion)
		case "resource_type":
			err = json.Unmarshal(raw, &target.ResourceType)
		case "resource_id":
			err = json.Unmarshal(raw, &target.ResourceID)
		case "action":
			err = json.Unmarshal(raw, &target.Action)
		default:
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
	if len(seen) != 5 || target.OrgVersion < 1 || !canonicalAuthorizationValue(target.OrgUnitID) || !canonicalAuthorizationValue(string(target.ResourceType)) || !canonicalAuthorizationValue(target.ResourceID) || !canonicalAuthorizationValue(string(target.Action)) {
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
