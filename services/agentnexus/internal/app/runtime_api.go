package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const missingEnvelopeError = "enterprise_id, actor_user_id, and request_id are required"

type RequestEnvelope struct {
	EnterpriseID string `json:"enterprise_id"`
	ActorUserID  string `json:"actor_user_id"`
	RequestID    string `json:"request_id"`
	TraceID      string `json:"trace_id,omitempty"`
}

func (e RequestEnvelope) valid() bool {
	return e.EnterpriseID != "" && e.ActorUserID != "" && e.RequestID != ""
}

type RuntimeResourceRef struct {
	Type                string `json:"type"`
	ID                  string `json:"id"`
	ConnectorInstanceID string `json:"connector_instance_id,omitempty"`
	ResourceName        string `json:"resource_name,omitempty"`
}

type RuntimeLocateRequest struct {
	RequestEnvelope
	Intent        string   `json:"intent"`
	ResourceTypes []string `json:"resource_types,omitempty"`
}

type RuntimeReadRequest struct {
	RequestEnvelope
	CaseTicketID string             `json:"case_ticket_id"`
	Resource     RuntimeResourceRef `json:"resource"`
	Fields       []string           `json:"fields,omitempty"`
}

type RuntimeActRequest struct {
	RequestEnvelope
	CaseTicketID string             `json:"case_ticket_id"`
	Resource     RuntimeResourceRef `json:"resource"`
	Action       string             `json:"action"`
	Input        map[string]any     `json:"input,omitempty"`
}

type RuntimeLocateResponse struct {
	CaseTicketID string                   `json:"case_ticket_id"`
	Resources    []RuntimeLocatedResource `json:"resources"`
}

type RuntimeLocatedResource struct {
	Resource        RuntimeResourceRef `json:"resource"`
	EvidencePointer string             `json:"evidence_pointer,omitempty"`
	Summary         string             `json:"summary,omitempty"`
}

type RuntimeReadResponse struct {
	Decision                 string         `json:"decision"`
	StepGrantID              string         `json:"step_grant_id,omitempty"`
	Data                     map[string]any `json:"data,omitempty"`
	WaitingExternalReceiptID string         `json:"waiting_external_receipt_id,omitempty"`
}

type RuntimeActResponse struct {
	Decision                 string         `json:"decision"`
	StepGrantID              string         `json:"step_grant_id,omitempty"`
	Result                   map[string]any `json:"result,omitempty"`
	WaitingExternalReceiptID string         `json:"waiting_external_receipt_id,omitempty"`
}

type RuntimeTicketResponse struct {
	CaseTicketID string `json:"case_ticket_id"`
	Status       string `json:"status"`
	TraceID      string `json:"trace_id,omitempty"`
	OrgVersionID string `json:"org_version_id,omitempty"`
}

type RuntimeAPI interface {
	Locate(*http.Request, RuntimeLocateRequest) (RuntimeLocateResponse, error)
	Read(*http.Request, RuntimeReadRequest) (RuntimeReadResponse, error)
	Act(*http.Request, RuntimeActRequest) (RuntimeActResponse, error)
	GetTicket(*http.Request, string) (RuntimeTicketResponse, error)
}

func RegisterRuntimeAPIRoutes(mux *http.ServeMux, runtime RuntimeAPI) {
	mux.HandleFunc("POST /v1/runtime/locate", func(w http.ResponseWriter, r *http.Request) {
		var req RuntimeLocateRequest
		if !decodeRuntimeRequest(w, r, &req) {
			return
		}
		if !req.RequestEnvelope.valid() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": missingEnvelopeError})
			return
		}
		resp, err := runtime.Locate(r, req)
		writeRuntimeResponse(w, resp, err)
	})
	mux.HandleFunc("POST /v1/runtime/read", func(w http.ResponseWriter, r *http.Request) {
		var req RuntimeReadRequest
		if !decodeRuntimeRequest(w, r, &req) {
			return
		}
		if !req.RequestEnvelope.valid() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": missingEnvelopeError})
			return
		}
		resp, err := runtime.Read(r, req)
		writeRuntimeResponse(w, resp, err)
	})
	mux.HandleFunc("POST /v1/runtime/act", func(w http.ResponseWriter, r *http.Request) {
		var req RuntimeActRequest
		if !decodeRuntimeRequest(w, r, &req) {
			return
		}
		if !req.RequestEnvelope.valid() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": missingEnvelopeError})
			return
		}
		resp, err := runtime.Act(r, req)
		writeRuntimeResponse(w, resp, err)
	})
	mux.HandleFunc("GET /v1/runtime/tickets/{id}", func(w http.ResponseWriter, r *http.Request) {
		resp, err := runtime.GetTicket(r, r.PathValue("id"))
		writeRuntimeResponse(w, resp, err)
	})
}

func decodeRuntimeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
		return false
	}
	return true
}

func writeRuntimeResponse(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

type RuntimeAPISkeleton struct{}

func NewRuntimeAPISkeleton() RuntimeAPISkeleton {
	return RuntimeAPISkeleton{}
}

func (RuntimeAPISkeleton) Locate(_ *http.Request, req RuntimeLocateRequest) (RuntimeLocateResponse, error) {
	caseTicketID := runtimeID("case_ticket", req.EnterpriseID, req.RequestID)
	resourceType := "connector_resource"
	if len(req.ResourceTypes) > 0 && strings.TrimSpace(req.ResourceTypes[0]) != "" {
		resourceType = req.ResourceTypes[0]
	}
	return RuntimeLocateResponse{
		CaseTicketID: caseTicketID,
		Resources: []RuntimeLocatedResource{{
			Resource: RuntimeResourceRef{
				Type:                resourceType,
				ID:                  "resource_dev_preview",
				ConnectorInstanceID: "connector_dev_preview",
				ResourceName:        "dev_preview",
			},
			Summary: "runtime API skeleton response; M4 binds policy, ticket, connector, and audit",
		}},
	}, nil
}

func (RuntimeAPISkeleton) Read(_ *http.Request, req RuntimeReadRequest) (RuntimeReadResponse, error) {
	if req.CaseTicketID == "" {
		return RuntimeReadResponse{}, fmt.Errorf("case_ticket_id is required")
	}
	return RuntimeReadResponse{
		Decision:    "allow",
		StepGrantID: runtimeID("step_grant", req.EnterpriseID, req.RequestID),
		Data: map[string]any{
			"resource_id": req.Resource.ID,
			"fields":      req.Fields,
		},
	}, nil
}

func (RuntimeAPISkeleton) Act(_ *http.Request, req RuntimeActRequest) (RuntimeActResponse, error) {
	if req.CaseTicketID == "" {
		return RuntimeActResponse{}, fmt.Errorf("case_ticket_id is required")
	}
	return RuntimeActResponse{
		Decision:    "allow",
		StepGrantID: runtimeID("step_grant", req.EnterpriseID, req.RequestID),
		Result: map[string]any{
			"resource_id": req.Resource.ID,
			"action":      req.Action,
		},
	}, nil
}

func (RuntimeAPISkeleton) GetTicket(_ *http.Request, id string) (RuntimeTicketResponse, error) {
	if id == "" {
		return RuntimeTicketResponse{}, fmt.Errorf("ticket id is required")
	}
	return RuntimeTicketResponse{
		CaseTicketID: id,
		Status:       "active",
	}, nil
}

func runtimeID(prefix, enterpriseID, requestID string) string {
	cleanEnterprise := strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(enterpriseID)
	cleanRequest := strings.NewReplacer("/", "_", ":", "_", " ", "_").Replace(requestID)
	return prefix + "_" + cleanEnterprise + "_" + cleanRequest
}

func hashRuntimeValue(value any) string {
	bytes, _ := json.Marshal(value)
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}
