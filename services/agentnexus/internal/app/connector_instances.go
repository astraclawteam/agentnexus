package app

import (
	"encoding/json"
	"net/http"
	"strings"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/instance"
)

const connectorInstanceActionPrefix = "/api/connectors/instances/"

type connectorInstanceDraftRequest struct {
	EnterpriseID   string             `json:"enterprise_id"`
	Manifest       connector.Manifest `json:"manifest"`
	BaseURL        string             `json:"base_url"`
	AccountSet     []string           `json:"account_set"`
	FieldMapping   map[string]string  `json:"field_mapping"`
	DataScope      []string           `json:"data_scope"`
	CredentialRefs map[string]string  `json:"credential_refs"`
}

type connectorInstanceDraftResponse struct {
	ConnectorPackageID  string            `json:"connector_package_id"`
	ConnectorInstanceID string            `json:"connector_instance_id"`
	PackageName         string            `json:"package_name"`
	Status              string            `json:"status"`
	CredentialRefs      map[string]string `json:"credential_refs"`
}

type connectorInstanceLifecycleSmokeRequest struct {
	EnterpriseID string   `json:"enterprise_id"`
	Resource     string   `json:"resource"`
	Operation    string   `json:"operation"`
	Fields       []string `json:"fields"`
}

type connectorInstanceLifecycleSmokeResponse struct {
	OK                 bool   `json:"ok"`
	Adapter            string `json:"adapter"`
	CredentialResolved bool   `json:"credential_resolved"`
	SchemaValid        bool   `json:"schema_valid"`
	MaskingValid       bool   `json:"masking_valid"`
	AuditEventID       string `json:"audit_event_id"`
	Error              string `json:"error,omitempty"`
}

type connectorInstanceConfirmRequest struct {
	EnterpriseID        string `json:"enterprise_id"`
	HumanConfirmationID string `json:"human_confirmation_id"`
}

type connectorInstanceConfirmResponse struct {
	ConnectorInstanceID string `json:"connector_instance_id"`
	Status              string `json:"status"`
}

func HandleConnectorInstanceDraft(service *instance.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req connectorInstanceDraftRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		result, err := service.DraftInstance(r.Context(), instance.DraftInstanceInput{
			EnterpriseID:   req.EnterpriseID,
			Manifest:       req.Manifest,
			BaseURL:        req.BaseURL,
			AccountSet:     req.AccountSet,
			FieldMapping:   req.FieldMapping,
			DataScope:      req.DataScope,
			CredentialRefs: req.CredentialRefs,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, connectorInstanceDraftResponse{
			ConnectorPackageID:  result.Package.ID,
			ConnectorInstanceID: result.Instance.ID,
			PackageName:         result.Package.Name,
			Status:              result.Instance.Status,
			CredentialRefs:      result.Instance.CredentialRefs,
		})
	}
}

func HandleConnectorInstanceLifecycleSmoke(service *instance.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req connectorInstanceLifecycleSmokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, connectorInstanceLifecycleSmokeResponse{OK: false, Error: "invalid json request"})
			return
		}
		result, err := service.SmokeInstance(r.Context(), instance.SmokeInstanceInput{
			EnterpriseID: req.EnterpriseID,
			InstanceID:   r.PathValue("id"),
			Resource:     req.Resource,
			Operation:    req.Operation,
			Fields:       req.Fields,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, connectorInstanceLifecycleSmokeResponse{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, connectorInstanceLifecycleSmokeResponse{
			OK:                 result.OK,
			Adapter:            result.Adapter,
			CredentialResolved: result.CredentialResolved,
			SchemaValid:        result.SchemaValid,
			MaskingValid:       result.MaskingValid,
			AuditEventID:       result.AuditEventID,
		})
	}
}

func HandleConnectorInstanceConfirm(service *instance.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req connectorInstanceConfirmRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		result, err := service.ConfirmInstance(r.Context(), instance.ConfirmInstanceInput{
			EnterpriseID:        req.EnterpriseID,
			InstanceID:          r.PathValue("id"),
			HumanConfirmationID: req.HumanConfirmationID,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, connectorInstanceConfirmResponse{
			ConnectorInstanceID: result.ID,
			Status:              result.Status,
		})
	}
}

func HandleConnectorInstanceAction(service *instance.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, connectorInstanceActionPrefix)
		instanceID, action, ok := strings.Cut(rest, ":")
		if !ok || instanceID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connector instance action not found"})
			return
		}
		r.SetPathValue("id", instanceID)
		switch action {
		case "smoke":
			HandleConnectorInstanceLifecycleSmoke(service)(w, r)
		case "confirm":
			HandleConnectorInstanceConfirm(service)(w, r)
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connector instance action not found"})
		}
	}
}
