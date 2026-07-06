package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/manifest"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
	"gopkg.in/yaml.v3"
)

type connectorPackageValidateResponse struct {
	Valid     bool     `json:"valid"`
	Name      string   `json:"name"`
	Resources []string `json:"resources"`
	Error     string   `json:"error,omitempty"`
}

type connectorInstanceSmokeRequest struct {
	ConnectorInstanceID string             `json:"connector_instance_id"`
	Manifest            connector.Manifest `json:"manifest"`
	Resource            string             `json:"resource"`
	Operation           string             `json:"operation"`
	Fields              []string           `json:"fields"`
	CredentialRef       string             `json:"credential_ref"`
}

type connectorInstanceSmokeResponse struct {
	OK                 bool   `json:"ok"`
	Adapter            string `json:"adapter"`
	Resource           string `json:"resource,omitempty"`
	Operation          string `json:"operation,omitempty"`
	CredentialResolved bool   `json:"credential_resolved"`
	SchemaValid        bool   `json:"schema_valid"`
	MaskingValid       bool   `json:"masking_valid"`
	AuditEventID       string `json:"audit_event_id,omitempty"`
	Error              string `json:"error,omitempty"`
}

func HandleConnectorPackageValidate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var parsed connector.Manifest
		if err := decodeManifestRequest(r, &parsed); err != nil {
			writeJSON(w, http.StatusBadRequest, connectorPackageValidateResponse{Valid: false, Error: "invalid connector manifest"})
			return
		}
		if err := manifest.Validate(parsed); err != nil {
			writeJSON(w, http.StatusBadRequest, connectorPackageValidateResponse{Valid: false, Error: err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, connectorPackageValidateResponse{
			Valid:     true,
			Name:      parsed.Name,
			Resources: connectorResourceNames(parsed),
		})
	}
}

func HandleConnectorInstanceSmoke() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req connectorInstanceSmokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, connectorInstanceSmokeResponse{OK: false, Error: "invalid json request"})
			return
		}
		if req.ConnectorInstanceID == "" {
			writeJSON(w, http.StatusBadRequest, connectorInstanceSmokeResponse{OK: false, Error: "connector_instance_id is required"})
			return
		}
		if err := manifest.Validate(req.Manifest); err != nil {
			writeJSON(w, http.StatusBadRequest, connectorInstanceSmokeResponse{OK: false, Error: "invalid connector manifest"})
			return
		}

		runtime := connectorruntime.New(connectorruntime.RuntimeConfig{
			Manifest:       req.Manifest,
			SecretResolver: devSmokeSecretResolver{},
		})
		result, err := runtime.Execute(r.Context(), connectorruntime.Request{
			Resource:      req.Resource,
			Operation:     req.Operation,
			Action:        connectorruntime.ActionRead,
			Fields:        req.Fields,
			CredentialRef: req.CredentialRef,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, connectorInstanceSmokeResponse{OK: false, Error: err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, connectorInstanceSmokeResponse{
			OK:                 true,
			Adapter:            result.Adapter,
			Resource:           result.Resource,
			Operation:          req.Operation,
			CredentialResolved: result.Audit.CredentialResolved,
			SchemaValid:        connectorruntime.ValidateOutputSchema(connectorResource(req.Manifest, req.Resource)),
			MaskingValid:       connectorruntime.ValidateMasking(connectorResource(req.Manifest, req.Resource), req.Fields),
			AuditEventID:       "dev_smoke",
		})
	}
}

func decodeManifestRequest(r *http.Request, target *connector.Manifest) error {
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "yaml") || strings.Contains(contentType, "yml") {
		return yaml.NewDecoder(r.Body).Decode(target)
	}
	return json.NewDecoder(r.Body).Decode(target)
}

func connectorResourceNames(parsed connector.Manifest) []string {
	resources := make([]string, 0, len(parsed.Resources))
	for _, resource := range parsed.Resources {
		resources = append(resources, resource.Name)
	}
	return resources
}

func connectorResource(parsed connector.Manifest, name string) connector.Resource {
	for _, resource := range parsed.Resources {
		if resource.Name == name {
			return resource
		}
	}
	return connector.Resource{}
}

type devSmokeSecretResolver struct{}

func (devSmokeSecretResolver) ResolveSecret(context.Context, string) (string, error) {
	return "resolved-dev-credential", nil
}
