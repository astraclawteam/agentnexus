package app

import (
	"encoding/json"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
)

type orgImportPreviewRequest struct {
	Provider        string `json:"provider"`
	BaseURL         string `json:"base_url"`
	DepartmentsPath string `json:"departments_path"`
	EmployeesPath   string `json:"employees_path"`
	TokenRef        string `json:"token_ref"`
}

type orgImportPreviewResponse struct {
	Provider                  string               `json:"provider"`
	RequiresConfirmation      bool                 `json:"requires_confirmation"`
	AutoImportableEmployeeIDs []string             `json:"auto_importable_employee_ids"`
	Conflicts                 []orgsource.Conflict `json:"conflicts"`
}

func HandleOrgImportPreview(secretResolver connectorruntime.SecretResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req orgImportPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		if req.Provider != "oa_http" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported org import provider"})
			return
		}

		token := ""
		if req.TokenRef != "" {
			if secretResolver == nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret resolver is required for token_ref"})
				return
			}
			resolved, err := secretResolver.ResolveSecret(r.Context(), req.TokenRef)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to resolve token_ref"})
				return
			}
			token = resolved
		}

		preview, err := BuildOrgImportPreview(r.Context(), orgsource.NewOAHTTPProvider(orgsource.OAHTTPConfig{
			BaseURL:         req.BaseURL,
			DepartmentsPath: req.DepartmentsPath,
			EmployeesPath:   req.EmployeesPath,
			Token:           token,
		}))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to build org import preview"})
			return
		}

		writeJSON(w, http.StatusOK, orgImportPreviewResponse{
			Provider:                  req.Provider,
			RequiresConfirmation:      preview.RequiresConfirmation,
			AutoImportableEmployeeIDs: preview.AutoImportableEmployeeIDs,
			Conflicts:                 preview.Conflicts,
		})
	}
}
