package app

import (
	"encoding/json"
	"net/http"
	"strings"

	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

type setupSecretsValidateRequest struct {
	Refs map[string]string `json:"refs"`
}

type setupSecretsValidateResponse struct {
	Valid   bool                                 `json:"valid"`
	Results map[string]setupSecretValidateResult `json:"results"`
}

type setupSecretValidateResult struct {
	Resolved bool   `json:"resolved"`
	Code     string `json:"code,omitempty"`
	Error    string `json:"error,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

func HandleSetupSecretsValidate(resolver connectorruntime.SecretResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req setupSecretsValidateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		if resolver == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "secret resolver is not configured"})
			return
		}

		resp := setupSecretsValidateResponse{Valid: true, Results: make(map[string]setupSecretValidateResult, len(req.Refs))}
		for name, ref := range req.Refs {
			if !strings.HasPrefix(ref, secrets.EnvRefPrefix) {
				resp.Valid = false
				resp.Results[name] = setupSecretValidateResult{
					Resolved: false,
					Code:     "invalid_format",
					Error:    "secret reference must use " + secrets.EnvRefPrefix,
					Fix:      "Configure the real secret in the deployment environment and submit a reference like secret://env/AGENTNEXUS_OA_TOKEN.",
				}
				continue
			}
			if _, err := resolver.ResolveSecret(r.Context(), ref); err != nil {
				resp.Valid = false
				resp.Results[name] = setupSecretValidateResult{
					Resolved: false,
					Code:     "missing",
					Error:    err.Error(),
					Fix:      "Set the referenced environment variable in the private deployment and retry validation.",
				}
				continue
			}
			resp.Results[name] = setupSecretValidateResult{Resolved: true}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
