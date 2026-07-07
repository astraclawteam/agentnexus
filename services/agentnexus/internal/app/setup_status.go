package app

import (
	"net/http"
)

func HandleSetupStatus(service *SetupService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, service.Status(r.Context()))
	}
}

func HandleSetupEnvironment() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, BuildSetupEnvironmentReport())
	}
}

func HandleConsoleSetupChecklist(service *SetupService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := service.Status(r.Context())
		enterpriseID := r.URL.Query().Get("enterprise_id")
		if enterpriseID == "" {
			enterpriseID = status.EnterpriseID
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enterprise_id": enterpriseID,
			"state":         status.State,
			"items":         status.Checklist,
		})
	}
}
