package app

import "net/http"

func HandleSetupSession(service *SetupService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := service.Status(r.Context())
		writeJSON(w, http.StatusOK, status.Session)
	}
}

func HandleSetupAdminInit(service *SetupService) http.HandlerFunc {
	return handleDeferredLocalAdminAuth(service, "local admin initialization is not implemented in open-core private-dev yet")
}

func HandleSetupLogin(service *SetupService) http.HandlerFunc {
	return handleDeferredLocalAdminAuth(service, "local admin login is not implemented in open-core private-dev yet")
}

func handleDeferredLocalAdminAuth(service *SetupService, message string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := service.Status(r.Context())
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"error":         message,
			"mode":          status.Session.Mode,
			"actor_user_id": status.Session.ActorUserID,
			"secure":        status.Session.Secure,
			"message":       status.Session.Message,
		})
	}
}

