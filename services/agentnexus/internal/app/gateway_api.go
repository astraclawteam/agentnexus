package app

import (
	"encoding/json"
	"net/http"
)

func NewGatewayAPIRouter(serviceName, version string) http.Handler {
	return newGatewayAPIMux(serviceName, version)
}

func NewGatewayAPIRouterWithDependencies(serviceName, version string, deps BrowserAuthDependencies) (http.Handler, error) {
	mux := newGatewayAPIMux(serviceName, version)
	handler, err := newBrowserAuthHandler(deps)
	if err != nil {
		return nil, err
	}
	handler.register(mux)
	return mux, nil
}

func newGatewayAPIMux(serviceName, version string) *http.ServeMux {
	mux := http.NewServeMux()
	health := NewHealthStatus(serviceName, version, true)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /api/console/overview", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, NewConsoleOverview(r.URL.Query().Get("locale")))
	})

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
