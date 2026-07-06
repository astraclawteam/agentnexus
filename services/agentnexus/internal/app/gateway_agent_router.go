package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func NewGatewayAgentRouter(serviceName, version string) http.Handler {
	mux := http.NewServeMux()
	health := NewHealthStatus(serviceName, version, true)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("POST /v1/agent/deployments/first-run:plan", func(w http.ResponseWriter, r *http.Request) {
		var input FirstDeploymentPlanInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		writeJSON(w, http.StatusOK, BuildFirstDeploymentPlan(input))
	})

	return mux
}
