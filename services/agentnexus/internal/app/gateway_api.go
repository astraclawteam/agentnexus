package app

import (
	"encoding/json"
	"net/http"

	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
)

type GatewayAPIOption func(*gatewayAPIConfig)

type gatewayAPIConfig struct {
	secretResolver connectorruntime.SecretResolver
}

func WithGatewayAPISecretResolver(resolver connectorruntime.SecretResolver) GatewayAPIOption {
	return func(config *gatewayAPIConfig) {
		config.secretResolver = resolver
	}
}

func NewGatewayAPIRouter(serviceName, version string, options ...GatewayAPIOption) http.Handler {
	config := gatewayAPIConfig{}
	for _, option := range options {
		option(&config)
	}

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
	mux.HandleFunc("POST /api/org/import/preview", HandleOrgImportPreview(config.secretResolver))
	mux.HandleFunc("POST /api/connectors/packages/validate", HandleConnectorPackageValidate())
	mux.HandleFunc("POST /api/connectors/instances/smoke", HandleConnectorInstanceSmoke())
	RegisterRuntimeAPIRoutes(mux, NewRuntimeAPISkeleton())

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
