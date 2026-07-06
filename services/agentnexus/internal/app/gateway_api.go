package app

import (
	"encoding/json"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	connectorinstance "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/instance"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
)

type GatewayAPIOption func(*gatewayAPIConfig)

type gatewayAPIConfig struct {
	secretResolver     connectorruntime.SecretResolver
	iamService         *iam.Service
	auditSink          audit.Sink
	connectorInstances *connectorinstance.Service
}

func WithGatewayAPISecretResolver(resolver connectorruntime.SecretResolver) GatewayAPIOption {
	return func(config *gatewayAPIConfig) {
		config.secretResolver = resolver
	}
}

func WithGatewayAPIIAMService(service *iam.Service) GatewayAPIOption {
	return func(config *gatewayAPIConfig) {
		config.iamService = service
	}
}

func WithGatewayAPIAuditSink(sink audit.Sink) GatewayAPIOption {
	return func(config *gatewayAPIConfig) {
		config.auditSink = sink
	}
}

func WithGatewayAPIConnectorInstanceService(service *connectorinstance.Service) GatewayAPIOption {
	return func(config *gatewayAPIConfig) {
		config.connectorInstances = service
	}
}

func NewGatewayAPIRouter(serviceName, version string, options ...GatewayAPIOption) http.Handler {
	config := gatewayAPIConfig{}
	for _, option := range options {
		option(&config)
	}
	if config.iamService == nil {
		config.iamService = iam.NewService(iam.NewMemoryStore())
	}
	if config.connectorInstances == nil {
		config.connectorInstances = connectorinstance.NewService(connectorinstance.NewMemoryStore(), connectorinstance.ServiceConfig{
			SecretResolver: connectorinstance.StaticSecretResolver{},
			AuditSink:      connectorinstance.NewMemoryAuditSink(),
		})
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
	mux.HandleFunc("POST /api/org/import/preview", HandleOrgImportPreview(config.secretResolver, config.auditSink))
	mux.HandleFunc("POST /api/org/import/confirm", HandleOrgImportConfirm(config.iamService, config.auditSink))
	mux.HandleFunc("GET /api/org/graph", HandleOrgGraph(config.iamService))
	mux.HandleFunc("POST /api/connectors/packages/validate", HandleConnectorPackageValidate())
	mux.HandleFunc("POST /api/connectors/instances/smoke", HandleConnectorInstanceSmoke())
	mux.HandleFunc("POST /api/connectors/instances/draft", HandleConnectorInstanceDraft(config.connectorInstances))
	mux.HandleFunc("POST /api/connectors/instances/", HandleConnectorInstanceAction(config.connectorInstances))
	RegisterRuntimeAPIRoutes(mux, NewDefaultAuthorizedRuntimeAPI())

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
