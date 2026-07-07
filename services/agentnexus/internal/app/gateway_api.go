package app

import (
	"encoding/json"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	connectorinstance "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/instance"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/observability"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/receipts"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

type GatewayAPIOption func(*gatewayAPIConfig)

type gatewayAPIConfig struct {
	secretResolver     connectorruntime.SecretResolver
	iamService         *iam.Service
	auditSink          audit.Sink
	connectorInstances *connectorinstance.Service
	receiptRelay       *receipts.Relay
	setupStore         setupEnterpriseStore
	orgImportPreviews  orgImportPreviewStore
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

func WithGatewayAPIReceiptRelay(relay *receipts.Relay) GatewayAPIOption {
	return func(config *gatewayAPIConfig) {
		config.receiptRelay = relay
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
	if config.receiptRelay == nil {
		config.receiptRelay = receipts.NewRelay(nil)
	}
	if config.secretResolver == nil {
		config.secretResolver = secrets.EnvProvider{}
	}
	if config.setupStore == nil {
		config.setupStore = newMemorySetupEnterpriseStore()
	}
	if config.orgImportPreviews == nil {
		config.orgImportPreviews = newMemoryOrgImportPreviewStore()
	}
	setupService := NewSetupService(config.setupStore, config.iamService)

	mux := http.NewServeMux()
	health := NewHealthStatus(serviceName, version, true)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(observability.PrometheusText(observability.Snapshot{
			Service: serviceName,
			Ready:   true,
		})))
	})
	mux.HandleFunc("GET /api/console/overview", func(w http.ResponseWriter, r *http.Request) {
		locale := r.URL.Query().Get("locale")
		if r.URL.Query().Get("demo") == "true" {
			writeJSON(w, http.StatusOK, NewDemoConsoleOverview(locale))
			return
		}
		enterpriseID := r.URL.Query().Get("enterprise_id")
		if enterpriseID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enterprise_id is required for live console overview"})
			return
		}
		setup, ok := config.setupStore.Get(enterpriseID)
		if !ok {
			writeJSON(w, http.StatusOK, NewUnconfiguredConsoleOverview(locale))
			return
		}
		graph, err := config.iamService.GetOrgGraph(r.Context(), enterpriseID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load org graph"})
			return
		}
		writeJSON(w, http.StatusOK, NewLiveConsoleOverview(locale, setup, graph))
	})
	mux.HandleFunc("GET /api/setup/status", HandleSetupStatus(setupService))
	mux.HandleFunc("GET /api/setup/environment", HandleSetupEnvironment())
	mux.HandleFunc("GET /api/setup/session", HandleSetupSession(setupService))
	mux.HandleFunc("POST /api/setup/admin/init", HandleSetupAdminInit(setupService))
	mux.HandleFunc("POST /api/setup/login", HandleSetupLogin(setupService))
	mux.HandleFunc("GET /api/console/setup-checklist", HandleConsoleSetupChecklist(setupService))
	mux.HandleFunc("POST /api/setup/enterprise", HandleSetupEnterprise(config.setupStore, config.iamService))
	mux.HandleFunc("POST /api/setup/secrets/validate", HandleSetupSecretsValidate(config.secretResolver))
	mux.HandleFunc("POST /api/org/import/preview", HandleOrgImportPreview(config.secretResolver, config.auditSink, config.orgImportPreviews))
	mux.HandleFunc("POST /api/org/import/confirm", HandleOrgImportConfirm(config.iamService, config.auditSink, config.orgImportPreviews, config.setupStore))
	mux.HandleFunc("GET /api/org/graph", HandleOrgGraph(config.iamService))
	mux.HandleFunc("POST /api/connectors/packages/validate", HandleConnectorPackageValidate())
	mux.HandleFunc("POST /api/connectors/instances/smoke", HandleConnectorInstanceSmoke())
	mux.HandleFunc("POST /api/connectors/instances/draft", HandleConnectorInstanceDraft(config.connectorInstances))
	mux.HandleFunc("POST /api/connectors/instances/", HandleConnectorInstanceAction(config.connectorInstances))
	mux.HandleFunc("POST /api/receipts/requests", HandleReceiptRequestCreate(config.receiptRelay))
	mux.HandleFunc("POST /api/receipts/requests/", HandleReceiptRequestCallback(config.receiptRelay))
	RegisterRuntimeAPIRoutes(mux, NewDefaultAuthorizedRuntimeAPI())

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
