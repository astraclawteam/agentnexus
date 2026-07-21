package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/gatewayagent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
	adksession "google.golang.org/adk/v2/session"
)

func main() {
	cfg := config.Load("gateway-agent")
	// Fail closed before anything else: production never runs plaintext.
	mode, err := transportsecurity.ResolveStartupMode(cfg.Environment, cfg.TLS)
	if err != nil {
		log.Fatal(err)
	}

	identity := ""
	if mode == transportsecurity.ModeMutualTLS {
		// Load and validate this service's unique mTLS identity through the
		// single public TLS profile so the material is ready for both the
		// serving and the dialing side of every link.
		manager, err := transportsecurity.NewManager(transportsecurity.SettingsFromConfig(cfg))
		if err != nil {
			log.Fatal(err)
		}
		peers, err := transportsecurity.AuthorizedClients(cfg.ServiceName, cfg.EnterpriseID)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := manager.ServerTLSConfig(peers); err != nil {
			log.Fatal(err)
		}
		identity = manager.IdentityURI()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The bounded operations assistant. Two dependencies are deliberately NOT
	// defaulted here:
	//
	//   - the model, which must be the llmrouter adapter. There is no fallback
	//     provider: model access is llmrouter-only, so without it the assistant
	//     simply does not exist rather than reaching for something else.
	//   - the deterministic diagnostics service, which grounds every fact the
	//     assistant may state. Without it the assistant could only guess, so it
	//     is refused rather than degraded.
	//
	// Both land with the surrounding work (the llmrouter wiring and the
	// deterministic health/error services). Until then the process runs, serves
	// health, and reports precisely why it is not ready.
	notReadyReason := "assistant not composed: llmrouter model and deterministic diagnostics service are not wired yet"
	var assistant *gatewayagent.Assistant

	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)
	healthServer := startHealthServer(cfg, assistant, notReadyReason)

	fmt.Printf("service=%s version=%s environment=%s ready=%t mtls=%t identity=%s app=%s agent=%s assistant_ready=%t\n",
		health.Service, health.Version, cfg.Environment, health.Ready,
		mode == transportsecurity.ModeMutualTLS, identity,
		gatewayagent.AppName, gatewayagent.AgentName, assistant != nil)
	if assistant == nil {
		slog.Warn("gateway agent is not serving the assistant", "reason", notReadyReason)
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = healthServer.Shutdown(shutdownCtx)
}

// newAssistant is the composition seam. It is exercised by the command's unit
// test so the refusal paths stay covered even while the concrete model and
// diagnostics services are still being wired.
func newAssistant(diagnostics gatewayagent.DiagnosticsService) (*gatewayagent.Assistant, error) {
	// A nil model is refused inside NewAssistant: there is no default provider
	// to fall back to, and inventing one would breach the llmrouter-only
	// boundary the GA manifest pins.
	return gatewayagent.NewAssistant(nil, gatewayagent.NewPolicy(), diagnostics, adksession.InMemoryService())
}

func startHealthServer(cfg config.Config, assistant *gatewayagent.Assistant, notReadyReason string) *http.Server {
	mux := http.NewServeMux()
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if assistant == nil {
			writeHealth(w, http.StatusServiceUnavailable, health.Service, health.Version, false, notReadyReason)
			return
		}
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("gateway agent health server stopped", "error", err)
		}
	}()
	return server
}

func writeHealth(w http.ResponseWriter, status int, service, version string, ready bool, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The reason describes this service's own wiring; it never carries tenant
	// or business data.
	if reason == "" {
		fmt.Fprintf(w, `{"service":%q,"version":%q,"ready":%t}`, service, version, ready)
		return
	}
	fmt.Fprintf(w, `{"service":%q,"version":%q,"ready":%t,"reason":%q}`, service, version, ready, reason)
}
