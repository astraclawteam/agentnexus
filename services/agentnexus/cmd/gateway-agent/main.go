package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/gatewayagent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/llmroutermodel"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
	adksession "google.golang.org/adk/v2/session"
)

// probeClientTimeout bounds a plaintext readiness dial. The diagnostics service
// applies its own per-probe deadline; this is the transport-level backstop.
const probeClientTimeout = 5 * time.Second

func main() {
	cfg := config.Load("gateway-agent")
	// Fail closed before anything else: production never runs plaintext.
	mode, err := transportsecurity.ResolveStartupMode(cfg.Environment, cfg.TLS)
	if err != nil {
		log.Fatal(err)
	}

	identity := ""
	var manager *transportsecurity.Manager
	if mode == transportsecurity.ModeMutualTLS {
		// Load and validate this service's unique mTLS identity through the
		// single public TLS profile so the material is ready for both the
		// serving and the dialing side of every link.
		manager, err = transportsecurity.NewManager(transportsecurity.SettingsFromConfig(cfg))
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

	// The bounded operations assistant. Composition can fail for reasons that
	// are deployment configuration rather than programmer error - an unset
	// router URL, an unreachable-by-design target list - so a failure here
	// leaves the process running and unready with a stated reason, rather than
	// exiting. An operator needs /readyz to tell them WHY, and a container that
	// exits on boot tells them nothing.
	assistant, notReadyReason := composeAssistant(cfg, mode, manager)

	health := serviceHealth(cfg, assistant)
	healthServer := startHealthServer(cfg, assistant, notReadyReason)

	fmt.Println(startupLine(cfg, health, mode, identity, assistant))
	if assistant == nil {
		slog.Warn("gateway agent is not serving the assistant", "reason", notReadyReason)
	} else {
		slog.Info("gateway agent composed the assistant but exposes no way to reach it",
			"reason", "the frozen gateway-runtime contract declares no agent conversation endpoint",
			"contract", "api/openapi/gateway-runtime.yaml")
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = healthServer.Shutdown(shutdownCtx)
}

// assistantIsServing is the single readiness predicate for this binary. The
// startup line and /readyz both derive from it, because the one thing that must
// never happen again is the two disagreeing.
func assistantIsServing(assistant *gatewayagent.Assistant) bool { return assistant != nil }

// serviceHealth is the one place readiness is decided.
//
// It used to be a literal true in TWO places - here and in newHealthMux - so
// the single line an operator reads at boot said ready=true while /readyz on
// the same process returned 503, and the line contradicted its own
// assistant_ready=false field three columns further along.
func serviceHealth(cfg config.Config, assistant *gatewayagent.Assistant) app.HealthStatus {
	return app.NewHealthStatus(cfg.ServiceName, cfg.Version, assistantIsServing(assistant))
}

// startupLine renders the one line an operator reads at boot.
//
// It is a function rather than an inline Printf so the value it publishes can
// be compared against the value /readyz serves for the same inputs. Reading
// main.go to check they agree is exactly how they came to disagree.
//
// assistant_transport is reported separately from assistant_ready, and is
// currently always none. The assistant is composed and its dependencies are
// wired, but nothing calls Assistant.Ask: the frozen contract at
// api/openapi/gateway-runtime.yaml declares no agent conversation endpoint, and
// it is digest-pinned cross-repo, so a route cannot be added here. Printing
// readiness alone would read as "operators can talk to it", which is the
// misreading this line exists to prevent.
func startupLine(cfg config.Config, health app.HealthStatus, mode transportsecurity.Mode, identity string, assistant *gatewayagent.Assistant) string {
	return fmt.Sprintf("service=%s version=%s environment=%s ready=%t mtls=%t identity=%s app=%s agent=%s assistant_ready=%t assistant_transport=none",
		health.Service, health.Version, cfg.Environment, health.Ready,
		mode == transportsecurity.ModeMutualTLS, identity,
		gatewayagent.AppName, gatewayagent.AgentName, assistantIsServing(assistant))
}

// composeAssistant builds the assistant, or explains why it could not.
//
// The returned reason is served from /readyz and logged, so it is written for
// an operator and it names environment variables rather than values: one of
// those values is the router API key, and a readiness endpoint is not a place
// a secret may ever appear.
func composeAssistant(cfg config.Config, mode transportsecurity.Mode, manager *transportsecurity.Manager) (*gatewayagent.Assistant, string) {
	if !cfg.LLMRouter.Complete() {
		// Deliberately not a partial start. Model access is llmrouter-only
		// with no direct-provider fallback, so an incomplete router config
		// means there is no model at all.
		return nil, fmt.Sprintf("assistant not composed: llmrouter is not fully configured, set %s", strings.Join(cfg.LLMRouter.Missing(), ", "))
	}

	targets, err := config.ParseProbeTargets(cfg.HealthProbeTargets)
	if err != nil {
		return nil, "assistant not composed: AGENTNEXUS_HEALTH_PROBE_TARGETS is malformed, expected a comma-separated name=url list"
	}
	if len(targets) == 0 {
		return nil, "assistant not composed: AGENTNEXUS_HEALTH_PROBE_TARGETS is empty, so a health report would be blank and read as healthy"
	}

	healthTargets, err := probeTargets(targets, mode, manager, cfg.EnterpriseID)
	if err != nil {
		return nil, fmt.Sprintf("assistant not composed: %v", err)
	}
	diagnostics, err := gatewayagent.NewServiceDiagnostics(healthTargets)
	if err != nil {
		return nil, fmt.Sprintf("assistant not composed: %v", err)
	}

	assistant, err := newAssistant(cfg.LLMRouter, diagnostics)
	if err != nil {
		return nil, fmt.Sprintf("assistant not composed: %v", err)
	}
	return assistant, ""
}

// newAssistant is the composition seam. It is exercised directly by the
// command's unit test so the refusal paths stay covered without standing up a
// router or a peer.
func newAssistant(router config.LLMRouterSettings, diagnostics gatewayagent.DiagnosticsService) (*gatewayagent.Assistant, error) {
	// The llmrouter adapter is the single outbound model path. Nothing here
	// constructs a provider client, and TestOnlyLLMRouterOutbound fails the
	// build if anything tries.
	llm, err := llmroutermodel.New(llmroutermodel.Config{
		BaseURL:      router.BaseURL,
		APIKey:       router.APIKey,
		DefaultModel: router.Model,
	})
	if err != nil {
		return nil, fmt.Errorf("build llmrouter model: %w", err)
	}
	// Sessions are in-memory: a turn is short-lived and an assistant
	// conversation is not durable state this deployment promises to keep. The
	// tenant scoping that matters is applied inside NewAssistant regardless of
	// which store backs it.
	return gatewayagent.NewAssistant(llm, gatewayagent.NewPolicy(), diagnostics, adksession.InMemoryService())
}

// probeTargets pairs each configured readiness endpoint with the client that
// may dial it.
//
// In mTLS mode each target gets its own client, because the dial pins that
// peer's server name. There is deliberately no shared plaintext fallback for
// that mode: a probe that quietly downgraded to plaintext would be an
// unauthenticated call to a production peer, and it would report the answer as
// though it were trustworthy.
func probeTargets(targets []config.ProbeTarget, mode transportsecurity.Mode, manager *transportsecurity.Manager, enterpriseID string) ([]gatewayagent.HealthTarget, error) {
	built := make([]gatewayagent.HealthTarget, 0, len(targets))
	for _, target := range targets {
		parsed, err := url.Parse(target.URL)
		if err != nil || parsed.Host == "" {
			return nil, fmt.Errorf("health target %q does not have a usable URL", target.Name)
		}
		var client gatewayagent.Doer
		if mode == transportsecurity.ModeMutualTLS {
			if manager == nil {
				return nil, errors.New("mTLS mode without loaded trust material")
			}
			// The peer set is the services this deployment may dial for
			// readiness. It is named here rather than derived from the target
			// list so a target URL cannot widen who this service will trust.
			peers := sdk.PeerAuthorization{Enterprise: enterpriseID, Services: []string{"gateway-api", "connector-worker"}}
			mtlsClient, err := manager.NewHTTPClient(peers, parsed.Hostname())
			if err != nil {
				return nil, fmt.Errorf("build mTLS client for health target %q: %w", target.Name, err)
			}
			client = mtlsClient
		} else {
			client = &http.Client{Timeout: probeClientTimeout}
		}
		built = append(built, gatewayagent.HealthTarget{Name: target.Name, ReadinessURL: target.URL, Client: client})
	}
	return built, nil
}

// newHealthMux builds the health surface.
//
// It is separate from startHealthServer so readiness can be exercised without
// binding a port: /readyz answering honestly is a behaviour worth a test, not
// an implementation detail of listening.
//
// This mux carries health only. There is no agent-chat route here, and adding
// one is not a local decision: the frozen contract at
// api/openapi/gateway-runtime.yaml declares no agent conversation endpoint, and
// it is digest-pinned cross-repo.
func newHealthMux(cfg config.Config, assistant *gatewayagent.Assistant, notReadyReason string) *http.ServeMux {
	mux := http.NewServeMux()
	health := serviceHealth(cfg, assistant)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		// Liveness stays 200 on purpose: the process must remain observable so
		// an operator can read /readyz and learn WHY it is not serving.
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		// Branch on health.Ready rather than re-deriving `assistant == nil`, so
		// the value this handler answers with and the value the startup line
		// prints are the SAME value. Independently derived, they drifted.
		if !health.Ready {
			writeHealth(w, http.StatusServiceUnavailable, health.Service, health.Version, false, notReadyReason)
			return
		}
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	return mux
}

func startHealthServer(cfg config.Config, assistant *gatewayagent.Assistant, notReadyReason string) *http.Server {
	mux := newHealthMux(cfg, assistant, notReadyReason)
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
