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

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
	"github.com/nats-io/nats.go"
)

// readinessPollInterval paces the gate that keeps a worker off the stream until
// its seams are wired. It is a wait rather than a fatal error so a deployment
// that completes its wiring while the process is up starts serving without a
// restart.
const readinessPollInterval = 5 * time.Second

func main() {
	cfg := config.Load("connector-worker")
	// Fail closed before anything else: production never runs plaintext.
	mode, err := transportsecurity.ResolveStartupMode(cfg.Environment, cfg.TLS)
	if err != nil {
		log.Fatal(err)
	}
	dispatchConfig, err := config.LoadDispatch()
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

	// GA Task 5 central Connector Worker. The durable execution orchestration
	// (internal/connectors/worker) is complete: it durably pulls Action Outbox
	// dispatch intents, resolves the PRIVATE customer binding server-side,
	// invokes the isolated host and produces the authoritative signed
	// ActionReceipt plus the exact ObservationReceipt set.
	//
	// Its two concrete fail-closed seams — the Postgres private BindingResolver
	// over connector_products/connector_bindings and the evidence-backed
	// ObservationProducer — are not wired yet. Rather than exiting, the process
	// stays up and the readiness gate keeps it OFF the stream: a worker that
	// consumed without those seams would fail every intent it pulled and burn
	// the delivery attempts of durable Actions. No pass-stub, no fake
	// ActionPlane, no fabricated receipt.
	// The worker's own first-party identity. The tenant of each dispatch comes
	// from the server-authored message, never from here and never from Agent
	// input.
	executionWorker, err := worker.New(worker.Config{
		Identity: worker.Identity{PrincipalRef: cfg.ServiceName},
	})
	notReadyReason := ""
	if err != nil {
		// A worker that cannot even be constructed still must not take the
		// process down: the health surface has to stay observable so an
		// operator sees WHY it is not serving.
		notReadyReason = err.Error()
		executionWorker = nil
	}

	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)
	healthServer := startHealthServer(cfg, executionWorker, notReadyReason)

	fmt.Printf("service=%s version=%s environment=%s ready=%t mtls=%t identity=%s dispatch_consumer=%s stream=%s bus=%t\n",
		health.Service, health.Version, cfg.Environment, health.Ready,
		mode == transportsecurity.ModeMutualTLS, identity, worker.DurableName,
		dispatchConfig.StreamName, dispatchConfig.Enabled())

	if executionWorker != nil && dispatchConfig.Enabled() {
		if err := runDispatchLoop(ctx, executionWorker, dispatchConfig); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("connector worker stopped", "error", err)
		}
	} else {
		// Without a bus there is nothing to consume. Stay up so the health
		// surface stays observable and the container does not flap.
		if !dispatchConfig.Enabled() {
			slog.Warn("no dispatch bus configured; connector worker is idle", "consumer", worker.DurableName)
		}
		<-ctx.Done()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = healthServer.Shutdown(shutdownCtx)
}

func runDispatchLoop(ctx context.Context, executionWorker *worker.Worker, dispatchConfig config.DispatchConfig) error {
	conn, err := nats.Connect(dispatchConfig.NATSURL)
	if err != nil {
		return fmt.Errorf("connect dispatch bus: %w", err)
	}
	defer conn.Close()
	js, err := conn.JetStream()
	if err != nil {
		return fmt.Errorf("open jetstream: %w", err)
	}
	// Ensure the dispatch stream exists. This is idempotent and keeps a
	// single-node deployment self-sufficient; a deployment that provisions its
	// own streams simply finds this a no-op. The subject is the one the outbox
	// publishes on, so the stream can never drift from its producer.
	if _, err := js.AddStream(&nats.StreamConfig{
		Name:     dispatchConfig.StreamName,
		Subjects: []string{actions.SubjectActionDispatch},
	}); err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return fmt.Errorf("ensure dispatch stream %q: %w", dispatchConfig.StreamName, err)
	}
	source, err := worker.NewNATSDispatchSource(js, dispatchConfig.StreamName, slog.Default())
	if err != nil {
		return fmt.Errorf("bind dispatch consumer: %w", err)
	}
	return worker.RunWhenReady(ctx, executionWorker, source, readinessPollInterval)
}

// startHealthServer exposes liveness and readiness. readyz reflects the SAME
// CheckReady the dispatch gate uses, so an orchestrator's view of readiness can
// never disagree with whether the worker is actually consuming.
func startHealthServer(cfg config.Config, executionWorker *worker.Worker, constructionError string) *http.Server {
	mux := http.NewServeMux()
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if executionWorker == nil {
			writeHealth(w, http.StatusServiceUnavailable, health.Service, health.Version, false, constructionError)
			return
		}
		if err := executionWorker.CheckReady(r.Context()); err != nil {
			writeHealth(w, http.StatusServiceUnavailable, health.Service, health.Version, false, err.Error())
			return
		}
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("connector worker health server stopped", "error", err)
		}
	}()
	return server
}

func writeHealth(w http.ResponseWriter, status int, service, version string, ready bool, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The reason is an operator diagnostic about this service's own wiring; it
	// never carries tenant or business data.
	if reason == "" {
		fmt.Fprintf(w, `{"service":%q,"version":%q,"ready":%t}`, service, version, ready)
		return
	}
	fmt.Fprintf(w, `{"service":%q,"version":%q,"ready":%t,"reason":%q}`, service, version, ready, reason)
}
