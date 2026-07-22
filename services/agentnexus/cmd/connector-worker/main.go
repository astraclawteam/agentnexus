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
	"strings"
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
	workerConfig := worker.Config{
		Identity: worker.Identity{PrincipalRef: cfg.ServiceName},
	}
	// Name the gap before trying to construct through it. worker.New stops at
	// the FIRST problem it meets (a nil action plane), so on its own it tells an
	// operator to go wire one thing, and the next restart tells them the next
	// thing. MissingRequired reports the whole set at once, including the three
	// identity refs that have no configuration surface at all -- which worker.New
	// can only describe as a sentence and CheckReady never reaches.
	//
	// Nothing here can satisfy that set today; both halves are task B3. The
	// guard's job for this binary is therefore to make the failure EXPLICIT, not
	// to pretend it can be met: no pass-stub, no fake ActionPlane, no invented
	// agent_client_ref. The process still stays up, because a container that
	// flaps hides the reason, and /readyz still answers 503 with it.
	executionWorker, notReadyReason := composeWorker(workerConfig)

	// Readiness in the startup line must be the SAME predicate /readyz answers.
	// It used to be a literal true, so the one line an operator reads at boot
	// said ready=true while /readyz on the same process returned 503 - the
	// startup log actively masked the fact that the worker consumes nothing.
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, workerCanConsume(executionWorker))
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
		// Stay up so the health surface stays observable and the container does
		// not flap. Staying up is deliberate; staying SILENT was not. Both
		// reasons must say so: in the deployed configuration NATS *is* set and
		// the worker is nil, which is exactly the branch that previously logged
		// nothing at all and parked forever looking healthy.
		switch {
		case executionWorker == nil:
			slog.Warn("connector worker cannot consume and is idle: its execution seams are not wired",
				"reason", notReadyReason, "consumer", worker.DurableName,
				"bus_configured", dispatchConfig.Enabled(), "readyz", "503")
		case !dispatchConfig.Enabled():
			slog.Warn("no dispatch bus configured; connector worker is idle", "consumer", worker.DurableName)
		}
		<-ctx.Done()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = healthServer.Shutdown(shutdownCtx)
}

// composeWorker builds the worker, or explains precisely why it could not.
//
// It is a function rather than inline in main so the refusal contract can be
// exercised directly. That matters here: the reason it returns is what /readyz
// serves and what an operator reads at boot, and the only alternative way to
// cover it would be to grep main.go for a string, which proves nothing about
// what the process actually answers.
//
// A nil worker is never an exit. The process stays up so the health surface
// stays observable; a container that flaps on boot tells an operator nothing.
func composeWorker(cfg worker.Config) (*worker.Worker, string) {
	unwired := cfg.MissingRequired()
	executionWorker, err := worker.New(cfg)
	reason := ""
	if err != nil {
		reason = err.Error()
		executionWorker = nil
	}
	if len(unwired) == 0 {
		return executionWorker, reason
	}
	// Lead with the full set. worker.New stops at the FIRST problem it meets, so
	// on its own it sends an operator to wire one thing and the next restart
	// sends them after the next.
	if reason != "" {
		reason = "; " + reason
	}
	// Drop a worker the guard says is incomplete, even when worker.New accepted
	// it. New only refuses a nil action plane and a blank identity, so a
	// partially wired config (an action plane, a full identity, no binding
	// resolver) constructs fine and then fails CheckReady forever - while the
	// startup line, which reads only "is the worker non-nil", would print
	// ready=true against a /readyz answering 503. That contradiction is the exact
	// one this binary was fixed for. Every dependency the guard names is fixed at
	// construction, so no runtime event could have made this worker ready later;
	// nilling it costs nothing and keeps both surfaces answering from one fact.
	return nil, "connector worker dependencies constructed by nobody (task B3): " + strings.Join(unwired, ", ") + reason
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
	mux := newHealthMux(cfg, executionWorker, constructionError)
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("connector worker health server stopped", "error", err)
		}
	}()
	return server
}

// workerCanConsume is the single readiness predicate. Both the startup line and
// /readyz derive from it, because the one thing that must never happen again is
// the two disagreeing.
func workerCanConsume(executionWorker *worker.Worker) bool { return executionWorker != nil }

// newHealthMux builds the health surface. Split out from startHealthServer so
// the readiness contract can be exercised over a real HTTP round trip instead
// of asserted by reading this file.
func newHealthMux(cfg config.Config, executionWorker *worker.Worker, constructionError string) *http.ServeMux {
	mux := http.NewServeMux()
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, workerCanConsume(executionWorker))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// Branch on health.Ready rather than re-deriving the predicate, so the
		// value this handler answers with and the value the startup line prints
		// are the SAME value. When they were derived independently they drifted:
		// the startup line said ready=true while this handler said 503.
		if !health.Ready {
			writeHealth(w, http.StatusServiceUnavailable, health.Service, health.Version, false, constructionError)
			return
		}
		if err := executionWorker.CheckReady(r.Context()); err != nil {
			writeHealth(w, http.StatusServiceUnavailable, health.Service, health.Version, false, err.Error())
			return
		}
		writeHealth(w, http.StatusOK, health.Service, health.Version, true, "")
	})
	return mux
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
