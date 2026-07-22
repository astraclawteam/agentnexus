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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// readinessPollInterval paces the gate that keeps a worker off the stream until
// its seams are wired. It is a wait rather than a fatal error so a deployment
// that completes its wiring while the process is up starts serving without a
// restart.
const readinessPollInterval = 5 * time.Second

// startupTimeout bounds the database work the execution seams do at boot (the
// signing-key registration). It is bounded so an unreachable database reports a
// reason instead of hanging the process before the health surface exists.
const startupTimeout = 15 * time.Second

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
	// The worker's own first-party identity. A PARTIAL identity is fatal here
	// (LoadWorkerIdentity's all-or-nothing rule); a wholly absent one is not,
	// because that is a deployment which has not wired the worker yet and its
	// health surface must stay observable rather than crash-loop.
	workerConfig, err := loadWorkerConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	// The Postgres-backed execution surface. Same all-or-nothing rule and same
	// reason: a deployment that supplied HALF of it must be told which half,
	// because the wiring guard downstream can only say the seams were
	// constructed by nobody. A deployment that supplied NONE of it is not an
	// error and boots to an honest 503.
	executionConfig, err := config.LoadWorkerExecution()
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
	// Task B1 composes the three execution seams that HAVE a production
	// implementation — the Task 0F action plane, the ed25519 receipt signer with
	// its key registered, and the Postgres private BindingResolver over
	// connector_products/connector_bindings. See app.NewPostgresWorkerSeams for
	// what each one does and does not deliver.
	//
	// The ObservationProducer is NOT composed, because it has no implementation
	// anywhere in this build: the evidence-backed producer is Task 7 work. So the
	// worker is still not constructible and this process still consumes nothing.
	// That is the honest state, and it is reported rather than papered over: no
	// pass-stub, no fake ActionPlane, no fabricated receipt. A worker that
	// consumed without that seam would fail every intent it pulled and burn the
	// delivery attempts of durable Actions.
	//
	// Wiring that producer is no longer enough to make this process consume, and
	// deliberately so. The composed BindingResolver has no HostFactory, and a
	// resolver that cannot produce a runnable operation now reports NOT-READY, so
	// the gate below parks the worker and /readyz answers 503 naming the missing
	// host wiring. Before that, this construction gap was the ONLY thing keeping
	// the worker off the stream, and removing it would have started a nak loop
	// against durable Actions on the very next deploy.
	//
	// Name the gap before trying to construct through it. worker.New stops at
	// the FIRST problem it meets (a nil action plane), so on its own it tells an
	// operator to go wire one thing, and the next restart tells them the next
	// thing. MissingRequired reports the whole set at once -- which worker.New
	// can only describe as a sentence and CheckReady never reaches.
	//
	// The set it reports is now a function of the deployment rather than a
	// constant: B3 gave the four identity refs a configuration surface
	// (AGENTNEXUS_WORKER_*) and B1 gives the execution seams one
	// (AGENTNEXUS_WORKER_RECEIPT_SIGNING_KEY_* plus the database DSN), so a
	// deployment that sets them sees the reason shrink to the one seam nobody
	// can supply yet. A deployment that sets neither sees all of them, which is
	// the truth about that deployment.
	//
	// The process stays up either way, because a container that flaps hides the
	// reason, and /readyz answers 503 with it.
	workerConfig, closeSeams, err := wireExecutionSeams(ctx, workerConfig, executionConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer closeSeams()
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

// loadWorkerConfig reads the deployment's worker configuration into the shape
// worker.New and the wiring guard consume.
//
// It is a function rather than inline in main for the same reason composeWorker
// is: it is the ONLY place the identity environment reaches the worker, and the
// alternative way to cover that link would be to grep main.go for a call to
// config.LoadWorkerIdentity, which proves a string is present and nothing about
// what the process does with it. Driven over real environment variables, this
// answers the question that actually matters — does setting AGENTNEXUS_WORKER_*
// change what the wiring guard reports missing.
//
// The tenant of each dispatch comes from the server-authored message, never from
// this identity and never from Agent input.
func loadWorkerConfig(cfg config.Config) (worker.Config, error) {
	identity, err := config.LoadWorkerIdentity(cfg.ServiceName)
	if err != nil {
		return worker.Config{}, err
	}
	return worker.Config{
		Identity: worker.Identity{
			PrincipalRef:    identity.PrincipalRef,
			AgentClientRef:  identity.AgentClientRef,
			AgentReleaseRef: identity.AgentReleaseRef,
			OrgSnapshotRef:  identity.OrgSnapshotRef,
		},
	}, nil
}

// wireExecutionSeams fills the Postgres-backed execution seams of an
// identity-bearing worker.Config, or leaves them nil when the deployment did not
// configure them. It returns the COMPLETE config the wiring guard then inspects.
//
// It owns the merge rather than leaving it to main for the same reason
// loadWorkerConfig owns the identity load: this is the only place the execution
// configuration reaches the worker, and the alternative way to cover that link
// would be to grep main.go for a call, which proves a string is present and
// nothing about what the process does with it. Driven over a real configuration,
// this answers the question that matters — does supplying the surface change
// what the guard reports missing.
//
// An unconfigured deployment is NOT an error. Every seam stays nil, the guard
// names them, and the process boots and answers an honest 503. A CONFIGURED one
// that cannot be composed IS fatal, and the asymmetry is deliberate: the
// operator asserted this worker is wired, so a DSN that does not parse or a
// signing key that cannot be registered is a mistake they must see, not a state
// to serve quietly.
//
// The returned func closes the pool. It is never nil, so the caller can defer it
// unconditionally.
func wireExecutionSeams(ctx context.Context, workerConfig worker.Config, executionConfig config.WorkerExecutionConfig) (worker.Config, func(), error) {
	noop := func() {}
	if !executionConfig.Configured() {
		return workerConfig, noop, nil
	}
	startupCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := pgxpool.New(startupCtx, executionConfig.DatabaseURL)
	if err != nil {
		return workerConfig, noop, fmt.Errorf("connect the connector worker database: %w", err)
	}
	seams, err := app.NewPostgresWorkerSeams(startupCtx, pool, app.PostgresWorkerConfig{
		ReceiptSigningKeyID: executionConfig.ReceiptSigningKeyID,
		ReceiptSigningKey:   executionConfig.ReceiptSigningKey,
	})
	if err != nil {
		pool.Close()
		return workerConfig, noop, err
	}
	return mergeExecutionSeams(workerConfig, seams), pool.Close, nil
}

// mergeExecutionSeams folds the composed seams into the identity-bearing config.
//
// It is separate so it can be exercised without a database — the composition
// itself needs one, and this assignment is where the two configurations meet.
// Identity is deliberately NOT copied: it is the deployment's own configuration
// and app.NewPostgresWorkerSeams leaves it zero, so taking the seams config
// wholesale would silently blank a configured identity and send an operator back
// to variables they had already set correctly.
func mergeExecutionSeams(workerConfig, seams worker.Config) worker.Config {
	workerConfig.Actions = seams.Actions
	workerConfig.Signer = seams.Signer
	workerConfig.Resolver = seams.Resolver
	return workerConfig
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
	// No task number in the reason any more. It used to say "task B3", and B3 and
	// B1 have both since landed while the list this sentence introduces has kept
	// changing; a stale ticket reference sends an operator to a closed task
	// instead of at the names that follow, which are the actual answer.
	return nil, "connector worker dependencies constructed by nobody: " + strings.Join(unwired, ", ") + reason
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
