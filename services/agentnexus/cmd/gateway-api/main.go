package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const startupTimeout = 15 * time.Second

func main() {
	cfg := config.Load("gateway-api")
	// Fail closed before anything else: production never serves plaintext.
	mode, err := transportsecurity.ResolveStartupMode(cfg.Environment, cfg.TLS)
	if err != nil {
		log.Fatal(err)
	}
	browserConfig, err := config.LoadBrowserAuth()
	if err != nil {
		log.Fatal(err)
	}
	dispatchConfig, err := config.LoadDispatch()
	if err != nil {
		log.Fatal(err)
	}
	approvalConfig, err := config.LoadApproval()
	if err != nil {
		log.Fatal(err)
	}
	evidenceConfig, err := config.LoadEvidence()
	if err != nil {
		log.Fatal(err)
	}
	runCtx, stopRun := context.WithCancel(context.Background())
	defer stopRun()
	router, recoveryPump, cleanup, err := buildRouter(runCtx, cfg, browserConfig, dispatchConfig, approvalConfig, evidenceConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()
	if recoveryPump != nil {
		// The outbox commits a dispatch intent before anything publishes it, so
		// a crash in that window leaves a durable row nothing would ever
		// deliver. This loop is what closes that window; it owns no state and
		// stops with the process.
		go recoveryPump.Run(runCtx)
	}
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)
	server := newHTTPServer(cfg, router)

	if mode == transportsecurity.ModeMutualTLS {
		// The single public TLS profile (sdk/go/transportsecurity) via the
		// runtime manager: unique service identity, mutual TLS 1.3,
		// revocation enforced per handshake, pools torn down on rotation.
		manager, err := transportsecurity.NewManager(transportsecurity.SettingsFromConfig(cfg))
		if err != nil {
			log.Fatal(err)
		}
		peers, err := transportsecurity.AuthorizedClients(cfg.ServiceName, cfg.EnterpriseID)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig, err := manager.ServerTLSConfig(peers)
		if err != nil {
			log.Fatal(err)
		}
		server.TLSConfig = tlsConfig
		manager.InstrumentServer(server)
		fmt.Printf("service=%s version=%s environment=%s ready=%t addr=%s mtls=true identity=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, cfg.HTTPAddr, manager.IdentityURI())
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
		return
	}

	fmt.Printf("service=%s version=%s environment=%s ready=%t addr=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, cfg.HTTPAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func buildRouter(ctx context.Context, cfg config.Config, browserConfig config.BrowserAuthConfig, dispatchConfig config.DispatchConfig, approvalConfig config.ApprovalConfig, evidenceConfig config.EvidenceConfig) (http.Handler, *actions.RecoveryPump, func(), error) {
	if !browserConfig.Enabled {
		// This is the branch every shipped compose/helm profile currently takes,
		// because none of them set AGENTNEXUS_BROWSER_AUTH_ENABLED. The result is
		// a gateway that answers /healthz, /readyz and /api/console/overview and
		// NOTHING else -- no runtime, evidence, approval, action, audit or
		// org-event surface -- while looking perfectly healthy to an
		// orchestrator. Serving a reduced router is a legitimate mode; doing it
		// without saying so is how a whole product surface goes missing and
		// every cross-product call 404s with no explanation on this side.
		log.Printf("gateway-api: browser auth is disabled, serving the minimal router only "+
			"(health and console overview). The runtime, evidence, approval, action, audit and "+
			"org-event surfaces are NOT registered. Set AGENTNEXUS_BROWSER_AUTH_ENABLED=true with "+
			"AGENTNEXUS_POSTGRES_DSN, AGENTNEXUS_OIDC_SIGNING_KEY_PATH, "+
			"AGENTNEXUS_OIDC_CONSOLE_CLIENTS_JSON, AGENTNEXUS_OIDC_CONSOLE_CLIENT_SECRET_FILES_JSON "+
			"and AGENTNEXUS_OIDC_UPSTREAM_CLIENT_SECRET_FILE to serve them. service=%s", cfg.ServiceName)
		return app.NewGatewayAPIRouter(cfg.ServiceName, cfg.Version), nil, func() {}, nil
	}
	startupCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := pgxpool.New(startupCtx, browserConfig.DatabaseURL)
	if err != nil {
		return nil, nil, func() {}, err
	}
	cleanup := func() { pool.Close() }
	if err := pool.Ping(startupCtx); err != nil {
		cleanup()
		return nil, nil, func() {}, fmt.Errorf("connect browser auth database: %w", err)
	}
	// The dispatch transport is optional, but a CONFIGURED one that cannot be
	// reached is a startup failure: silently serving without delivery would
	// look healthy while every Action stalls at `dispatched`.
	var dispatchPublisher actions.Publisher
	if dispatchConfig.Enabled() {
		conn, err := nats.Connect(dispatchConfig.NATSURL)
		if err != nil {
			cleanup()
			return nil, nil, func() {}, fmt.Errorf("connect dispatch bus: %w", err)
		}
		publisher, err := actions.NewNATSPublisher(conn)
		if err != nil {
			conn.Close()
			cleanup()
			return nil, nil, func() {}, fmt.Errorf("build dispatch publisher: %w", err)
		}
		dispatchPublisher = publisher
		poolCleanup := cleanup
		cleanup = func() { conn.Close(); poolCleanup() }
	}
	// AgentNexus never resolves approvals itself: it transmits a caller-authored
	// plan to the deployment's approval authority. No outbound integration with
	// a customer OA/BPM exists yet (task B7), so the only channel this build can
	// offer is one that correlates plans durably and reports them undelivered.
	//
	// Default stays "none" -- endpoints unregistered, historical behaviour. Set
	// AGENTNEXUS_APPROVAL_CHANNEL=pending-only to register the surface so
	// AgentAtlas gets a truthful pending transmission instead of a bare 404
	// that says nothing about why.
	var approvalChannel approvaltransport.Channel
	if approvalConfig.Registered() {
		approvalChannel = approvaltransport.NewPendingDeliveryChannel()
	}
	// The semantic evidence runtime (task B6). Configured, /v1/runtime/locate and
	// /v1/runtime/read are REGISTERED; unconfigured, they 404 as before. The
	// source-binding registry is now populated from the deployment's source
	// catalog, so a DECLARED data class resolves and is authorized — but the
	// content source still cannot reach any customer system (task B3), so an
	// authorized locate fails at the fetch with 503 evidence_unavailable rather
	// than serving records. An UNDECLARED data class still denies with 403
	// evidence_denied (not_resolvable), which is correct. Say both to whoever
	// reads the log, so a 503 is not mistaken for a regression.
	if evidenceConfig.Enabled() {
		log.Printf("gateway-api: evidence runtime registered at /v1/runtime/locate and /v1/runtime/read, "+
			"staging under %s (NODE-LOCAL: a handle staged by one replica is unreadable on another), "+
			"with %d source(s) declared in the semantic registry. It still cannot serve data: the content "+
			"source is not connected to the connector runtime (task B3), so a locate for a declared data "+
			"class fails at the fetch with 503 evidence_unavailable. An undeclared data class denies with "+
			"403 evidence_denied. service=%s",
			evidenceConfig.ObjectRoot, len(evidenceConfig.SourceCatalog.Sources), cfg.ServiceName)
	} else {
		log.Printf("gateway-api: evidence runtime NOT configured, /v1/runtime/locate and /v1/runtime/read are "+
			"UNREGISTERED and answer 404. Set %s, %s, %s and %s together to register them. service=%s",
			"AGENTNEXUS_EVIDENCE_OBJECT_ROOT", "AGENTNEXUS_EVIDENCE_CONTENT_KEY_REF",
			"AGENTNEXUS_EVIDENCE_CONTENT_KEY_FILE", "AGENTNEXUS_EVIDENCE_SOURCE_CATALOG_FILE", cfg.ServiceName)
	}
	router, recoveryPump, err := app.NewPostgresGatewayRouter(startupCtx, pool, app.PostgresGatewayConfig{
		ApprovalChannel: approvalChannel,
		ServiceName:     cfg.ServiceName, Version: cfg.Version, OIDC: browserConfig.OIDC,
		LoginAttemptLimits: browserConfig.LoginAttemptLimits, AuthorizeRateLimitPerMinute: browserConfig.AuthorizeRateLimitPerMinute,
		TrustedProxyCIDRs: browserConfig.TrustedProxyCIDRs,
		// Dev binary: no stable audit key wired yet, so allow a dev-only ephemeral
		// signing key. A production deployment supplies AuditSigningKey (KMS) and
		// pins its public half as the offline verifier's trust anchor.
		AllowEphemeralAuditKey:   true,
		DispatchPublisher:        dispatchPublisher,
		DispatchRecoveryInterval: dispatchConfig.RecoveryInterval,
		// No ephemeral fallback here, deliberately: an ephemeral audit key still
		// signs new events, but an ephemeral CONTENT key orphans every handle
		// staged before the restart. The operator supplies a stable one or the
		// surface stays unregistered.
		EvidenceObjectRoot:    evidenceConfig.ObjectRoot,
		EvidenceContentKeyRef: evidenceConfig.ContentKeyRef,
		EvidenceContentKey:    evidenceConfig.ContentKey,
		EvidenceSourceCatalog: evidenceConfig.SourceCatalog,
	})
	if err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	return router, recoveryPump, cleanup, nil
}

// Kept as focused wiring seams for the command's fail-closed unit tests.
func productionAuthorizationDependencies(enterpriseID string, pool *pgxpool.Pool) (policy.SnapshotSource, trust.AccessTicketVerifier) {
	return app.NewPostgresSnapshotSource(pool), app.NewPostgresTicketActorAuthenticator(enterpriseID, pool, time.Now)
}

func productionApprovalTransmissionStore(pool *pgxpool.Pool) *approvaltransport.PostgresStore {
	return approvaltransport.NewPostgresStore(pool)
}

func newHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	return &http.Server{Addr: cfg.HTTPAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
}
