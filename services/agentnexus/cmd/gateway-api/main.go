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
	runCtx, stopRun := context.WithCancel(context.Background())
	defer stopRun()
	router, recoveryPump, cleanup, err := buildRouter(runCtx, cfg, browserConfig, dispatchConfig, approvalConfig)
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

func buildRouter(ctx context.Context, cfg config.Config, browserConfig config.BrowserAuthConfig, dispatchConfig config.DispatchConfig, approvalConfig config.ApprovalConfig) (http.Handler, *actions.RecoveryPump, func(), error) {
	if !browserConfig.Enabled {
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
