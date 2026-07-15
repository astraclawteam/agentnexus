package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
	"github.com/jackc/pgx/v5/pgxpool"
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
	router, cleanup, err := buildRouter(context.Background(), cfg, browserConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()
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

func buildRouter(ctx context.Context, cfg config.Config, browserConfig config.BrowserAuthConfig) (http.Handler, func(), error) {
	if !browserConfig.Enabled {
		return app.NewGatewayAPIRouter(cfg.ServiceName, cfg.Version), func() {}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := pgxpool.New(ctx, browserConfig.DatabaseURL)
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { pool.Close() }
	if err := pool.Ping(ctx); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("connect browser auth database: %w", err)
	}
	// GA Task 0E: no approval channel is configured in this command yet, so
	// the approval transmission endpoints stay unregistered (fail closed).
	// AgentNexus never resolves approvals itself; the deployment-specific
	// AgentAtlas/OA/BPM channel wiring arrives with Task 0F.
	router, err := app.NewPostgresGatewayRouter(ctx, pool, app.PostgresGatewayConfig{
		ServiceName: cfg.ServiceName, Version: cfg.Version, OIDC: browserConfig.OIDC,
		LoginAttemptLimits: browserConfig.LoginAttemptLimits, AuthorizeRateLimitPerMinute: browserConfig.AuthorizeRateLimitPerMinute,
		TrustedProxyCIDRs: browserConfig.TrustedProxyCIDRs,
		// Dev binary: no stable audit key wired yet, so allow a dev-only ephemeral
		// signing key. A production deployment supplies AuditSigningKey (KMS) and
		// pins its public half as the offline verifier's trust anchor.
		AllowEphemeralAuditKey: true,
	})
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return router, cleanup, nil
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
