package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5/pgxpool"
)

const startupTimeout = 15 * time.Second

func main() {
	cfg := config.Load("gateway-api")
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

	fmt.Printf("service=%s version=%s environment=%s ready=%t addr=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, cfg.HTTPAddr)
	if err := newHTTPServer(cfg, router).ListenAndServe(); err != nil {
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
	approvalFactsVerifier, err := app.LoadChangeFactsVerifierFromFile(os.Getenv("AGENTNEXUS_APPROVAL_FACTS_SECRET_FILE"), time.Now)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	router, err := app.NewPostgresGatewayRouter(ctx, pool, app.PostgresGatewayConfig{
		ServiceName: cfg.ServiceName, Version: cfg.Version, OIDC: browserConfig.OIDC,
		LoginAttemptLimits: browserConfig.LoginAttemptLimits, AuthorizeRateLimitPerMinute: browserConfig.AuthorizeRateLimitPerMinute,
		TrustedProxyCIDRs: browserConfig.TrustedProxyCIDRs, ApprovalFactsVerifier: approvalFactsVerifier,
	})
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return router, cleanup, nil
}

// Kept as focused wiring seams for the command's fail-closed unit tests.
func productionAuthorizationDependencies(enterpriseID string, pool *pgxpool.Pool) (policy.AtlasPolicySource, app.TicketActorAuthenticator) {
	return app.NewPostgresAtlasPolicySource(pool), app.NewPostgresTicketActorAuthenticator(enterpriseID, pool, time.Now)
}

func productionApprovalDependencies(pool *pgxpool.Pool) (app.ApprovalSnapshotSource, app.ApprovalRouteStore) {
	return app.NewPostgresApprovalSource(pool), app.NewPostgresApprovalStore(pool)
}

func newHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	return &http.Server{Addr: cfg.HTTPAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
}
