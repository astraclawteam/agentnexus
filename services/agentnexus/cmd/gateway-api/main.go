package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
	if err := http.ListenAndServe(cfg.HTTPAddr, router); err != nil {
		log.Fatal(err)
	}
}

func buildRouter(ctx context.Context, cfg config.Config, browserConfig config.BrowserAuthConfig) (http.Handler, func(), error) {
	if !browserConfig.Enabled {
		return app.NewGatewayAPIRouter(cfg.ServiceName, cfg.Version), func() {}, nil
	}
	pool, err := pgxpool.New(ctx, browserConfig.DatabaseURL)
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { pool.Close() }
	if err := pool.Ping(ctx); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("connect browser auth database: %w", err)
	}
	upstream, err := browserauth.NewEnterpriseOIDC(ctx, browserConfig.OIDC)
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("initialize enterprise OIDC: %w", err)
	}
	directory := app.NewPostgresBrowserDirectory(pool)
	router, err := app.NewGatewayAPIRouterWithDependencies(cfg.ServiceName, cfg.Version, app.BrowserAuthDependencies{Config: browserConfig.OIDC, Sessions: browserauth.NewService(browserauth.NewPostgresStore(pool)), Upstream: upstream, Identities: directory, Profiles: directory, Audit: app.NewPostgresBrowserAuditSink(pool)})
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return router, cleanup, nil
}
