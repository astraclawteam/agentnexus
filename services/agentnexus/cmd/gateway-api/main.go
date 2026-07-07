package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

func main() {
	cfg := config.Load("gateway-api")
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	fmt.Printf("service=%s version=%s environment=%s ready=%t addr=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, cfg.HTTPAddr)
	if err := http.ListenAndServe(cfg.HTTPAddr, app.NewGatewayAPIRouter(cfg.ServiceName, cfg.Version, app.WithGatewayAPISecretResolver(secrets.EnvProvider{}))); err != nil {
		log.Fatal(err)
	}
}
