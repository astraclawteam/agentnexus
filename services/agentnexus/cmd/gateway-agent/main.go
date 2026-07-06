package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
)

func main() {
	cfg := config.Load("gateway-agent")
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	fmt.Printf("service=%s version=%s environment=%s ready=%t addr=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, cfg.HTTPAddr)
	if err := http.ListenAndServe(cfg.HTTPAddr, app.NewGatewayAgentRouter(cfg.ServiceName, cfg.Version)); err != nil {
		log.Fatal(err)
	}
}
