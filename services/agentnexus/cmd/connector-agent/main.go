package main

import (
	"fmt"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
)

func main() {
	cfg := config.Load("connector-agent")
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	fmt.Printf("service=%s version=%s environment=%s ready=%t\n", health.Service, health.Version, cfg.Environment, health.Ready)
}
