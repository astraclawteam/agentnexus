package main

import (
	"fmt"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
)

func main() {
	cfg := config.Load("connector-host")
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	fmt.Printf("service=%s version=%s environment=%s ready=%t protocol=%s\n",
		health.Service, health.Version, cfg.Environment, health.Ready, host.ProtocolVersion)
}
