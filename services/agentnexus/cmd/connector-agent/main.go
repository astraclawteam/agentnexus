package main

import (
	"fmt"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/agent"
)

func main() {
	cfg := config.Load("connector-agent")
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)
	identity := agent.Identity{AgentID: cfg.ServiceName, DisplayName: "AgentNexus Connector Agent"}

	fmt.Printf("service=%s version=%s environment=%s ready=%t agent_id=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, identity.AgentID)
}
