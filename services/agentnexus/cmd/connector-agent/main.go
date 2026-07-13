package main

import (
	"fmt"
	"log"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/agent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
)

func main() {
	cfg := config.Load("connector-agent")
	// Fail closed before anything else: production never runs plaintext.
	mode, err := transportsecurity.ResolveStartupMode(cfg.Environment, cfg.TLS)
	if err != nil {
		log.Fatal(err)
	}
	agentID := cfg.AgentID
	if agentID == "" {
		agentID = cfg.ServiceName
	}
	identity := agent.Identity{AgentID: agentID, EnterpriseID: cfg.EnterpriseID, DisplayName: "AgentNexus Connector Agent"}
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	if mode == transportsecurity.ModeMutualTLS {
		// The Connector Agent's certificate identity binds the enterprise
		// AND the registered installation from the existing registration
		// vocabulary (agent.Identity): the manager refuses material whose
		// URI SAN does not carry exactly this enterprise + agent id.
		if cfg.EnterpriseID == "" || cfg.AgentID == "" {
			log.Fatal("connector-agent mTLS requires AGENTNEXUS_ENTERPRISE_ID and AGENTNEXUS_AGENT_ID: the certificate identity binds the enterprise and the registered installation")
		}
		settings := transportsecurity.SettingsFromConfig(cfg)
		settings.Identity.Installation = identity.AgentID
		manager, err := transportsecurity.NewManager(settings)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("service=%s version=%s environment=%s ready=%t agent_id=%s enterprise_id=%s mtls=true identity=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, identity.AgentID, identity.EnterpriseID, manager.IdentityURI())
		return
	}

	fmt.Printf("service=%s version=%s environment=%s ready=%t agent_id=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, identity.AgentID)
}
