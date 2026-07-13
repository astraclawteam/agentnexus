package main

import (
	"fmt"
	"log"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
)

func main() {
	cfg := config.Load("gateway-agent")
	// Fail closed before anything else: production never runs plaintext.
	mode, err := transportsecurity.ResolveStartupMode(cfg.Environment, cfg.TLS)
	if err != nil {
		log.Fatal(err)
	}
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	if mode == transportsecurity.ModeMutualTLS {
		// Load and validate this service's unique mTLS identity through the
		// single public TLS profile so the material is ready for both the
		// serving and the dialing side of every link.
		manager, err := transportsecurity.NewManager(transportsecurity.SettingsFromConfig(cfg))
		if err != nil {
			log.Fatal(err)
		}
		peers, err := transportsecurity.AuthorizedClients(cfg.ServiceName, cfg.EnterpriseID)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := manager.ServerTLSConfig(peers); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("service=%s version=%s environment=%s ready=%t mtls=true identity=%s\n", health.Service, health.Version, cfg.Environment, health.Ready, manager.IdentityURI())
		return
	}

	fmt.Printf("service=%s version=%s environment=%s ready=%t\n", health.Service, health.Version, cfg.Environment, health.Ready)
}
