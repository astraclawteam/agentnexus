package main

import (
	"fmt"
	"log"
	"os"

	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
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
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	// GA Task 6 outbound Connector Agent. The resumable durable-execution
	// pipeline (internal/connectors/agent) is complete: it drives every dispatch
	// through the central Worker's exported provenance/receipt/observation helpers
	// and the shared isolated host over an outbound-initiated mTLS session, with an
	// edge durable journal for exactly-once disconnect/resume.
	//
	// Its concrete fail-closed seams — the Postgres private BindingResolver and the
	// evidence-backed ObservationProducer (both shared with Task 5), the central
	// ActionPlane request/reply RESPONDER (the server side of the outbound bridge)
	// and the concrete durable edge-journal store — land in the Task 7 connector-
	// qualification work. Until they are wired, the agent's CheckReady fails closed
	// and this command NEVER processes a dispatch with a missing seam: no pass-stub,
	// no fake ActionPlane, no fabricated receipt. This mirrors the central Worker.
	executionPlaneReady := false
	executionPlaneStatus := "not_ready(pending_task7:binding_resolver,observation_producer,action_plane_responder,edge_journal)"

	if mode == transportsecurity.ModeMutualTLS {
		// The Connector Agent's certificate identity binds the enterprise AND the
		// registered installation via the URI SAN; the manager refuses material
		// whose URI SAN does not carry exactly this enterprise + installation.
		if cfg.EnterpriseID == "" || cfg.AgentID == "" {
			log.Fatal("connector-agent mTLS requires AGENTNEXUS_ENTERPRISE_ID and AGENTNEXUS_AGENT_ID: the certificate identity binds the enterprise and the registered installation")
		}
		settings := transportsecurity.SettingsFromConfig(cfg)
		settings.Identity.Installation = cfg.AgentID
		manager, err := transportsecurity.NewManager(settings)
		if err != nil {
			log.Fatal(err)
		}
		// GA identity is CERT-DERIVED from the mTLS URI SAN, never caller JSON.
		identity, err := agent.CertDerivedIdentity(manager)
		if err != nil {
			log.Fatal(err)
		}
		// Build the OUTBOUND client mTLS config the agent DIALS the central with
		// (it never binds a listener). The central endpoint's server name is
		// deployment config; when present we validate the dial config can be
		// expressed under the current material, failing closed otherwise.
		if serverName := os.Getenv("AGENTNEXUS_CENTRAL_SERVER_NAME"); serverName != "" {
			peers := sdk.PeerAuthorization{Enterprise: cfg.EnterpriseID, Services: []string{"connector-worker", "gateway-api"}}
			if _, err := manager.ClientTLSConfig(peers, serverName); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Printf("service=%s version=%s environment=%s ready=%t mtls=true identity=%s enterprise_id=%s installation=%s dispatch_consumer=%s execution_plane_ready=%t execution_plane=%s\n",
			health.Service, health.Version, cfg.Environment, health.Ready, manager.IdentityURI(), identity.Enterprise, identity.Installation, agent.DurableName, executionPlaneReady, executionPlaneStatus)
		return
	}

	fmt.Printf("service=%s version=%s environment=%s ready=%t agent_id=%s dispatch_consumer=%s execution_plane_ready=%t execution_plane=%s\n",
		health.Service, health.Version, cfg.Environment, health.Ready, cfg.AgentID, agent.DurableName, executionPlaneReady, executionPlaneStatus)
}
