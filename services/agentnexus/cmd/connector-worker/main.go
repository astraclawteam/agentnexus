package main

import (
	"fmt"
	"log"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/app"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
)

func main() {
	cfg := config.Load("connector-worker")
	// Fail closed before anything else: production never runs plaintext.
	mode, err := transportsecurity.ResolveStartupMode(cfg.Environment, cfg.TLS)
	if err != nil {
		log.Fatal(err)
	}
	health := app.NewHealthStatus(cfg.ServiceName, cfg.Version, true)

	// GA Task 5 central Connector Worker. The durable execution orchestration
	// (internal/connectors/worker) is complete: it durably pulls Action Outbox
	// dispatch intents on the worker.DurableName consumer of
	// actions.SubjectActionDispatch, resolves the PRIVATE customer binding
	// server-side, invokes the isolated host and produces the authoritative
	// signed ActionReceipt plus the exact ObservationReceipt set.
	//
	// Its two concrete fail-closed seams — the Postgres private BindingResolver
	// over connector_products/connector_bindings and the evidence-backed
	// ObservationProducer — land in the Task 7 connector-qualification work
	// (migration 000012 reserves the tables with "queries arrive in a later
	// task"). Until they are wired, worker.CheckReady fails closed and this
	// command NEVER processes a dispatch with a missing seam: no pass-stub, no
	// fake ActionPlane, no fabricated receipt. This mirrors the 0F
	// ReceiptVerifier / 0D ActionBindingVerifier deferral pattern.
	executionPlaneReady := false
	executionPlaneStatus := "not_ready(pending_task7:binding_resolver,observation_producer)"

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
		fmt.Printf("service=%s version=%s environment=%s ready=%t mtls=true identity=%s dispatch_consumer=%s execution_plane_ready=%t execution_plane=%s\n",
			health.Service, health.Version, cfg.Environment, health.Ready, manager.IdentityURI(), worker.DurableName, executionPlaneReady, executionPlaneStatus)
		return
	}

	fmt.Printf("service=%s version=%s environment=%s ready=%t dispatch_consumer=%s execution_plane_ready=%t execution_plane=%s\n",
		health.Service, health.Version, cfg.Environment, health.Ready, worker.DurableName, executionPlaneReady, executionPlaneStatus)
}
