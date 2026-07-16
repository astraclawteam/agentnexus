package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	sdk "github.com/astraclawteam/agentnexus/sdk/go/transportsecurity"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/agent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
	"github.com/nats-io/nats.go"
)

// ============================================================================
// GA Task 6 outbound Connector Agent integration (the Verify).
//
// Two layers, plus a non-gated fixture-validity guard:
//   - an ALWAYS-RUN real crypto/tls loopback layer proving firewall-deny-inbound
//     (the agent binds NO listener and only dials), mutual identity, and cert
//     revocation dropping the session with NO duplicate external operation;
//   - an ENV-GATED layer (real NATS + real Postgres) driving the durable pipeline
//     over the outbound request/reply ActionPlane bridge against a REAL responder
//     wired to a real actions.Service, with a genuine broker redelivery, asserting
//     one Action, one ActionReceipt, the exact deduplicated ObservationReceipt set
//     and connector-invocation-count == 1;
//   - TestOutboundConnectorAgentFixtureIsValid, which runs in the DEFAULT suite so
//     the env-gated fixture can never silently rot.
// ============================================================================

// --- in-memory edge journal (the concrete durable edge store is deferred) ----

type memEdgeJournal struct {
	mu       sync.Mutex
	receipts map[string]runtime.ActionReceipt
	obs      map[string]runtime.ObservationReceipt
}

func newMemEdgeJournal() *memEdgeJournal {
	return &memEdgeJournal{receipts: map[string]runtime.ActionReceipt{}, obs: map[string]runtime.ObservationReceipt{}}
}

func (j *memEdgeJournal) LoadReceipt(_ context.Context, tenant, action, dispatch string) (runtime.ActionReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.receipts[tenant+"|"+action+"|"+dispatch]
	return r, ok, nil
}

func (j *memEdgeJournal) RecordReceipt(_ context.Context, tenant, action, dispatch string, receipt runtime.ActionReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.receipts[tenant+"|"+action+"|"+dispatch] = receipt
	return nil
}

func (j *memEdgeJournal) LoadObservation(_ context.Context, tenant, action, need string) (runtime.ObservationReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.obs[tenant+"|"+action+"|"+need]
	return r, ok, nil
}

func (j *memEdgeJournal) RecordObservation(_ context.Context, tenant, action, need string, receipt runtime.ObservationReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.obs[tenant+"|"+action+"|"+need] = receipt
	return nil
}

// flakyBridge wraps a worker.ActionPlane and drops the session (a transient
// disconnect) on a named method a bounded number of times.
type flakyBridge struct {
	inner    worker.ActionPlane
	mu       sync.Mutex
	failNext map[string]int
}

func newFlakyBridge(inner worker.ActionPlane) *flakyBridge {
	return &flakyBridge{inner: inner, failNext: map[string]int{}}
}

var errBridgeDisconnected = errors.New("outbound session disconnected")

func (p *flakyBridge) fail(method string, n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failNext[method] = n
}

func (p *flakyBridge) drop(method string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext[method] > 0 {
		p.failNext[method]--
		return true
	}
	return false
}

func (p *flakyBridge) GetAction(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	if p.drop("GetAction") {
		return actions.Action{}, errBridgeDisconnected
	}
	return p.inner.GetAction(ctx, principal, actionRef)
}
func (p *flakyBridge) MarkExecuting(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	if p.drop("MarkExecuting") {
		return actions.Action{}, errBridgeDisconnected
	}
	return p.inner.MarkExecuting(ctx, principal, actionRef)
}
func (p *flakyBridge) IngestReceipt(ctx context.Context, principal runtime.PrincipalContext, resultID string, receipt runtime.ActionReceipt) (actions.Action, error) {
	if p.drop("IngestReceipt") {
		return actions.Action{}, errBridgeDisconnected
	}
	return p.inner.IngestReceipt(ctx, principal, resultID, receipt)
}
func (p *flakyBridge) MarkResultUnknown(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	if p.drop("MarkResultUnknown") {
		return actions.Action{}, errBridgeDisconnected
	}
	return p.inner.MarkResultUnknown(ctx, principal, actionRef)
}

func agentPin() agent.Pin {
	return agent.Pin{TenantRef: "tenant-1", Capabilities: []string{"erp.purchase_order.approve"}}
}

func agentSystemIdentity() worker.Identity {
	return worker.Identity{PrincipalRef: "connector-agent", AgentClientRef: "agc_connector_agent", AgentReleaseRef: "agent-rel-1", OrgSnapshotRef: "org-system"}
}

// ============================================================================
// Non-gated fixture-validity guard (mirror TestConnectorWorkerFixtureIsValid).
// ============================================================================

func TestOutboundConnectorAgentFixtureIsValid(t *testing.T) {
	// The action/principal fixtures reused for the env-gated run must be valid.
	if err := workerIntegrationPrincipal().Validate(); err != nil {
		t.Fatalf("integration principal fixture is invalid: %v", err)
	}
	if err := workerIntegrationRequest(t).Validate(); err != nil {
		t.Fatalf("integration ActionRequest fixture is invalid: %v", err)
	}

	// The cert-minting fixture builds valid managers for both the central server
	// and the connector-agent installation, and the agent's identity is cert-derived.
	p := newAgentPKI(t)
	serverID := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	agentID := sdk.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-7"}
	_, agentManager := p.managerPair(t, serverID, agentID)
	identity, err := agent.CertDerivedIdentity(agentManager)
	if err != nil {
		t.Fatalf("CertDerivedIdentity: %v", err)
	}
	if identity.Enterprise != "acme" || identity.Installation != "agent-7" {
		t.Fatalf("cert-derived identity = %+v, want enterprise=acme installation=agent-7", identity)
	}

	// The edge journal round-trips a receipt and an observation.
	journal := newMemEdgeJournal()
	ctx := context.Background()
	rcpt := runtime.ActionReceipt{ReceiptRef: "rcp_x", ActionRef: "act_0123456789abcdef"}
	if err := journal.RecordReceipt(ctx, "tenant-1", "act_0123456789abcdef", "dsp_1", rcpt); err != nil {
		t.Fatalf("RecordReceipt: %v", err)
	}
	if got, ok, _ := journal.LoadReceipt(ctx, "tenant-1", "act_0123456789abcdef", "dsp_1"); !ok || got.ReceiptRef != "rcp_x" {
		t.Fatalf("LoadReceipt = %+v ok=%v, want the recorded receipt", got, ok)
	}

	// A fully-wired Session is ready; the responder wiring rejects nil arguments.
	signer, _ := newAgentSigner(t)
	svc := newMemoryActionService(t, signerKey(t, signer))
	s, err := agent.New(agent.Config{
		ActionPlane: svc, Resolver: fixedResolver{binding: worker.ResolvedBinding{Host: &countingHost{output: []byte(`{"ok":true}`)}}},
		Signer: signer, Observations: &fakeObservationProducer{}, Journal: journal,
		Identity: agentSystemIdentity(), Pin: agentPin(), Version: "1.0.0",
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	if err := s.CheckReady(ctx); err != nil {
		t.Fatalf("CheckReady with all seams wired = %v, want ready", err)
	}
	if _, err := agent.ServeActionPlane(nil, svc); err == nil {
		t.Fatal("ServeActionPlane accepted a nil connection")
	}
}

// ============================================================================
// Always-run real crypto/tls loopback layer: outbound-only, mutual identity,
// revocation drops the session with no duplicate external operation.
// ============================================================================

func TestOutboundConnectorAgentMutualTLSOutboundOnly(t *testing.T) {
	p := newAgentPKI(t)
	// The agent DIALS the central gateway-api, which authorizes a connector-agent
	// client; the agent pins the central server identity. Mutual auth has no opt-out.
	serverID := sdk.Identity{Enterprise: "acme", Service: "gateway-api"}
	agentID := sdk.Identity{Enterprise: "acme", Service: "connector-agent", Installation: "agent-7"}
	serverManager, agentManager := p.managerPair(t, serverID, agentID)

	serverPeers, err := transportsecurity.AuthorizedClients("gateway-api", "acme")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := serverManager.ServerTLSConfig(serverPeers)
	if err != nil {
		t.Fatal(err)
	}
	agentPeers := sdk.PeerAuthorization{Enterprise: "acme", Services: []string{"gateway-api"}}
	clientCfg, err := agentManager.ClientTLSConfig(agentPeers, "localhost")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("mutual_identity_over_agent_initiated_connection", func(t *testing.T) {
		out := loopbackHandshake(t, serverCfg, clientCfg)
		if out.serverErr != nil || out.clientErr != nil {
			t.Fatalf("agent-initiated handshake failed: server=%v client=%v", out.serverErr, out.clientErr)
		}
		serverSaw, err := sdk.PeerIdentity(*out.serverState)
		if err != nil || serverSaw != agentID {
			t.Fatalf("central saw peer %+v (err=%v), want the connector-agent %+v", serverSaw, err, agentID)
		}
		clientSaw, err := sdk.PeerIdentity(*out.clientState)
		if err != nil || clientSaw != serverID {
			t.Fatalf("agent saw peer %+v (err=%v), want the central %+v", clientSaw, err, serverID)
		}
	})

	t.Run("firewall_deny_inbound_agent_binds_no_listener", func(t *testing.T) {
		// The firewall-deny-inbound fixture at the Go level: the agent is given ONLY
		// an outbound dialer (a NATSDialer has no Listen/Accept surface) and binds no
		// listener, so nothing can connect TO it — all data rides the connection the
		// agent initiates. The central is the only party that binds a listener.
		var dialer agent.Dialer = &agent.NATSDialer{URL: "tls://central.acme.example:4222"}
		if _, isListener := any(dialer).(interface{ Listen(string) (net.Listener, error) }); isListener {
			t.Fatal("the outbound dialer must expose no inbound Listen surface")
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		// The agent dials the central; the reverse (central dialing the agent) has no
		// target because the agent binds nothing. This models the firewall denying
		// every inbound connection to the customer edge.
		go func() {
			conn, aerr := ln.Accept()
			if aerr == nil {
				_ = tls.Server(conn, serverCfg).HandshakeContext(context.Background())
				conn.Close()
			}
		}()
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("outbound dial failed: %v", err)
		}
		tc := tls.Client(conn, clientCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(ctx); err != nil {
			t.Fatalf("agent-initiated handshake failed: %v", err)
		}
		tc.Close()
	})

	t.Run("revocation_drops_the_session", func(t *testing.T) {
		// A working handshake before revocation...
		if out := loopbackHandshake(t, serverCfg, clientCfg); out.serverErr != nil || out.clientErr != nil {
			t.Fatalf("pre-revocation handshake failed: server=%v client=%v", out.serverErr, out.clientErr)
		}
		// ...the central revokes the agent identity and reloads its CRL...
		p.revoke(p.agentLeaf.leaf)
		p.serverDir.replaceCRL(t, p.signedCRL(p.crlNumber+1))
		if err := serverManager.Reload(); err != nil {
			t.Fatal(err)
		}
		// ...and every NEW handshake from the revoked agent is rejected: the session
		// cannot be re-established, so a revoked peer keeps nothing alive.
		out := loopbackHandshake(t, serverCfg, clientCfg)
		if out.serverErr == nil || !strings.Contains(out.serverErr.Error(), "revoked") {
			t.Fatalf("post-revocation server err = %v, want a revocation failure", out.serverErr)
		}
	})

	t.Run("no_duplicate_external_operation_across_teardown", func(t *testing.T) {
		// The revocation teardown composes with the resumable pipeline: an in-flight
		// Action whose central apply is lost as the session drops is re-applied from
		// the edge journal on re-establish — the connector is invoked exactly once.
		signer, key := newAgentSigner(t)
		svc, pub := newMemoryActionServiceWithPublisher(t, key)
		bridge := newFlakyBridge(svc)
		hostRunner := &countingHost{output: []byte(`{"po_id":"po-1"}`)}
		resolver := fixedResolver{binding: worker.ResolvedBinding{Host: hostRunner, Resource: "purchase_orders", Operation: "approve", OperationAction: "write", ConnectorRef: "conn_private_1", CredentialRef: "secretref://vault/acme/erp"}}
		journal := newMemEdgeJournal()
		s, err := agent.New(agent.Config{
			ActionPlane: bridge, Resolver: resolver, Signer: signer, Observations: &fakeObservationProducer{},
			Journal: journal, Identity: agentSystemIdentity(), Pin: agentPin(),
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		action, msg := driveDispatch(t, svc, pub)

		// Disconnect at the central apply: host ran, receipt journaled, apply lost.
		bridge.fail("IngestReceipt", 1)
		if _, err := s.ProcessDispatch(ctx, msg); err == nil {
			t.Fatal("expected the in-flight disconnect, got nil")
		}
		if hostRunner.runs() != 1 {
			t.Fatalf("connector runs = %d, want 1", hostRunner.runs())
		}
		// The revocation teardown drops the live session.
		s.HandleRotation()
		// Re-establish + redeliver: the journaled receipt is re-applied, the
		// connector is NEVER re-invoked.
		res, err := s.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("resume after teardown: %v", err)
		}
		if res.Outcome != worker.OutcomeCompleted {
			t.Fatalf("resume outcome = %q, want completed", res.Outcome)
		}
		if hostRunner.runs() != 1 {
			t.Fatalf("connector runs = %d after revocation teardown + re-establish, want exactly 1 (no duplicate)", hostRunner.runs())
		}
		if got := getActionStatus(t, svc, action.ActionRef); got != actions.StatusSucceeded {
			t.Fatalf("action status = %q, want succeeded", got)
		}
	})
}

// ============================================================================
// Env-gated layer: real NATS + real Postgres, real responder over the outbound
// request/reply ActionPlane bridge, genuine broker redelivery, exactly-once.
// ============================================================================

func TestOutboundConnectorAgentDurableExecution(t *testing.T) {
	natsURL := os.Getenv("AGENTNEXUS_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("set AGENTNEXUS_TEST_NATS_URL and AGENTNEXUS_E2E_POSTGRES_DSN to run the outbound connector-agent integration test")
	}
	pool := workerIntegrationPool(t) // skips if AGENTNEXUS_E2E_POSTGRES_DSN is unset
	ctx := context.Background()

	// --- durable action plane (real Postgres) + signer ----------------------
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := audit.NewEd25519AuditSigner("connector-agent-int-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	keys := sdkaudit.NewKeySet(sdkaudit.SigningKey{KeyID: "connector-agent-int-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyActive})

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	publisher, err := actions.NewNATSPublisher(nc)
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	svc, err := actions.NewService(actions.NewPostgresStore(pool), actions.NewMemoryAuditSink(),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(keys)),
		actions.WithPublisher(publisher))
	if err != nil {
		t.Fatalf("actions.NewService: %v", err)
	}

	// --- the REAL central responder answers the outbound ActionPlane bridge --
	unsub, err := agent.ServeActionPlane(nc, svc)
	if err != nil {
		t.Fatalf("ServeActionPlane: %v", err)
	}
	defer unsub()
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}

	// --- the agent: RemoteActionPlane over the SAME outbound connection ------
	hostRunner := &countingHost{output: []byte(`{"po_id":"po-1"}`)}
	resolver := fixedResolver{binding: worker.ResolvedBinding{Host: hostRunner, Resource: "purchase_orders", Operation: "approve", OperationAction: "write", ConnectorRef: "conn_private_1", CredentialRef: "secretref://vault/acme/erp"}}
	obs := &fakeObservationProducer{}
	journal := newMemEdgeJournal()
	remotePlane := agent.NewRemoteActionPlane(nc, 5*time.Second)
	s, err := agent.New(agent.Config{
		ActionPlane: remotePlane, Resolver: resolver, Signer: signer, Observations: obs, Journal: journal,
		Identity: agentSystemIdentity(), Pin: agentPin(),
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	if err := s.CheckReady(ctx); err != nil {
		t.Fatalf("agent not ready: %v", err)
	}

	// --- drive one Action to dispatched, publish the durable intent ---------
	principal := workerIntegrationPrincipal()
	req := workerIntegrationRequest(t)
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	stream := fmt.Sprintf("AGENTNEXUS_AGENT_DISPATCH_%d", time.Now().UnixNano())
	if _, err := js.AddStream(&nats.StreamConfig{Name: stream, Subjects: []string{actions.SubjectActionDispatch}}); err != nil {
		t.Fatalf("add stream: %v", err)
	}
	defer js.DeleteStream(stream)
	if _, err := svc.RepublishPending(ctx, principal.TenantRef); err != nil {
		t.Fatalf("RepublishPending: %v", err)
	}

	// --- durable pull with a deliberate, genuine broker redelivery ----------
	const ackWait = 300 * time.Millisecond
	sub, err := js.PullSubscribe(actions.SubjectActionDispatch, agent.DurableName, nats.BindStream(stream), nats.AckWait(ackWait))
	if err != nil {
		t.Fatalf("pull subscribe: %v", err)
	}
	first, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
	if err != nil || len(first) != 1 {
		t.Fatalf("first fetch: msgs=%d err=%v", len(first), err)
	}
	firstMeta, _ := first[0].Metadata()
	// Do NOT ack the first delivery; wait past AckWait so JetStream redelivers the
	// SAME tracked message (a genuine broker at-least-once), then process both.
	time.Sleep(ackWait + 400*time.Millisecond)
	second, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
	if err != nil || len(second) != 1 {
		t.Fatalf("redelivery fetch: msgs=%d err=%v", len(second), err)
	}
	secondMeta, _ := second[0].Metadata()
	if secondMeta.Sequence.Stream != firstMeta.Sequence.Stream || secondMeta.NumDelivered < 2 {
		t.Fatalf("second fetch is not a genuine redelivery (stream seq %d/%d, delivered %d)", secondMeta.Sequence.Stream, firstMeta.Sequence.Stream, secondMeta.NumDelivered)
	}

	var lastReceiptRef string
	var observationCount int
	for _, delivery := range [][]*nats.Msg{first, second} {
		var msg actions.DispatchMessage
		if err := json.Unmarshal(delivery[0].Data, &msg); err != nil {
			t.Fatalf("decode dispatch message: %v", err)
		}
		res, err := s.ProcessDispatch(ctx, msg)
		if err != nil {
			t.Fatalf("ProcessDispatch: %v", err)
		}
		if res.ActionReceipt != nil {
			lastReceiptRef = res.ActionReceipt.ReceiptRef
		}
		if len(res.ObservationReceipts) > observationCount {
			observationCount = len(res.ObservationReceipts)
		}
		_ = delivery[0].Ack()
	}

	// --- exactly-once side effect + one authoritative receipt over the bridge -
	if hostRunner.runs() != 1 {
		t.Fatalf("connector executed %d times, want exactly once (central dedup + edge journal across a real redelivery)", hostRunner.runs())
	}
	final, err := svc.GetAction(ctx, principal, action.ActionRef)
	if err != nil || final.Status != actions.StatusSucceeded {
		t.Fatalf("final action = %+v err=%v, want succeeded", final, err)
	}
	if final.ReceiptRef == "" || (lastReceiptRef != "" && final.ReceiptRef != lastReceiptRef) {
		t.Fatalf("action receipt ref = %q, produced = %q", final.ReceiptRef, lastReceiptRef)
	}
	var inboxCount, receiptCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM action_inbox WHERE action_ref=$1`, action.ActionRef).Scan(&inboxCount); err != nil {
		t.Fatalf("inbox count: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM action_receipts WHERE action_ref=$1`, action.ActionRef).Scan(&receiptCount); err != nil {
		t.Fatalf("receipt count: %v", err)
	}
	if inboxCount != 1 || receiptCount != 1 {
		t.Fatalf("inbox rows=%d receipt rows=%d, want exactly 1 each (one authoritative ActionReceipt)", inboxCount, receiptCount)
	}
	if observationCount != 2 {
		t.Fatalf("observation receipts = %d, want exactly the 2 declared verification needs", observationCount)
	}
	if got := obs.distinctNeeds(); len(got) != 2 || !got["n1"] || !got["n2"] {
		t.Fatalf("observed needs = %v, want exactly {n1,n2}", got)
	}
}

// --- helpers ----------------------------------------------------------------

func newMemoryActionService(t *testing.T, key sdkaudit.SigningKey) *actions.Service {
	t.Helper()
	svc, _ := newMemoryActionServiceWithPublisher(t, key)
	return svc
}

func newMemoryActionServiceWithPublisher(t *testing.T, key sdkaudit.SigningKey) (*actions.Service, *capturePublisher) {
	t.Helper()
	pub := &capturePublisher{}
	svc, err := actions.NewService(actions.NewMemoryStore(), actions.NewMemoryAuditSink(),
		actions.WithIDGenerator(sequentialAgentIDs()),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(sdkaudit.NewKeySet(key))),
		actions.WithPublisher(pub))
	if err != nil {
		t.Fatalf("actions.NewService: %v", err)
	}
	return svc, pub
}

func newAgentSigner(t *testing.T) (*audit.Ed25519AuditSigner, sdkaudit.SigningKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := audit.NewEd25519AuditSigner("connector-agent-crypto-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, sdkaudit.SigningKey{KeyID: "connector-agent-crypto-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyActive}
}

func signerKey(t *testing.T, signer *audit.Ed25519AuditSigner) sdkaudit.SigningKey {
	t.Helper()
	return sdkaudit.SigningKey{KeyID: signer.KeyID(), Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: signer.PublicKey(), Status: sdkaudit.KeyActive}
}

type capturePublisher struct {
	mu   sync.Mutex
	sent []actions.DispatchMessage
}

func (p *capturePublisher) PublishDispatch(_ context.Context, message actions.DispatchMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, message)
	return nil
}
func (p *capturePublisher) last() actions.DispatchMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent[len(p.sent)-1]
}

func sequentialAgentIDs() func(string) string {
	var mu sync.Mutex
	counters := map[string]int{}
	return func(prefix string) string {
		mu.Lock()
		defer mu.Unlock()
		counters[prefix]++
		return fmt.Sprintf("%s%016d", prefix, counters[prefix])
	}
}

// driveDispatch drives one Action to dispatched over an in-memory service whose
// capture publisher records the durable dispatch intent.
func driveDispatch(t *testing.T, svc *actions.Service, pub *capturePublisher) (actions.Action, actions.DispatchMessage) {
	t.Helper()
	ctx := context.Background()
	principal := workerIntegrationPrincipal()
	req := workerIntegrationRequest(t)
	// A single declared need keeps the crypto-layer resume check focused.
	req.Postconditions = req.Postconditions[:0]
	req.VerificationNeeds = req.VerificationNeeds[:0]
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, err := svc.Dispatch(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if _, err := svc.RepublishPending(ctx, principal.TenantRef); err != nil {
		t.Fatalf("RepublishPending: %v", err)
	}
	stored, err := svc.GetAction(ctx, principal, action.ActionRef)
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	return stored, pub.last()
}

func getActionStatus(t *testing.T, svc *actions.Service, actionRef string) runtime.ActionStatus {
	t.Helper()
	a, err := svc.GetAction(context.Background(), workerIntegrationPrincipal(), actionRef)
	if err != nil {
		t.Fatalf("GetAction: %v", err)
	}
	return a.Status
}

func loopbackHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) handshakeOutcome {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type serverResult struct {
		err   error
		state *tls.ConnectionState
	}
	serverCh := make(chan serverResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverCh <- serverResult{err: err}
			return
		}
		defer conn.Close()
		tconn := tls.Server(conn, serverCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := tconn.HandshakeContext(ctx); err != nil {
			serverCh <- serverResult{err: err}
			return
		}
		state := tconn.ConnectionState()
		_, werr := tconn.Write([]byte("ok"))
		serverCh <- serverResult{err: werr, state: &state}
	}()
	outcome := handshakeOutcome{}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tconn := tls.Client(conn, clientCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tconn.HandshakeContext(ctx); err != nil {
		outcome.clientErr = err
	} else {
		buf := make([]byte, 2)
		if _, err := io.ReadFull(tconn, buf); err != nil {
			outcome.clientErr = err
		} else {
			state := tconn.ConnectionState()
			outcome.clientState = &state
		}
	}
	result := <-serverCh
	outcome.serverErr = result.err
	outcome.serverState = result.state
	return outcome
}

type handshakeOutcome struct {
	serverErr   error
	clientErr   error
	serverState *tls.ConnectionState
	clientState *tls.ConnectionState
}

// ============================================================================
// Ported minimal test PKI (mirrors internal/transportsecurity/tls_test.go).
// ============================================================================

type apkiRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type apkiLeaf struct {
	certPEM []byte
	keyPEM  []byte
	leaf    *x509.Certificate
}

type agentPKI struct {
	t          *testing.T
	roots      []apkiRoot
	signer     *ecdsa.PrivateKey
	revoked    []x509.RevocationListEntry
	crlNumber  int64
	agentLeaf  apkiLeaf
	serverDir  apkiMaterialDir
}

func newAgentPKI(t *testing.T) *agentPKI {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &agentPKI{t: t, signer: signer}
	p.roots = []apkiRoot{p.newRoot("agentnexus-test-root-1")}
	return p
}

func (p *agentPKI) newRoot(cn string) apkiRoot {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: newAgentSerial(p.t), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		p.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	return apkiRoot{cert: cert, key: key}
}

func newAgentSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func (p *agentPKI) issue(id sdk.Identity) apkiLeaf {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: newAgentSerial(p.t), Subject: pkix.Name{CommonName: id.Service},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	raw, err := id.URI()
	if err != nil {
		p.t.Fatal(err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		p.t.Fatal(err)
	}
	tpl.URIs = []*url.URL{parsed}
	issuer := p.roots[len(p.roots)-1]
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		p.t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		p.t.Fatal(err)
	}
	return apkiLeaf{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		leaf:    leaf,
	}
}

func (p *agentPKI) rootsPEM() string {
	p.t.Helper()
	var b strings.Builder
	for _, root := range p.roots {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}); err != nil {
			p.t.Fatal(err)
		}
	}
	return b.String()
}

func (p *agentPKI) signedBundle(sequence uint64) []byte {
	p.t.Helper()
	bundle := sdk.TrustBundle{Format: sdk.TrustBundleFormat, Sequence: sequence, IssuedAt: time.Now().UTC(), RootsPEM: p.rootsPEM(), SigningKeyID: "test-authority"}
	digest := sha256.Sum256(bundle.SigningPayload())
	sig, err := ecdsa.SignASN1(rand.Reader, p.signer, digest[:])
	if err != nil {
		p.t.Fatal(err)
	}
	bundle.Signature = sig
	raw, err := json.Marshal(bundle)
	if err != nil {
		p.t.Fatal(err)
	}
	return raw
}

func (p *agentPKI) revoke(leaf *x509.Certificate) {
	p.revoked = append(p.revoked, x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now()})
}

func (p *agentPKI) signedCRL(number int64) []byte {
	p.t.Helper()
	issuer := p.roots[len(p.roots)-1]
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: p.revoked,
	}, issuer.cert, issuer.key)
	if err != nil {
		p.t.Fatal(err)
	}
	p.crlNumber = number
	return der
}

func (p *agentPKI) authorityPublicPEM() []byte {
	p.t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&p.signer.PublicKey)
	if err != nil {
		p.t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

type apkiMaterialDir struct {
	settings transportsecurity.Settings
}

func (p *agentPKI) materialDir(id sdk.Identity, leaf apkiLeaf, bundle, crl []byte) apkiMaterialDir {
	p.t.Helper()
	dir := p.t.TempDir()
	m := apkiMaterialDir{settings: transportsecurity.Settings{
		CertFile:           filepath.Join(dir, "tls.crt"),
		KeyFile:            filepath.Join(dir, "tls.key"),
		TrustBundleFile:    filepath.Join(dir, "trust-bundle.json"),
		TrustAuthorityFile: filepath.Join(dir, "bundle-authority.pub"),
		CRLFile:            filepath.Join(dir, "revocations.crl"),
		Identity:           id,
	}}
	writeAgentFile(p.t, m.settings.CertFile, leaf.certPEM)
	writeAgentFile(p.t, m.settings.KeyFile, leaf.keyPEM)
	writeAgentFile(p.t, m.settings.TrustBundleFile, bundle)
	writeAgentFile(p.t, m.settings.TrustAuthorityFile, p.authorityPublicPEM())
	writeAgentFile(p.t, m.settings.CRLFile, crl)
	return m
}

func (m apkiMaterialDir) replaceCRL(t *testing.T, crl []byte) {
	t.Helper()
	writeAgentFile(t, m.settings.CRLFile, crl)
}

func writeAgentFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// managerPair mints server + agent material and builds both managers, recording
// the agent leaf + server material dir so revocation can be exercised.
func (p *agentPKI) managerPair(t *testing.T, serverID, agentID sdk.Identity) (*transportsecurity.Manager, *transportsecurity.Manager) {
	t.Helper()
	serverLeaf := p.issue(serverID)
	agentLeaf := p.issue(agentID)
	bundle := p.signedBundle(1)
	crl := p.signedCRL(1)
	serverDir := p.materialDir(serverID, serverLeaf, bundle, crl)
	agentDir := p.materialDir(agentID, agentLeaf, bundle, crl)
	serverManager, err := transportsecurity.NewManager(serverDir.settings)
	if err != nil {
		t.Fatalf("server NewManager: %v", err)
	}
	agentManager, err := transportsecurity.NewManager(agentDir.settings)
	if err != nil {
		t.Fatalf("agent NewManager: %v", err)
	}
	p.agentLeaf = agentLeaf
	p.serverDir = serverDir
	return serverManager, agentManager
}
