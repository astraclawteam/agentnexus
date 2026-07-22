package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
)

// The connector worker's evidence-backed ObservationProducer has no
// implementation anywhere in this build, so worker.New still fails and the
// process stays up with a nil worker to keep its health surface observable.
// That decision is fine. What was NOT fine is that
// the process reported itself ready anyway: the startup line printed
// ready=true from a hard-coded literal while /readyz on the same process
// returned 503, so the single line an operator reads at boot -- and the line a
// closeout would quote as evidence -- actively masked the fact that the worker
// consumes nothing.
//
// These assertions go over a real HTTP round trip against the composed mux.
// They deliberately do NOT read main.go's source text: a test that greps the
// composition root for a call proves only that a string is present, which is
// exactly how the contradiction survived in the first place.

func testConfig() config.Config {
	return config.Config{ServiceName: "connector-worker", Version: "test", HTTPAddr: "127.0.0.1:0"}
}

func readyState(t *testing.T, mux http.Handler, path string) (int, bool, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body struct {
		Ready  bool   `json:"ready"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s body %q: %v", path, rec.Body.String(), err)
	}
	return rec.Code, body.Ready, body.Reason
}

func TestReadinessIsNotClaimedWhenTheWorkerCannotConsume(t *testing.T) {
	const reason = "binding resolver is not wired"
	mux := newHealthMux(testConfig(), nil, reason)

	status, ready, got := readyState(t, mux, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want %d when the worker is nil", status, http.StatusServiceUnavailable)
	}
	if ready {
		t.Error("/readyz reported ready=true while the worker cannot consume")
	}
	if !strings.Contains(got, reason) {
		t.Errorf("/readyz reason = %q, want it to name why: %q", got, reason)
	}
}

// A nil worker must never be reported as ready by ANY surface. This is the
// assertion that fails if the startup line goes back to a hard-coded true:
// NewHealthStatus is fed the same predicate the readiness handler branches on,
// so the two cannot drift apart again.
func TestStartupReadinessAgreesWithReadyz(t *testing.T) {
	mux := newHealthMux(testConfig(), nil, "seams not wired")

	// Liveness stays up on purpose: the container must not flap, and the health
	// surface has to remain observable so an operator can see WHY.
	if status, _, _ := readyState(t, mux, "/healthz"); status != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200 - the process must stay observable", status)
	}
	status, ready, _ := readyState(t, mux, "/readyz")
	if status == http.StatusOK || ready {
		t.Fatalf("readiness disagrees with the worker's actual state: status=%d ready=%v", status, ready)
	}
}

// The wiring guard's contract for this binary: name every unconstructed
// dependency, and never hand back a worker it called incomplete. Exercised
// through composeWorker rather than by reading main.go, because the value that
// matters is the one /readyz actually serves.

func TestComposeWorkerNamesEveryUnconstructedDependency(t *testing.T) {
	// The deployment that configured nothing but has a service name: no identity
	// refs, no execution surface. Everything must be named.
	executionWorker, reason := composeWorker(worker.Config{
		Identity: worker.Identity{PrincipalRef: "connector-worker"},
	})
	if executionWorker != nil {
		t.Fatal("composeWorker returned a worker whose dependencies were constructed by nobody")
	}
	// Every name, not just the first. A reason that stops at the action plane
	// sends an operator to wire one thing and the next restart sends them after
	// the next one.
	for _, want := range []string{
		"Actions", "Resolver", "Signer", "Observations",
		"Identity.AgentClientRef", "Identity.AgentReleaseRef", "Identity.OrgSnapshotRef",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("the not-ready reason does not name %s: %q", want, reason)
		}
	}
	// The ref that IS supplied must not be listed as missing; a guard that cries
	// wolf about a wired dependency gets read past.
	if strings.Contains(reason, "Identity.PrincipalRef") {
		t.Errorf("the reason names Identity.PrincipalRef, which main() does supply: %q", reason)
	}
}

// The reason is served from /readyz, so the two must agree. This is the same
// invariant the startup-line fix pinned, now covering the guard's own output.
func TestReadyzServesTheGuardsReason(t *testing.T) {
	executionWorker, reason := composeWorker(worker.Config{
		Identity: worker.Identity{PrincipalRef: "connector-worker"},
	})
	status, ready, served := readyState(t, newHealthMux(testConfig(), executionWorker, reason), "/readyz")
	if status != http.StatusServiceUnavailable || ready {
		t.Fatalf("/readyz status=%d ready=%v while the worker cannot consume", status, ready)
	}
	if served != reason {
		t.Errorf("/readyz reason = %q, want the guard's own reason %q", served, reason)
	}
}

// --- the identity configuration surface (task B3) ----------------------------

// Before B3, AgentClientRef/AgentReleaseRef/OrgSnapshotRef had no configuration
// surface anywhere in the module: main() supplied its service name as the
// principal and the wiring guard named the other three forever, with nothing an
// operator could set to satisfy them.
//
// These assertions drive loadWorkerConfig over the REAL environment rather than
// reading main.go for a call to config.LoadWorkerIdentity. The question worth
// answering is not whether the call is written down, it is whether setting the
// variables changes what the guard reports — which is what an operator
// experiences and what /readyz serves.

func setIdentityEnv(t *testing.T, client, release, org string) {
	t.Helper()
	t.Setenv("AGENTNEXUS_WORKER_PRINCIPAL_REF", "")
	t.Setenv("AGENTNEXUS_WORKER_AGENT_CLIENT_REF", client)
	t.Setenv("AGENTNEXUS_WORKER_AGENT_RELEASE_REF", release)
	t.Setenv("AGENTNEXUS_WORKER_ORG_SNAPSHOT_REF", org)
}

func TestConfiguredIdentityStopsTheGuardNamingTheIdentityRefs(t *testing.T) {
	setIdentityEnv(t, "agc_console", "agr_2026_07", "orgv_7")
	workerConfig, err := loadWorkerConfig(testConfig())
	if err != nil {
		t.Fatalf("loadWorkerConfig: %v", err)
	}
	for _, name := range workerConfig.MissingRequired() {
		if strings.HasPrefix(name, "Identity.") {
			t.Errorf("a fully configured environment still leaves %s unsatisfied", name)
		}
	}
	// The execution seams are a separate gap and must STILL be named. A test
	// that only checked the identity would pass just as well against a build
	// that had quietly stopped reporting the unwired action plane.
	_, reason := composeWorker(workerConfig)
	for _, want := range []string{"Actions", "Resolver", "Signer", "Observations"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the not-ready reason no longer names the unwired %s: %q", want, reason)
		}
	}
}

// The unconfigured deployment: every identity ref is still reported, so an
// operator reading /readyz learns the identity is unset rather than seeing a
// principal defaulted in behind their back.
func TestUnconfiguredIdentityIsStillReportedMissing(t *testing.T) {
	setIdentityEnv(t, "", "", "")
	workerConfig, err := loadWorkerConfig(testConfig())
	if err != nil {
		t.Fatalf("an unconfigured identity must not be a startup error: %v", err)
	}
	executionWorker, reason := composeWorker(workerConfig)
	if executionWorker != nil {
		t.Fatal("composeWorker returned a worker with no identity at all")
	}
	for _, want := range []string{
		"Identity.PrincipalRef", "Identity.AgentClientRef",
		"Identity.AgentReleaseRef", "Identity.OrgSnapshotRef",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("the not-ready reason does not name %s: %q", want, reason)
		}
	}
}

// A PARTIAL identity is a startup error, not a three-quarters-empty worker.
// main() turns this into log.Fatal; the value here is that the error exists at
// all, because the alternative is a worker whose audit lineage points at a
// blank agent client.
func TestPartialIdentityEnvironmentIsAStartupError(t *testing.T) {
	setIdentityEnv(t, "agc_console", "", "orgv_7")
	if _, err := loadWorkerConfig(testConfig()); err == nil {
		t.Fatal("a partial identity environment must fail startup")
	}
}

// --- the execution seams (task B1) -------------------------------------------

// Three of the four execution seams have a production implementation and are now
// composed by app.NewPostgresWorkerSeams. The fourth, the ObservationProducer,
// has none anywhere in this build, so the worker is still not constructible and
// this process still consumes nothing. What B1 changes is the REASON: it must
// shrink to name only what genuinely remains, instead of listing four seams of
// which three were satisfiable all along.
//
// The composed-successfully path needs a database and lives with the seams it
// exercises (app.TestPostgresWorkerSeams*, DSN-gated). What is coverable here is
// the link main() actually owns: the merge of the identity and the seams into
// the one Config the guard inspects, and the boot-time refusals around it.

func TestUnconfiguredExecutionSurfaceLeavesEverySeamNamed(t *testing.T) {
	setIdentityEnv(t, "agc_console", "agr_2026_07", "orgv_7")
	workerConfig, err := loadWorkerConfig(testConfig())
	if err != nil {
		t.Fatalf("loadWorkerConfig: %v", err)
	}
	// The deployment that has not wired its execution surface. It must boot.
	wired, closeSeams, err := wireExecutionSeams(context.Background(), workerConfig, config.WorkerExecutionConfig{})
	if err != nil {
		t.Fatalf("an unconfigured execution surface must not be a startup error: %v", err)
	}
	defer closeSeams()

	executionWorker, reason := composeWorker(wired)
	if executionWorker != nil {
		t.Fatal("composeWorker returned a worker whose execution seams were constructed by nobody")
	}
	for _, want := range []string{"Actions", "Resolver", "Signer", "Observations"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the not-ready reason does not name the unwired %s: %q", want, reason)
		}
	}
	// The identity it DID carry must survive the merge. A wiring step that
	// overwrote the whole Config would blank a configured identity and send an
	// operator back to variables they had already set correctly.
	if strings.Contains(reason, "Identity.") {
		t.Errorf("wiring the execution seams discarded the configured identity: %q", reason)
	}
}

// The composed path, minus the database the composition needs. Supplying the
// three seams must shrink the guard's reason to the ONE dependency that has no
// implementation anywhere in this build, and must leave the identity alone.
//
// The seams here are stand-ins; that they are real is what
// app.TestPostgresWorkerSeamsLeaveOnlyTheObservationProducerUnwired asserts,
// against a real database. What is being pinned here is the merge itself, which
// is the step main() owns.
func TestSuppliedSeamsLeaveOnlyTheObservationProducerNamed(t *testing.T) {
	setIdentityEnv(t, "agc_console", "agr_2026_07", "orgv_7")
	workerConfig, err := loadWorkerConfig(testConfig())
	if err != nil {
		t.Fatalf("loadWorkerConfig: %v", err)
	}
	seams := worker.Config{
		Actions:  stubActionPlane{},
		Signer:   stubReceiptSigner{},
		Resolver: stubBindingResolver{},
	}

	executionWorker, reason := composeWorker(mergeExecutionSeams(workerConfig, seams))
	if executionWorker != nil {
		t.Fatal("composeWorker handed back a worker whose observation producer is nil")
	}
	if !strings.Contains(reason, "Observations") {
		t.Errorf("the not-ready reason does not name the unwired Observations: %q", reason)
	}
	for _, gone := range []string{"Actions", "Resolver", "Signer", "Identity."} {
		if strings.Contains(reason, gone) {
			t.Errorf("the reason still names %s after it was supplied: %q", gone, reason)
		}
	}
}

// A configured surface the process cannot compose is FATAL rather than served
// quietly: the operator asserted this worker is wired. The DSN here fails to
// parse, so this never touches a network.
func TestConfiguredExecutionSurfaceThatCannotBeComposedIsAStartupError(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	broken := config.WorkerExecutionConfig{
		DatabaseURL:         "postgres://user:pass@host:not-a-port/db",
		ReceiptSigningKeyID: "connector-worker-receipt-1",
		ReceiptSigningKey:   key,
	}
	if !broken.Configured() {
		t.Fatal("the fixture is not a configured surface, so this asserts nothing")
	}
	if _, _, err := wireExecutionSeams(context.Background(), worker.Config{}, broken); err == nil {
		t.Fatal("a configured execution surface that cannot be composed must fail startup")
	}
}

// The cleanup func is never nil on ANY path, so main can defer it
// unconditionally. A nil one would panic the process at shutdown on exactly the
// paths this binary exists to keep observable.
func TestWireExecutionSeamsAlwaysReturnsAClosableCleanup(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, executionConfig := range map[string]config.WorkerExecutionConfig{
		"unconfigured": {},
		"unusable":     {DatabaseURL: "postgres://user:pass@host:not-a-port/db", ReceiptSigningKeyID: "k", ReceiptSigningKey: key},
	} {
		t.Run(name, func(t *testing.T) {
			_, closeSeams, _ := wireExecutionSeams(context.Background(), worker.Config{}, executionConfig)
			if closeSeams == nil {
				t.Fatal("the cleanup func is nil; main defers it unconditionally")
			}
			closeSeams()
		})
	}
}

// Stand-ins for the three seams that DO have production implementations, used
// only to pin what the guard reports once they are present. They are inert on
// purpose: every method fails, so nothing here can be mistaken for a shippable
// pass-stub. The real composition is app.NewPostgresWorkerSeams and its
// behaviour is asserted against a real database, not here.

var errStubSeam = errors.New("test stand-in seam; never a production implementation")

type stubActionPlane struct{}

func (stubActionPlane) GetAction(context.Context, runtime.PrincipalContext, string) (actions.Action, error) {
	return actions.Action{}, errStubSeam
}
func (stubActionPlane) MarkExecuting(context.Context, runtime.PrincipalContext, string) (actions.Action, error) {
	return actions.Action{}, errStubSeam
}
func (stubActionPlane) IngestReceipt(context.Context, runtime.PrincipalContext, string, runtime.ActionReceipt) (actions.Action, error) {
	return actions.Action{}, errStubSeam
}
func (stubActionPlane) MarkResultUnknown(context.Context, runtime.PrincipalContext, string) (actions.Action, error) {
	return actions.Action{}, errStubSeam
}

type stubReceiptSigner struct{}

func (stubReceiptSigner) Sign(context.Context, []byte) (runtime.Signature, error) {
	return runtime.Signature{}, errStubSeam
}

type stubBindingResolver struct{}

func (stubBindingResolver) Resolve(context.Context, string, string) (worker.ResolvedBinding, error) {
	return worker.ResolvedBinding{}, errStubSeam
}
