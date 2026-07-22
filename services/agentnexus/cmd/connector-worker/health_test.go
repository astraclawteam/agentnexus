package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
)

// The connector worker's execution seams (the private Postgres BindingResolver
// and the evidence-backed ObservationProducer) are deliberately not wired yet,
// so worker.New fails and the process stays up with a nil worker to keep its
// health surface observable. That decision is fine. What was NOT fine is that
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
	// Exactly what main() supplies today: this service's own name, and nothing
	// else, because the remaining seams and identity refs have no configuration
	// surface at all (task B3).
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
