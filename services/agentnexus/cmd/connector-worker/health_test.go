package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
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
