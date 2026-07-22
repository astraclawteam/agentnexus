package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/gatewayagent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/transportsecurity"
)

type stubDiagnostics struct{}

func (stubDiagnostics) InspectHealth(context.Context) (gatewayagent.HealthReport, error) {
	return gatewayagent.HealthReport{}, nil
}

func (stubDiagnostics) ExplainError(context.Context, string) (gatewayagent.ErrorExplanation, error) {
	return gatewayagent.ErrorExplanation{}, nil
}

const testAPIKey = "sk-router-secret-value"

func testRouter() config.LLMRouterSettings {
	return config.LLMRouterSettings{
		BaseURL: "https://llmrouter.internal",
		APIKey:  testAPIKey,
		Model:   "claude-opus-4-8",
	}
}

func testConfig() config.Config {
	return config.Config{
		ServiceName:        "gateway-agent",
		Version:            config.DefaultVersion,
		Environment:        "dev",
		EnterpriseID:       "ent-test",
		LLMRouter:          testRouter(),
		HealthProbeTargets: "gateway-api=http://gateway-api:8080/readyz,connector-worker=http://connector-worker:8080/readyz",
	}
}

// TestAssistantComposes is the point of this command: main must actually build
// the assistant, not hard-code a nil one and serve health endpoints forever.
// Composition reaches no peer and no router, so this is a real check that the
// wiring holds rather than a check that a network is up.
func TestAssistantComposes(t *testing.T) {
	assistant, reason := composeAssistant(testConfig(), transportsecurity.ModePlaintext, nil)
	if reason != "" {
		t.Fatalf("assistant not composed from a complete configuration: %s", reason)
	}
	if assistant == nil {
		t.Fatal("composition reported success but returned no assistant")
	}
}

// TestReadinessFollowsComposition ties /readyz to the fact it is supposed to
// report. The endpoint previously answered 503 permanently because nothing ever
// set an assistant; a readiness check that cannot say yes is not a check.
func TestReadinessFollowsComposition(t *testing.T) {
	assistant, reason := composeAssistant(testConfig(), transportsecurity.ModePlaintext, nil)
	if assistant == nil {
		t.Fatalf("no assistant to serve: %s", reason)
	}
	if got := readinessStatus(assistant); got != 200 {
		t.Fatalf("readiness with a composed assistant = %d; want 200", got)
	}
	if got := readinessStatus(nil); got != 503 {
		t.Fatalf("readiness without an assistant = %d; want 503", got)
	}
}

// readinessStatus drives GET /readyz through the real handler.
func readinessStatus(assistant *gatewayagent.Assistant) int {
	recorder := httptest.NewRecorder()
	newHealthMux(testConfig(), assistant, "not composed").ServeHTTP(
		recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return recorder.Code
}

// TestAssistantRefusesWithoutAModel pins the llmrouter-only boundary at the
// composition seam. There is no default provider to fall back to: the GA
// manifest pins model access as llmrouter-only with an empty direct-provider
// list, so a missing router must stop the assistant existing rather than cause
// it to reach for something else.
func TestAssistantRefusesWithoutAModel(t *testing.T) {
	assistant, err := newAssistant(config.LLMRouterSettings{}, stubDiagnostics{})
	if err == nil {
		t.Fatal("assistant composed without a model")
	}
	if assistant != nil {
		t.Fatal("a refused composition still returned an assistant")
	}
}

// TestAssistantRefusesWithoutDeterministicDiagnostics covers the other
// non-negotiable dependency: the assistant may only state facts a
// deterministic service produced, so it must not compose without one.
func TestAssistantRefusesWithoutDeterministicDiagnostics(t *testing.T) {
	if _, err := newAssistant(testRouter(), nil); err == nil {
		t.Fatal("assistant composed without a deterministic diagnostics service")
	}
}

// TestNotReadyReasonsNameTheGap covers the operator-facing half. A process that
// is unready for a configuration reason has to say which one, or the operator
// is left reading source to find out why the container is up and useless.
func TestNotReadyReasonsNameTheGap(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		mutate  func(*config.Config)
		wantHas string
	}{
		{
			name:    "no router",
			mutate:  func(c *config.Config) { c.LLMRouter = config.LLMRouterSettings{} },
			wantHas: "AGENTNEXUS_LLMROUTER_BASE_URL",
		},
		{
			name:    "router missing only the key",
			mutate:  func(c *config.Config) { c.LLMRouter.APIKey = "" },
			wantHas: "AGENTNEXUS_LLMROUTER_API_KEY",
		},
		{
			name:    "no health targets",
			mutate:  func(c *config.Config) { c.HealthProbeTargets = "" },
			wantHas: "AGENTNEXUS_HEALTH_PROBE_TARGETS",
		},
		{
			name:    "malformed health targets",
			mutate:  func(c *config.Config) { c.HealthProbeTargets = "gateway-api" },
			wantHas: "AGENTNEXUS_HEALTH_PROBE_TARGETS",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := testConfig()
			testCase.mutate(&cfg)
			assistant, reason := composeAssistant(cfg, transportsecurity.ModePlaintext, nil)
			if assistant != nil {
				t.Fatal("assistant composed from an incomplete configuration")
			}
			if !strings.Contains(reason, testCase.wantHas) {
				t.Fatalf("not-ready reason %q does not name %s", reason, testCase.wantHas)
			}
		})
	}
}

// TestNotReadyReasonNeverCarriesTheAPIKey is the one that matters most here.
//
// The reason is written into the /readyz body and into a log line, and one of
// the values it reports on is a secret. Reporting variable names rather than
// values is what keeps that safe, and nothing about that is obvious enough to
// leave unpinned - a later "include the value, it helps debugging" edit would
// publish the router key on an unauthenticated endpoint.
func TestNotReadyReasonNeverCarriesTheAPIKey(t *testing.T) {
	cfg := testConfig()
	cfg.HealthProbeTargets = "" // force a refusal while the key is set
	_, reason := composeAssistant(cfg, transportsecurity.ModePlaintext, nil)
	if reason == "" {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(reason, testAPIKey) {
		t.Fatal("the not-ready reason leaked the llmrouter API key")
	}

	// And the same for a refusal that comes from the router itself.
	cfg = testConfig()
	cfg.LLMRouter.BaseURL = ""
	if _, reason := composeAssistant(cfg, transportsecurity.ModePlaintext, nil); strings.Contains(reason, testAPIKey) {
		t.Fatal("the not-ready reason leaked the llmrouter API key")
	}
}

// TestMutualTLSProbesNeverDowngradeToPlaintext: in mTLS mode a readiness probe
// must dial under the mTLS profile or not exist. A silent plaintext fallback
// would be an unauthenticated call to a production peer whose answer the
// assistant would then report as trustworthy.
func TestMutualTLSProbesNeverDowngradeToPlaintext(t *testing.T) {
	targets := []config.ProbeTarget{{Name: "gateway-api", URL: "https://gateway-api:8443/readyz"}}
	if _, err := probeTargets(targets, transportsecurity.ModeMutualTLS, nil, "ent-test"); err == nil {
		t.Fatal("mTLS mode built probe clients with no trust material loaded")
	}
}
