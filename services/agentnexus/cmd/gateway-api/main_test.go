package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

func TestBuildRouterDisabledOmitsBrowserAuthRoutes(t *testing.T) {
	router, recoveryPump, cleanup, err := buildRouter(context.Background(), config.Config{ServiceName: "gateway-api", Version: "test"}, config.BrowserAuthConfig{}, config.DispatchConfig{}, config.ApprovalConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// No dispatch transport is configured here, so there must be no recovery
	// loop to start: a pump without a publisher could only spin and fail.
	if recoveryPump != nil {
		t.Fatal("a gateway without a dispatch publisher must not return a recovery pump")
	}
	for path, want := range map[string]int{"/healthz": http.StatusOK, "/.well-known/openid-configuration": http.StatusNotFound} {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != want {
			t.Fatalf("%s status=%d", path, rr.Code)
		}
	}
}

func TestGatewayHTTPServerAndStartupHaveBoundedTimeouts(t *testing.T) {
	server := newHTTPServer(config.Config{HTTPAddr: ":1234"}, http.NotFoundHandler())
	for name, value := range map[string]time.Duration{"read-header": server.ReadHeaderTimeout, "read": server.ReadTimeout, "write": server.WriteTimeout, "idle": server.IdleTimeout} {
		if value <= 0 || value > 2*time.Minute {
			t.Fatalf("%s timeout=%s", name, value)
		}
	}
	if server.MaxHeaderBytes <= 0 || server.MaxHeaderBytes > 1<<20 {
		t.Fatalf("max headers=%d", server.MaxHeaderBytes)
	}
	_, file, _, _ := runtime.Caller(0)
	source, err := os.ReadFile(strings.TrimSuffix(file, "_test.go") + ".go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "context.WithTimeout(ctx, startupTimeout)") {
		t.Fatal("buildRouter startup context is not bounded")
	}
}

func TestBuildRouterWiresAuthorizeRateLimiterAndTrustedSourceResolver(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	source, err := os.ReadFile(strings.TrimSuffix(file, "_test.go") + ".go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"app.NewPostgresGatewayRouter(startupCtx, pool",
		"AuthorizeRateLimitPerMinute: browserConfig.AuthorizeRateLimitPerMinute",
		"TrustedProxyCIDRs:",
		"browserConfig.TrustedProxyCIDRs",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("buildRouter missing %q", required)
		}
	}
}

func TestBuildRouterWiresAuthorizationPolicyAndPostgresTicketActor(t *testing.T) {
	source, tickets := productionAuthorizationDependencies("enterprise-1", nil)
	if _, err := source.LoadAccessSnapshot(context.Background(), "enterprise-1", "user-1"); !errors.Is(err, policy.ErrPolicyUnavailable) {
		t.Fatalf("nil Postgres source error = %v", err)
	}
	if _, err := tickets.VerifyAccessTicket(context.Background(), "opaque-ticket"); !errors.Is(err, trust.ErrSourceUnavailable) {
		t.Fatalf("production ticket adapter error = %v", err)
	}
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(strings.TrimSuffix(file, "_test.go") + ".go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"app.NewPostgresGatewayRouter(startupCtx, pool", "app.NewPostgresTicketActorAuthenticator(enterpriseID, pool, time.Now)"} {
		if !strings.Contains(string(raw), required) {
			t.Errorf("production authorization wiring missing %q", required)
		}
	}
}

func TestApprovalTransmissionProductionWiringFailsClosed(t *testing.T) {
	// The production transmission store fails closed without a pool, and the
	// command wires NO approval channel yet: the retired resolver secret is
	// gone and the transmission endpoints stay unregistered until a channel
	// is configured (AgentNexus never resolves approvals itself).
	store := productionApprovalTransmissionStore(nil)
	if _, err := store.GetTransmission(context.Background(), "enterprise-1", "apl_0123456789abcdef"); !errors.Is(err, approvaltransport.ErrUnavailable) {
		t.Fatalf("nil Postgres transmission store err=%v want ErrUnavailable", err)
	}
	if _, _, err := store.CreateTransmission(context.Background(), approvaltransport.Transmission{TenantRef: "enterprise-1", PlanRef: "apl_0123456789abcdef"}); !errors.Is(err, approvaltransport.ErrUnavailable) {
		t.Fatalf("nil Postgres transmission store create err=%v want ErrUnavailable", err)
	}
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(strings.TrimSuffix(file, "_test.go") + ".go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, retired := range []string{"AGENTNEXUS_APPROVAL_FACTS_SECRET_FILE", "LoadChangeFactsVerifierFromFile"} {
		if strings.Contains(source, retired) {
			t.Errorf("retired approval resolution wiring %q still present in main.go", retired)
		}
	}
	if !strings.Contains(source, "approvaltransport.NewPostgresStore(pool)") {
		t.Error("production approval transmission store seam missing")
	}
}

func TestBuildRouterDoesNotLeakDatabaseCredentialsInStartupError(t *testing.T) {
	_, _, cleanup, err := buildRouter(context.Background(), config.Config{ServiceName: "gateway-api", Version: "test"}, config.BrowserAuthConfig{Enabled: true, DatabaseURL: "postgres://user:supersecret@%zz"}, config.DispatchConfig{}, config.ApprovalConfig{})
	cleanup()
	if err == nil {
		t.Fatal("invalid database URL accepted")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("credential leaked: %v", err)
	}
}
