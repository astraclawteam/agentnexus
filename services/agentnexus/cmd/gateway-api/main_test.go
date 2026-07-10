package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/config"
)

func TestBuildRouterDisabledOmitsBrowserAuthRoutes(t *testing.T) {
	router, cleanup, err := buildRouter(context.Background(), config.Config{ServiceName: "gateway-api", Version: "test"}, config.BrowserAuthConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
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

func TestBuildRouterDoesNotLeakDatabaseCredentialsInStartupError(t *testing.T) {
	_, cleanup, err := buildRouter(context.Background(), config.Config{ServiceName: "gateway-api", Version: "test"}, config.BrowserAuthConfig{Enabled: true, DatabaseURL: "postgres://user:supersecret@%zz"})
	cleanup()
	if err == nil {
		t.Fatal("invalid database URL accepted")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("credential leaked: %v", err)
	}
}
