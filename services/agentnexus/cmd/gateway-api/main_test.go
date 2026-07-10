package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
