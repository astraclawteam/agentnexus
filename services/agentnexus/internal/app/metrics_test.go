package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatewayAPIMetricsRoute(t *testing.T) {
	router := NewGatewayAPIRouter("gateway-api", "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `agentnexus_service_ready{service="gateway-api"} 1`) {
		t.Fatalf("metrics body = %s", rec.Body.String())
	}
}

func TestGatewayAgentMetricsRoute(t *testing.T) {
	router := NewGatewayAgentRouter("gateway-agent", "test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `agentnexus_service_ready{service="gateway-agent"} 1`) {
		t.Fatalf("metrics body = %s", rec.Body.String())
	}
}
