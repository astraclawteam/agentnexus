package app

import "testing"

func TestNewHealthStatusReturnsServiceVersionAndReadiness(t *testing.T) {
	status := NewHealthStatus("gateway-api", "0.1.0-dev", true)

	if status.Service != "gateway-api" {
		t.Fatalf("Service = %q, want %q", status.Service, "gateway-api")
	}
	if status.Version != "0.1.0-dev" {
		t.Fatalf("Version = %q, want %q", status.Version, "0.1.0-dev")
	}
	if !status.Ready {
		t.Fatal("Ready = false, want true")
	}
}
