package observability

import (
	"strings"
	"testing"
)

func TestPrometheusTextIncludesServiceReadiness(t *testing.T) {
	text := PrometheusText(Snapshot{
		Service: "gateway-api",
		Ready:   true,
		Counters: map[string]int64{
			"runtime_audit_fail_closed_total": 2,
		},
	})

	if !strings.Contains(text, `agentnexus_service_ready{service="gateway-api"} 1`) {
		t.Fatalf("metrics text missing readiness: %s", text)
	}
	if !strings.Contains(text, `agentnexus_runtime_audit_fail_closed_total 2`) {
		t.Fatalf("metrics text missing counter: %s", text)
	}
}
